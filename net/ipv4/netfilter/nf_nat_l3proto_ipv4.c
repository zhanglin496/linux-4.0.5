/*
 * (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2011 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/secure_seq.h>
#include <net/checksum.h>
#include <net/route.h>
#include <net/ip.h>

#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_l3proto.h>
#include <net/netfilter/nf_nat_l4proto.h>

static const struct nf_nat_l3proto nf_nat_l3proto_ipv4;

#ifdef CONFIG_XFRM
static void nf_nat_ipv4_decode_session(struct sk_buff *skb,
				       const struct nf_conn *ct,
				       enum ip_conntrack_dir dir,
				       unsigned long statusbit,
				       struct flowi *fl)
{
	const struct nf_conntrack_tuple *t = &ct->tuplehash[dir].tuple;
	struct flowi4 *fl4 = &fl->u.ip4;

	if (ct->status & statusbit) {
		fl4->daddr = t->dst.u3.ip;
		if (t->dst.protonum == IPPROTO_TCP ||
		    t->dst.protonum == IPPROTO_UDP ||
		    t->dst.protonum == IPPROTO_UDPLITE ||
		    t->dst.protonum == IPPROTO_DCCP ||
		    t->dst.protonum == IPPROTO_SCTP)
			fl4->fl4_dport = t->dst.u.all;
	}

	statusbit ^= IPS_NAT_MASK;

	if (ct->status & statusbit) {
		fl4->saddr = t->src.u3.ip;
		if (t->dst.protonum == IPPROTO_TCP ||
		    t->dst.protonum == IPPROTO_UDP ||
		    t->dst.protonum == IPPROTO_UDPLITE ||
		    t->dst.protonum == IPPROTO_DCCP ||
		    t->dst.protonum == IPPROTO_SCTP)
			fl4->fl4_sport = t->src.u.all;
	}
}
#endif /* CONFIG_XFRM */

static bool nf_nat_ipv4_in_range(const struct nf_conntrack_tuple *t,
				 const struct nf_nat_range *range)
{
	return ntohl(t->src.u3.ip) >= ntohl(range->min_addr.ip) &&
	       ntohl(t->src.u3.ip) <= ntohl(range->max_addr.ip);
}

static u32 nf_nat_ipv4_secure_port(const struct nf_conntrack_tuple *t,
				   __be16 dport)
{
	return secure_ipv4_port_ephemeral(t->src.u3.ip, t->dst.u3.ip, dport);
}

static bool nf_nat_ipv4_manip_pkt(struct sk_buff *skb,
				  unsigned int iphdroff,
				  const struct nf_nat_l4proto *l4proto,
				  const struct nf_conntrack_tuple *target,
				  enum nf_nat_manip_type maniptype)
{
	struct iphdr *iph;
	unsigned int hdroff;

	if (!skb_make_writable(skb, iphdroff + sizeof(*iph)))
		return false;

	iph = (void *)skb->data + iphdroff;
	hdroff = iphdroff + iph->ihl * 4;

	if (!l4proto->manip_pkt(skb, &nf_nat_l3proto_ipv4, iphdroff, hdroff,
				target, maniptype))
		return false;
	iph = (void *)skb->data + iphdroff;

	if (maniptype == NF_NAT_MANIP_SRC) {
		csum_replace4(&iph->check, iph->saddr, target->src.u3.ip);
		iph->saddr = target->src.u3.ip;
	} else {
		csum_replace4(&iph->check, iph->daddr, target->dst.u3.ip);
		iph->daddr = target->dst.u3.ip;
	}
	return true;
}

static void nf_nat_ipv4_csum_update(struct sk_buff *skb,
				    unsigned int iphdroff, __sum16 *check,
				    const struct nf_conntrack_tuple *t,
				    enum nf_nat_manip_type maniptype)
{
	struct iphdr *iph = (struct iphdr *)(skb->data + iphdroff);
	__be32 oldip, newip;

	if (maniptype == NF_NAT_MANIP_SRC) {
		oldip = iph->saddr;
		newip = t->src.u3.ip;
	} else {
		oldip = iph->daddr;
		newip = t->dst.u3.ip;
	}
	inet_proto_csum_replace4(check, skb, oldip, newip, 1);
}

static void nf_nat_ipv4_csum_recalc(struct sk_buff *skb,
				    u8 proto, void *data, __sum16 *check,
				    int datalen, int oldlen)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt = skb_rtable(skb);

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		if (!(rt->rt_flags & RTCF_LOCAL) &&
		    (!skb->dev || skb->dev->features & NETIF_F_V4_CSUM)) {
			skb->ip_summed = CHECKSUM_PARTIAL;
			skb->csum_start = skb_headroom(skb) +
					  skb_network_offset(skb) +
					  ip_hdrlen(skb);
			skb->csum_offset = (void *)check - data;
			*check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
						    datalen, proto, 0);
		} else {
			*check = 0;
			*check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						   datalen, proto,
						   csum_partial(data, datalen,
								0));
			if (proto == IPPROTO_UDP && !*check)
				*check = CSUM_MANGLED_0;
		}
	} else
		inet_proto_csum_replace2(check, skb,
					 htons(oldlen), htons(datalen), 1);
}

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
static int nf_nat_ipv4_nlattr_to_range(struct nlattr *tb[],
				       struct nf_nat_range *range)
{
	if (tb[CTA_NAT_V4_MINIP]) {
		range->min_addr.ip = nla_get_be32(tb[CTA_NAT_V4_MINIP]);
		range->flags |= NF_NAT_RANGE_MAP_IPS;
	}

	if (tb[CTA_NAT_V4_MAXIP])
		range->max_addr.ip = nla_get_be32(tb[CTA_NAT_V4_MAXIP]);
	else
		range->max_addr.ip = range->min_addr.ip;

	return 0;
}
#endif

static const struct nf_nat_l3proto nf_nat_l3proto_ipv4 = {
	.l3proto		= NFPROTO_IPV4,
	.in_range		= nf_nat_ipv4_in_range,
	.secure_port		= nf_nat_ipv4_secure_port,
	.manip_pkt		= nf_nat_ipv4_manip_pkt,
	.csum_update		= nf_nat_ipv4_csum_update,
	.csum_recalc		= nf_nat_ipv4_csum_recalc,
#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	.nlattr_to_range	= nf_nat_ipv4_nlattr_to_range,
#endif
#ifdef CONFIG_XFRM
	.decode_session		= nf_nat_ipv4_decode_session,
#endif
};

int nf_nat_icmp_reply_translation(struct sk_buff *skb,
				  struct nf_conn *ct,
				  enum ip_conntrack_info ctinfo,
				  unsigned int hooknum)
{
	struct {
		struct icmphdr	icmp;
		struct iphdr	ip;
	} *inside;
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	enum nf_nat_manip_type manip = HOOK2MANIP(hooknum);
	unsigned int hdrlen = ip_hdrlen(skb);
	const struct nf_nat_l4proto *l4proto;
	struct nf_conntrack_tuple target;
	unsigned long statusbit;

	NF_CT_ASSERT(ctinfo == IP_CT_RELATED || ctinfo == IP_CT_RELATED_REPLY);

	if (!skb_make_writable(skb, hdrlen + sizeof(*inside)))
		return 0;
	if (nf_ip_checksum(skb, hooknum, hdrlen, 0))
		return 0;

	inside = (void *)skb->data + hdrlen;
	if (inside->icmp.type == ICMP_REDIRECT) {
		if ((ct->status & IPS_NAT_DONE_MASK) != IPS_NAT_DONE_MASK)
			return 0;
		if (ct->status & IPS_NAT_MASK)
			return 0;
	}

	if (manip == NF_NAT_MANIP_SRC)
		statusbit = IPS_SRC_NAT;
	else
		statusbit = IPS_DST_NAT;

	/* Invert if this is reply direction */
	if (dir == IP_CT_DIR_REPLY)
		statusbit ^= IPS_NAT_MASK;
	
	//是否需要NAT转换
	if (!(ct->status & statusbit))
		return 1;

	//转换内嵌IP数据头的IP地址
	l4proto = __nf_nat_l4proto_find(NFPROTO_IPV4, inside->ip.protocol);
	if (!nf_nat_ipv4_manip_pkt(skb, hdrlen + sizeof(inside->icmp),
				   l4proto, &ct->tuplehash[!dir].tuple, !manip))
		return 0;

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		/* Reloading "inside" here since manip_pkt may reallocate */
		inside = (void *)skb->data + hdrlen;
		inside->icmp.checksum = 0;
		inside->icmp.checksum =
			csum_fold(skb_checksum(skb, hdrlen,
					       skb->len - hdrlen, 0));
	}
	//转换实际外部IP头的IP地址
	/* Change outer to look like the reply to an incoming packet */
	nf_ct_invert_tuplepr(&target, &ct->tuplehash[!dir].tuple);
	l4proto = __nf_nat_l4proto_find(NFPROTO_IPV4, 0);
	if (!nf_nat_ipv4_manip_pkt(skb, 0, l4proto, &target, manip))
		return 0;

	return 1;
}
EXPORT_SYMBOL_GPL(nf_nat_icmp_reply_translation);

//只要内核配置了支持NAT，即使用户没有添加nat规则，
//每个conntrack 都需要额外做一次NAT空绑定，所谓空绑定，就是不会改变IP地址
//但是有可能会改变端口，空绑定的目的是为了保证conntrack表中五元组的唯一性
//比如本地发出的数据包到目的地C:80端口，标为连接A
//然后存在转发的数据包也是到目的地C:80端口,标为连接B
//假设B经过了NAT转换，变为D:8080
//然后删除NAT规则
//由于连接A不知道8080端口被占用了，并且A要使用D这个地址，如果A使用D:8080端口
//就会冲突，所以这种情况下A必须执行一次空绑定，选择一个
//另外的源端口号
unsigned int
nf_nat_ipv4_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
	       const struct net_device *in, const struct net_device *out,
	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					struct sk_buff *skb,
					const struct net_device *in,
					const struct net_device *out,
					struct nf_conn *ct))
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_nat *nat;
	/* maniptype == SRC for postrouting. */
	enum nf_nat_manip_type maniptype = HOOK2MANIP(ops->hooknum);

	/* We never see fragments: conntrack defrags on pre-routing
	 * and local-out, and nf_nat_out protects post-routing.
	 */
	NF_CT_ASSERT(!ip_is_fragment(ip_hdr(skb)));

	ct = nf_ct_get(skb, &ctinfo);
	/* Can't track?  It's not due to stress, or conntrack would
	 * have dropped it.  Hence it's the user's responsibilty to
	 * packet filter it out, or implement conntrack/NAT for that
	 * protocol. 8) --RR
	 */
	if (!ct)
		return NF_ACCEPT;

	/* Don't try to NAT if this packet is not conntracked */
	if (nf_ct_is_untracked(ct))
		return NF_ACCEPT;

	//检查nat扩展是否存在
	//nat实现依赖此扩展
	nat = nf_ct_nat_ext_add(ct);
	if (nat == NULL)
		return NF_ACCEPT;

	switch (ctinfo) {
	case IP_CT_RELATED:
	case IP_CT_RELATED_REPLY:
		//会出现IP_CT_RELATED的情况
		//对于期待连接，也会出现IP_CT_RELATED的情况

		//ICMP 需要做特殊的处理,根据RFC2663要求
		//ICMP error packet 的负载部分需要NAT 还原处理
		//比如对于UDP 有可能连接的发起方关闭了套接字
		//如果对端再发数据，就会出现ICMP_DEST_UNREACH错误
		//如果是ICMP协议，需要做特殊的NAT处理
		//前提是skb 为IP_CT_RELATED类型的，
		//如果不是就不需要做特别的处理
		if (ip_hdr(skb)->protocol == IPPROTO_ICMP) {
			if (!nf_nat_icmp_reply_translation(skb, ct, ctinfo,
							   ops->hooknum))
				return NF_DROP;
			else
				return NF_ACCEPT;
		}
		/* Fall thru... (Only ICMPs can be IP_CT_IS_REPLY) */
	case IP_CT_NEW:
		/* Seen it before?  This can happen for loopback, retrans,
		 * or local packets.
		 */
		if (!nf_nat_initialized(ct, maniptype)) {
			unsigned int ret;
			//遍历用户配置的NAT规则，最终都会调用nf_nat_setup_info函数包NAT信息保存到conntrak中
			//注意内核实现只会将NAT后的地址保存到reply tuple中，而不会去更改original tuple
			//因此用户原始的连接信息都可以通过original tuple来获取
			ret = do_chain(ops, skb, in, out, ct);
			if (ret != NF_ACCEPT)
				return ret;
			//如果数据包已经在NAT模块中处理过了
			//也就是调用过nf_nat_setup_info函数
			//那么就不需要再执行下面的空绑定流程了
			if (nf_nat_initialized(ct, HOOK2MANIP(ops->hooknum)))
				break;
			//如果数据包没有经过nat 处理，比如没有配置nat规则
			//根据目前nat 的实现，必须做一次空绑定
			ret = nf_nat_alloc_null_binding(ct, ops->hooknum);
			if (ret != NF_ACCEPT)
				return ret;
		} else {
			pr_debug("Already setup manip %s for ct %p\n",
				 maniptype == NF_NAT_MANIP_SRC ? "SRC" : "DST",
				 ct);
			//nf_nat_oif_changed 是在netfilter 上提交的patch 上做出的修改
			//netfilter: nf_nat: Handle routing changes in MASQUERADE target
			//When the route changes (backup default route, VPNs) which affect a
			//masqueraded target, the packets were sent out with the outdated source
			//address. The patch addresses the issue by comparing the outgoing interface
			//directly with the masqueraded interface in the nat table.

			//Events are inefficient in this case, because it'd require adding route
			//events to the network core and then scanning the whole conntrack table
			//and re-checking the route for all entry.

			//对于MASQUERADE 模块，会记录出口设备的索引到
			//masq_index, 如果这里的出口索引变更了，表示
			//设备有变化，比如在多wan的情况下，每次选择的出口有变化，需要销毁conntrack
			//这里意思应该是对于同一条数据流应该始终选择同一个出口
			//除非设备注销了或者确实不可用
			//MASQUERADE 是根据规则配置的出口设备动态选择IP地址的
			//而SNAT 和DNAT 模块则是完全静态的
			//会根据你设置的规则来转换
			//规则不会受出口设备的影响，这也是他的缺点，如果出口IP地址改变了
			//则无法正常工作
			if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
				goto oif_changed;
		}
		break;

	default:
		/* ESTABLISHED */
		NF_CT_ASSERT(ctinfo == IP_CT_ESTABLISHED ||
			     ctinfo == IP_CT_ESTABLISHED_REPLY);
		if (nf_nat_oif_changed(ops->hooknum, ctinfo, nat, out))
			goto oif_changed;
	}
	//做实际的数据包修改工作，根据conntrack中保存的信息对数据包做NAT转换
	return nf_nat_packet(ct, ctinfo, ops->hooknum, skb);

oif_changed:
	nf_ct_kill_acct(ct, ctinfo, skb);
	return NF_DROP;
}
EXPORT_SYMBOL_GPL(nf_nat_ipv4_fn);

unsigned int
nf_nat_ipv4_in(const struct nf_hook_ops *ops, struct sk_buff *skb,
	       const struct net_device *in, const struct net_device *out,
	       unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					 struct sk_buff *skb,
					 const struct net_device *in,
					 const struct net_device *out,
					 struct nf_conn *ct))
{
	unsigned int ret;
	__be32 daddr = ip_hdr(skb)->daddr;

	ret = nf_nat_ipv4_fn(ops, skb, in, out, do_chain);
	if (ret != NF_DROP && ret != NF_STOLEN &&
	    daddr != ip_hdr(skb)->daddr)
		skb_dst_drop(skb);

	return ret;
}
EXPORT_SYMBOL_GPL(nf_nat_ipv4_in);

unsigned int
nf_nat_ipv4_out(const struct nf_hook_ops *ops, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					  struct sk_buff *skb,
					  const struct net_device *in,
					  const struct net_device *out,
					  struct nf_conn *ct))
{
#ifdef CONFIG_XFRM
	const struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	int err;
#endif
	unsigned int ret;

	/* root is playing with raw sockets. */
	if (skb->len < sizeof(struct iphdr) ||
	    ip_hdrlen(skb) < sizeof(struct iphdr))
		return NF_ACCEPT;

	ret = nf_nat_ipv4_fn(ops, skb, in, out, do_chain);
#ifdef CONFIG_XFRM
	if (ret != NF_DROP && ret != NF_STOLEN &&
	    !(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
		//如果改变了目的IP地址，需要重新路由
		if ((ct->tuplehash[dir].tuple.src.u3.ip !=
		     ct->tuplehash[!dir].tuple.dst.u3.ip) ||
		    (ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMP &&
		     ct->tuplehash[dir].tuple.src.u.all !=
		     ct->tuplehash[!dir].tuple.dst.u.all)) {
			err = nf_xfrm_me_harder(skb, AF_INET);
			if (err < 0)
				ret = NF_DROP_ERR(err);
		}
	}
#endif
	return ret;
}
EXPORT_SYMBOL_GPL(nf_nat_ipv4_out);

unsigned int
nf_nat_ipv4_local_fn(const struct nf_hook_ops *ops, struct sk_buff *skb,
		     const struct net_device *in, const struct net_device *out,
		     unsigned int (*do_chain)(const struct nf_hook_ops *ops,
					       struct sk_buff *skb,
					       const struct net_device *in,
					       const struct net_device *out,
					       struct nf_conn *ct))
{
	const struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	unsigned int ret;
	int err;

	/* root is playing with raw sockets. */
	if (skb->len < sizeof(struct iphdr) ||
	    ip_hdrlen(skb) < sizeof(struct iphdr))
		return NF_ACCEPT;

	ret = nf_nat_ipv4_fn(ops, skb, in, out, do_chain);
	if (ret != NF_DROP && ret != NF_STOLEN &&
	    (ct = nf_ct_get(skb, &ctinfo)) != NULL) {
		enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
		//在LOCAL_OUT点调用,如果改变了目的IP地址，需要重新路由
		if (ct->tuplehash[dir].tuple.dst.u3.ip !=
		    ct->tuplehash[!dir].tuple.src.u3.ip) {
			err = ip_route_me_harder(skb, RTN_UNSPEC);
			if (err < 0)
				ret = NF_DROP_ERR(err);
		}
#ifdef CONFIG_XFRM
		else if (!(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
			 ct->tuplehash[dir].tuple.dst.protonum != IPPROTO_ICMP &&
			 ct->tuplehash[dir].tuple.dst.u.all !=
			 ct->tuplehash[!dir].tuple.src.u.all) {
			err = nf_xfrm_me_harder(skb, AF_INET);
			if (err < 0)
				ret = NF_DROP_ERR(err);
		}
#endif
	}
	return ret;
}
EXPORT_SYMBOL_GPL(nf_nat_ipv4_local_fn);

static int __init nf_nat_l3proto_ipv4_init(void)
{
	int err;

	err = nf_nat_l4proto_register(NFPROTO_IPV4, &nf_nat_l4proto_icmp);
	if (err < 0)
		goto err1;
	err = nf_nat_l3proto_register(&nf_nat_l3proto_ipv4);
	if (err < 0)
		goto err2;
	return err;

err2:
	nf_nat_l4proto_unregister(NFPROTO_IPV4, &nf_nat_l4proto_icmp);
err1:
	return err;
}

static void __exit nf_nat_l3proto_ipv4_exit(void)
{
	nf_nat_l3proto_unregister(&nf_nat_l3proto_ipv4);
	nf_nat_l4proto_unregister(NFPROTO_IPV4, &nf_nat_l4proto_icmp);
}

MODULE_LICENSE("GPL");
MODULE_ALIAS("nf-nat-" __stringify(AF_INET));

module_init(nf_nat_l3proto_ipv4_init);
module_exit(nf_nat_l3proto_ipv4_exit);
