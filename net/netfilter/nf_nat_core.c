/*
 * (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2011 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include <net/xfrm.h>
#include <linux/jhash.h>
#include <linux/rtnetlink.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_l3proto.h>
#include <net/netfilter/nf_nat_l4proto.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <linux/netfilter/nf_nat.h>

static DEFINE_SPINLOCK(nf_nat_lock);

static DEFINE_MUTEX(nf_nat_proto_mutex);
static const struct nf_nat_l3proto __rcu *nf_nat_l3protos[NFPROTO_NUMPROTO]
						__read_mostly;
static const struct nf_nat_l4proto __rcu **nf_nat_l4protos[NFPROTO_NUMPROTO]
						__read_mostly;


inline const struct nf_nat_l3proto *
__nf_nat_l3proto_find(u8 family)
{
	return rcu_dereference(nf_nat_l3protos[family]);
}

inline const struct nf_nat_l4proto *
__nf_nat_l4proto_find(u8 family, u8 protonum)
{
	return rcu_dereference(nf_nat_l4protos[family][protonum]);
}
EXPORT_SYMBOL_GPL(__nf_nat_l4proto_find);

#ifdef CONFIG_XFRM
static void __nf_nat_decode_session(struct sk_buff *skb, struct flowi *fl)
{
	const struct nf_nat_l3proto *l3proto;
	const struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	enum ip_conntrack_dir dir;
	unsigned  long statusbit;
	u8 family;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL)
		return;

	family = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num;
	rcu_read_lock();
	l3proto = __nf_nat_l3proto_find(family);
	if (l3proto == NULL)
		goto out;

	dir = CTINFO2DIR(ctinfo);
	if (dir == IP_CT_DIR_ORIGINAL)
		statusbit = IPS_DST_NAT;
	else
		statusbit = IPS_SRC_NAT;

	l3proto->decode_session(skb, ct, dir, statusbit, fl);
out:
	rcu_read_unlock();
}

int nf_xfrm_me_harder(struct sk_buff *skb, unsigned int family)
{
	struct flowi fl;
	unsigned int hh_len;
	struct dst_entry *dst;
	int err;

	err = xfrm_decode_session(skb, &fl, family);
	if (err < 0)
		return err;

	dst = skb_dst(skb);
	if (dst->xfrm)
		dst = ((struct xfrm_dst *)dst)->route;
	dst_hold(dst);

	dst = xfrm_lookup(dev_net(dst->dev), dst, &fl, skb->sk, 0);
	if (IS_ERR(dst))
		return PTR_ERR(dst);

	skb_dst_drop(skb);
	skb_dst_set(skb, dst);

	/* Change in oif may mean change in hh_len. */
	hh_len = skb_dst(skb)->dev->hard_header_len;
	if (skb_headroom(skb) < hh_len &&
	    pskb_expand_head(skb, hh_len - skb_headroom(skb), 0, GFP_ATOMIC))
		return -ENOMEM;
	return 0;
}
EXPORT_SYMBOL(nf_xfrm_me_harder);
#endif /* CONFIG_XFRM */

/* We keep an extra hash for each conntrack, for fast searching. */
static inline unsigned int
hash_by_src(const struct net *net, u16 zone,
	    const struct nf_conntrack_tuple *tuple)
{
	unsigned int hash;

	/* Original src, to ensure we map it consistently if poss. */
	hash = jhash2((u32 *)&tuple->src, sizeof(tuple->src) / sizeof(u32),
		      tuple->dst.protonum ^ zone ^ nf_conntrack_hash_rnd);

	return reciprocal_scale(hash, net->ct.nat_htable_size);
}

/* Is this tuple already taken? (not by us) */
int
nf_nat_used_tuple(const struct nf_conntrack_tuple *tuple,
		  const struct nf_conn *ignored_conntrack)
{
	/* Conntrack tracking doesn't keep track of outgoing tuples; only
	 * incoming ones.  NAT means they don't have a fixed mapping,
	 * so we invert the tuple and look for the incoming reply.
	 *
	 * We could keep a separate hash if this proves too slow.
	 */
	struct nf_conntrack_tuple reply;

	nf_ct_invert_tuplepr(&reply, tuple);
	return nf_conntrack_tuple_taken(&reply, ignored_conntrack);
}
EXPORT_SYMBOL(nf_nat_used_tuple);

/* If we source map this tuple so reply looks like reply_tuple, will
 * that meet the constraints of range.
 */
static int in_range(const struct nf_nat_l3proto *l3proto,
		    const struct nf_nat_l4proto *l4proto,
		    const struct nf_conntrack_tuple *tuple,
		    const struct nf_nat_range *range)
{
	/* If we are supposed to map IPs, then we must be in the
	 * range specified, otherwise let this drag us onto a new src IP.
	 */
	//检查src IP地址是否在range范围内
	if (range->flags & NF_NAT_RANGE_MAP_IPS &&
	    !l3proto->in_range(tuple, range))
		return 0;
	//检查端口是否在range范围内
	if (!(range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) ||
	    l4proto->in_range(tuple, NF_NAT_MANIP_SRC,
			      &range->min_proto, &range->max_proto))
		return 1;

	return 0;
}

static inline int
same_src(const struct nf_conn *ct,
	 const struct nf_conntrack_tuple *tuple)
{
	const struct nf_conntrack_tuple *t;

	t = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	return (t->dst.protonum == tuple->dst.protonum &&
		nf_inet_addr_cmp(&t->src.u3, &tuple->src.u3) &&
		t->src.u.all == tuple->src.u.all);
}

/* Only called for SRC manip */
static int
find_appropriate_src(struct net *net, u16 zone,
		     const struct nf_nat_l3proto *l3proto,
		     const struct nf_nat_l4proto *l4proto,
		     const struct nf_conntrack_tuple *tuple,
		     struct nf_conntrack_tuple *result,
		     const struct nf_nat_range *range)
{
	unsigned int h = hash_by_src(net, zone, tuple);
	const struct nf_conn_nat *nat;
	const struct nf_conn *ct;

	hlist_for_each_entry_rcu(nat, &net->ct.nat_bysource[h], bysource) {
		ct = nat->ct;
		if (same_src(ct, tuple) && nf_ct_zone(ct) == zone) {
			/* Copy source part from reply tuple. */
			//映射到相同的源地址
			nf_ct_invert_tuplepr(result,
				       &ct->tuplehash[IP_CT_DIR_REPLY].tuple);
			//保存实际的目的地址
			result->dst = tuple->dst;

			if (in_range(l3proto, l4proto, result, range))
				return 1;
		}
	}
	return 0;
}

/* For [FUTURE] fragmentation handling, we want the least-used
 * src-ip/dst-ip/proto triple.  Fairness doesn't come into it.  Thus
 * if the range specifies 1.2.3.4 ports 10000-10005 and 1.2.3.5 ports
 * 1-65535, we don't do pro-rata allocation based on ports; we choose
 * the ip with the lowest src-ip/dst-ip/proto usage.
 */
static void
find_best_ips_proto(u16 zone, struct nf_conntrack_tuple *tuple,
		    const struct nf_nat_range *range,
		    const struct nf_conn *ct,
		    enum nf_nat_manip_type maniptype)
{
	union nf_inet_addr *var_ipp;
	unsigned int i, max;
	/* Host order */
	u32 minip, maxip, j, dist;
	bool full_range;

	/* No IP mapping?  Do nothing. */
	if (!(range->flags & NF_NAT_RANGE_MAP_IPS))
		return;

	if (maniptype == NF_NAT_MANIP_SRC)
		var_ipp = &tuple->src.u3;
	else
		var_ipp = &tuple->dst.u3;

	/* Fast path: only one choice. */
	//只有一地址可以选择的情况
	if (nf_inet_addr_cmp(&range->min_addr, &range->max_addr)) {��
		//���ڵ�wan·������˵��ֻ��һ��IP��ַ����ѡ��
		*var_ipp = range->min_addr;
		return;
	}
	//����IP��ַ��������ֵ
	if (nf_ct_l3num(ct) == NFPROTO_IPV4)
		max = sizeof(var_ipp->ip) / sizeof(u32) - 1; //max = 0
	else
		max = sizeof(var_ipp->ip6) / sizeof(u32) - 1;//max=3

	/* Hashing source and destination IPs gives a fairly even
	 * spread in practice (if there are a small number of IPs
	 * involved, there usually aren't that many connections
	 * anyway).  The consistency means that servers see the same
	 * client coming from the same IP (some Internet Banking sites
	 * like this), even across reboots.
	 */
	 //NF_NAT_RANGE_PERSISTENT����˼�Ǳ�֤��һ�������ĵ�ַ��Χ��
	 //ǰ��ӳ�䵽��ͬ��IP��ַ
	 //����A��ʼʱӳ�䵽B,��conntrack��ʱ��A����ӳ�䵽B
	 //����A�п���ӳ�䵽C
	 //���������j��ֵ��3
	j = jhash2((u32 *)&tuple->src.u3, sizeof(tuple->src.u3) / sizeof(u32),
		   range->flags & NF_NAT_RANGE_PERSISTENT ?
			0 : (__force u32)tuple->dst.u3.all[max] ^ zone);

	full_range = false;
	//����IPV4��˵��ֻ��ѡ��һ��
	for (i = 0; i <= max; i++) {
		/* If first bytes of the address are at the maximum, use the
		 * distance. Otherwise use the full range.
		 */
		if (!full_range) {
			// 2
			minip = ntohl((__force __be32)range->min_addr.all[i]);
			// 6
			maxip = ntohl((__force __be32)range->max_addr.all[i]);
			//minip��maxip �ĵ�ַ�ռ��������ģ���֧�ֳ��ֿն������
			//����IP��ַ��ľ���
			// 6 - 2 + 1 = 5
			dist  = maxip - minip + 1;
		} else {
			//ipv6����Ч
			//����minip����Ϊ0��IP��ַѡ����ȫ��reciprocal_scale
			//����������ΧΪ[0, 0xFFFFFFFF)�������full_range����˼
			minip = 0;
			dist  = ~0;
		}
		// 2.6.5.4.3
		// 6.7.3.3.2
		//�������һ��ip��ַ
		//reciprocal_scale���������Ľ������[0, dist) ֮��
		//������֤������IP��ַ��[minip, maxip]��Χ��
		var_ipp->all[i] = (__force __u32)
			htonl(minip + reciprocal_scale(j, dist));
		//full_range ֻ��ipv6����Ч
		//��IPV6�У�ֻ��Ҫ��֤�����Чλ��4���ֽ�
		//С��maxip����������ַ�϶���С��maxip�ģ�
		//ʣ�µ�3���ֽڿ�����ȫ��[0, 0xFFFFFFFF) 4�ֽڵĵ�ַ�ռ������ѡ��
		//���ܱ�֤ip��ַ��[minip, maxip]��Χ��
		//�������max_addr.all[i]����������full_range
		//�������ֳ���maxip�����
		//����IP��ַ��ΧΪ[112, 988]����ַ�ռ�Ϊ[0~10)
		//��һ��ѡ��9���������full_range�� �ڶ��ο���ѡ��9
		//�ͳ���988��
		if (var_ipp->all[i] != range->max_addr.all[i])
			full_range = true;
		//���������NF_NAT_RANGE_PERSISTENT��������j��ֵ
		//����reciprocal_scale  �������ͬ��ֵ
		if (!(range->flags & NF_NAT_RANGE_PERSISTENT))
			j ^= (__force u32)tuple->dst.u3.all[i];
	}
}

/* Manipulate the tuple into the range given. For NF_INET_POST_ROUTING,
 * we change the source to map into the range. For NF_INET_PRE_ROUTING
 * and NF_INET_LOCAL_OUT, we change the destination to map into the
 * range. It might not be possible to get a unique tuple, but we try.
 * At worst (or if we race), we will end up with a final duplicate in
 * __ip_conntrack_confirm and drop the packet. */
static void
get_unique_tuple(struct nf_conntrack_tuple *tuple,
		 const struct nf_conntrack_tuple *orig_tuple,
		 const struct nf_nat_range *range,
		 struct nf_conn *ct,
		 enum nf_nat_manip_type maniptype)
{
	const struct nf_nat_l3proto *l3proto;
	const struct nf_nat_l4proto *l4proto;
	struct net *net = nf_ct_net(ct);
	u16 zone = nf_ct_zone(ct);

	rcu_read_lock();
	l3proto = __nf_nat_l3proto_find(orig_tuple->src.l3num);
	l4proto = __nf_nat_l4proto_find(orig_tuple->src.l3num,
					orig_tuple->dst.protonum);

	/* 1) If this srcip/proto/src-proto-part is currently mapped,
	 * and that same mapping gives a unique tuple within the given
	 * range, use that.
	 *
	 * This is only required for source (ie. NAT/masq) mappings.
	 * So far, we don't do local source mappings, so multiple
	 * manips not an issue.
	 */
	 //只能是源地址nat的情况下才能做相同的映射
	 //目的地址NAT是不可能映射到相同的目的地址
	 //否则，数据包会到达错误的目的地址
	if (maniptype == NF_NAT_MANIP_SRC &&
	    !(range->flags & NF_NAT_RANGE_PROTO_RANDOM_ALL)) {
		/* try the original tuple first */
		//
		//     orig_tuple为192.168.18.100:10088---------->61.139.2.69:80
		//路由器的wan口ip地址为172.168.3.36
		//假设对wan口是用了MASQUERADE模块
		//range指定的ip地址为172.168.3.36
		//这里先尝试使用原IP地址和端口是否可行
		//这里192.168.18.100不在range指定的IP地址172.168.3.36范围内
		if (in_range(l3proto, l4proto, orig_tuple, range)) {
			//大多是情况下只有本机发出去数据包才会到达这里
			//可行，检查该tuple是否冲突
			if (!nf_nat_used_tuple(orig_tuple, ct)) {
				//ok，tuple唯一
				*tuple = *orig_tuple;
				goto out;
			}
		//在ct.nat_bysource中选择是否可以映射到相同的源地址
		//这样可以节约端口号
		//就是说有相同的四层协议和源地址、源端口的映射表已经存在
		//假设已经存在一个192.168.18.100：1008,TCP的映射
		//其源地址映射到172.168.3.36:10088--->61.139.2.69:8080
		//192.168.18.100:10088---------->61.139.2.69:80将会被映射到
		//172.168.3.36:10088 ---------->61.139.2.69:80
		//因为这里目的端口不一样
		} else if (find_appropriate_src(net, zone, l3proto, l4proto,
						orig_tuple, tuple, range)) {
			pr_debug("get_unique_tuple: Found current src map\n");
			//因为这里目的端口不同，tuple不会冲突，如果tuple冲突
			//进入下面的流程
			//tuple取反，看是否有冲突的tuple，
			//61.139.2.69:80------->172.168.3.36:10088
			//假设先前的链接192.168.18.110:10088---------->61.139.2.69:80
			//被映射到了172.168.3.36:10088 ---------->61.139.2.69:80
			//这个时候就会冲突了
			//所以只有在目的地址或目的端口不同的情况下才可能做相同的映射
			if (!nf_nat_used_tuple(tuple, ct))
				goto out;
		}
	}

	/* 2) Select the least-used IP/proto combination in the given range */
	*tuple = *orig_tuple;
	//选择一个合适的IP地址
	find_best_ips_proto(zone, tuple, range, ct, maniptype);

	//下面代码都是做端口选择，IP地址映射在上面代码中已经完成
	/* 3) The per-protocol part of the manip is made to map into
	 * the range to make a unique tuple.
	 */
	//下面就是根据L4协议选择合适的端口
	/* Only bother mapping if it's not already in range and unique */
	if (!(range->flags & NF_NAT_RANGE_PROTO_RANDOM_ALL)) {
			//如果源端口恰好在指定范围内
			//并且范围相等或者tuple不冲突
			//NF_NAT_RANGE_PROTO_SPECIFIED 意思是需要检查端口是否在配置的范围内
		if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
			if (l4proto->in_range(tuple, maniptype,
					      &range->min_proto,
					      &range->max_proto) &&
			    (range->min_proto.all == range->max_proto.all ||
			     !nf_nat_used_tuple(tuple, ct)))
				goto out;
		} else if (!nf_nat_used_tuple(tuple, ct)) {
			goto out;
		}
	}
	//前面的尝试都失败，或者设置了NF_NAT_RANGE_PROTO_RANDOM_ALL标志
	//则做随机化的端口选择
	/* Last change: get protocol to try to obtain unique tuple. */
	l4proto->unique_tuple(l3proto, tuple, range, maniptype, ct);
out:
	//最终可能生成的tuple并不是唯一的，但是我们已经尽力了
	//对不是唯一的tuple，最终会在ipv4_confirm中丢弃该数据包
	//所以这是NAT的坏处，如果是IPV6，每台设备的IP地址都不一样
	//就不会出现这个情况
	rcu_read_unlock();
}

struct nf_conn_nat *nf_ct_nat_ext_add(struct nf_conn *ct)
{
	struct nf_conn_nat *nat = nfct_nat(ct);
	if (nat)
		return nat;

	if (!nf_ct_is_confirmed(ct))
		nat = nf_ct_ext_add(ct, NF_CT_EXT_NAT, GFP_ATOMIC);

	return nat;
}
EXPORT_SYMBOL_GPL(nf_ct_nat_ext_add);
//正常情况下，nf_nat_packet只会调用2次
//nf_nat_setup_info最多也只调用2次
//但是如果NAT模块返回了NF_REPEAT，则视情况
//内核标准的NAT模块实现是不会这么做的
unsigned int
nf_nat_setup_info(struct nf_conn *ct,
		  const struct nf_nat_range *range,
		  enum nf_nat_manip_type maniptype)
{
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_tuple curr_tuple, new_tuple;
	struct nf_conn_nat *nat;

	/* nat helper or nfctnetlink also setup binding */
	nat = nf_ct_nat_ext_add(ct);
	if (nat == NULL)
		return NF_ACCEPT;

	NF_CT_ASSERT(maniptype == NF_NAT_MANIP_SRC ||
		     maniptype == NF_NAT_MANIP_DST);
	BUG_ON(nf_nat_initialized(ct, maniptype));

	/* What we've got will look like inverse of reply. Normally
	 * this is what is in the conntrack, except for prior
	 * manipulations (future optimization: if num_manips == 0,
	 * orig_tp = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple)
	 */
	 //转换的原则是始终都不更改ct IP_CT_DIR_ORIGINAL的值，只会更改IP_CT_DIR_REPLY的值
	 //假设转换前ct中的tuple值为
	//original:192.168.18.100:10088 ------->61.139.2.69:80
	//replay:61.139.2.69:80---------->192.168.18.100:10088
	//则curr_tuple：192.168.18.100:10088 ------->61.139.2.69:80
	nf_ct_invert_tuplepr(&curr_tuple,
			     &ct->tuplehash[IP_CT_DIR_REPLY].tuple);
	//获取一个唯一的反向tuple，可能会出现tuple冲突
	//在ipv4_confirm中会再次检查tuple的唯一性
	//假设做了目的地址转换。则
	//new_tuple:192.168.18.100:10088 ------->61.139.2.70:90
	get_unique_tuple(&new_tuple, &curr_tuple, range, ct, maniptype);

	if (!nf_ct_tuple_equal(&new_tuple, &curr_tuple)) {
		struct nf_conntrack_tuple reply;
	//正常情况下，NAT信息的设置都是在流首包完成的
	//也就是说此刻conntrack未被加入到hash表中，是新建的conntrack
	//该skb独占该conntrack，在conntrack被加入到全局hash表后
	//不会再调用次函数，因为所需的NAT信息都已经建立完成
	//这是内核NAT实现的规定
	//不需要加锁，因为conntrack 还未加入hash表中，未被确认
	//conntrack 处于unconfirm 链表中，是skb 独有的
	//其他skb此刻不可能匹配到该conntrack
		/* Alter conntrack table so will recognize replies. */
		//reply：61.139.2.70:90---------->192.168.18.100:10088
		nf_ct_invert_tuplepr(&reply, &new_tuple);
		//ct->tuplehash[IP_CT_DIR_REPLY].tuple:61.139.2.70:90---------->192.168.18.100:10088
		//以后reply的数据包在PREOUTING处不做转换，因为没设置IPS_SRC_NAT标志
		//然后经过POSTROUTING时，设置了IPS_DST_NAT标志，要做SNAT转换
		//返回数据包被修改为61.139.2.69:80---------->192.168.18.100:10088
		nf_conntrack_alter_reply(ct, &reply);
		//表示需要做NAT修改
		/* Non-atomic: we own this at the moment. */
		if (maniptype == NF_NAT_MANIP_SRC)
			ct->status |= IPS_SRC_NAT;
		else
			ct->status |= IPS_DST_NAT;

		if (nfct_help(ct))
			nfct_seqadj_ext_add(ct);
	}

	if (maniptype == NF_NAT_MANIP_SRC) {
		unsigned int srchash;

		srchash = hash_by_src(net, nf_ct_zone(ct),
				      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
		//因为nat扩展是内嵌于conntrack中的
		//所以这里不需要增加引用计数
		spin_lock_bh(&nf_nat_lock);
		/* nf_conntrack_alter_reply might re-allocate extension aera */
		nat = nfct_nat(ct);
		nat->ct = ct;
		hlist_add_head_rcu(&nat->bysource,
				   &net->ct.nat_bysource[srchash]);
		spin_unlock_bh(&nf_nat_lock);
	}
	// 表示流头包已完成NAT 信息设置
	// 后续跟该conntrack相关联的skb不再调用此函数
	/* It's done. */
	if (maniptype == NF_NAT_MANIP_DST)
		ct->status |= IPS_DST_NAT_DONE;
	else
		ct->status |= IPS_SRC_NAT_DONE;

	return NF_ACCEPT;
}
EXPORT_SYMBOL(nf_nat_setup_info);

static unsigned int
__nf_nat_alloc_null_binding(struct nf_conn *ct, enum nf_nat_manip_type manip)
{
	/* Force range to this IP; let proto decide mapping for
	 * per-proto parts (hence not IP_NAT_RANGE_PROTO_SPECIFIED).
	 * Use reply in case it's already been mangled (eg local packet).
	 */
	union nf_inet_addr ip =
		(manip == NF_NAT_MANIP_SRC ?
		ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3 :
		ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3);
	struct nf_nat_range range = {
		.flags		= NF_NAT_RANGE_MAP_IPS,
		.min_addr	= ip,
		.max_addr	= ip,
	};
	return nf_nat_setup_info(ct, &range, manip);
}
//因为有的数据包做了NAT规则，有的没有
//为了保证五元组的唯一性，要做空绑定
//Linux的NAT实现是基于ip_conntrack的，这句话已经不知道说了多少遍。一切均实现在Netflter的HOOK函数里面，
//其逻辑一点也不复杂，然而有意个小小的要点，那就是：即使没有匹配到任何的NAT规则的和NAT无关的数据流，
//也要针对其执行一个null_binding，所谓的null_binding就是用其原有的源IP地址和目标IP地址构造一个range，
//然后基于这个range做转换，这看似是一个无用的东西，其实还真的有用。
//用处在哪里呢？注意null_binding只是不改变IP地址，其端口可能要发生改变。
//为何要改变和NAT无关的数据流的端口呢？因为和NAT有关的数据流可能为了
//五元组的唯一性已经将和NAT无关的数据流的某个端口给占用了，这就影响了和NAT无关的数据流五元组的唯一性。
//由于ip_conntrack是不区分是否和NAT有关的，而NAT操作要改变五元组，为了整个conntrack的五元组都是唯一的，
//哪怕只有一个数据流执行了NAT，也可能占用了某个其它数据流的五元组要素，进而引发连锁反应，
//所以全部要执行唯一性检测和更新，alloc_null_binding就是为了做这个操作。
unsigned int
nf_nat_alloc_null_binding(struct nf_conn *ct, unsigned int hooknum)
{
	return __nf_nat_alloc_null_binding(ct, HOOK2MANIP(hooknum));
}
EXPORT_SYMBOL_GPL(nf_nat_alloc_null_binding);

//一个数据包要调用该函数2次
//因为nat在四个规则点注册了NAT函数回调
//假设是转发的数据包会先PREROUTING---------->FORWARDING----------->POSTROUTING
//假设是到本机的包PREROUTING--------->LOCAL_IN
//假设是本机发出的包LOCAL_OUT--------->POSTROUTING
//因此始终会调用该函数2次
//即使该数据包不需要做NAT转换
//也必须经过该函数的检查
/* Do packet manipulations according to nf_nat_setup_info. */
unsigned int nf_nat_packet(struct nf_conn *ct,
			   enum ip_conntrack_info ctinfo,
			   unsigned int hooknum,
			   struct sk_buff *skb)
{
	const struct nf_nat_l3proto *l3proto;
	const struct nf_nat_l4proto *l4proto;
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned long statusbit;
	enum nf_nat_manip_type mtype = HOOK2MANIP(hooknum);

	if (mtype == NF_NAT_MANIP_SRC)
		statusbit = IPS_SRC_NAT;
	else
		statusbit = IPS_DST_NAT;

	/* Invert if this is reply dir. */
	if (dir == IP_CT_DIR_REPLY)
		statusbit ^= IPS_NAT_MASK;

	//检查数据包是否需要做NAT转换
	/* Non-atomic: these bits don't change. */
	if (ct->status & statusbit) {
		struct nf_conntrack_tuple target;

		/* We are aiming to look like inverse of other direction. */
		nf_ct_invert_tuplepr(&target, &ct->tuplehash[!dir].tuple);

		l3proto = __nf_nat_l3proto_find(target.src.l3num);
		l4proto = __nf_nat_l4proto_find(target.src.l3num,
						target.dst.protonum);
		if (!l3proto->manip_pkt(skb, 0, l4proto, &target, mtype))
			return NF_DROP;
	}
	return NF_ACCEPT;
}
EXPORT_SYMBOL_GPL(nf_nat_packet);

struct nf_nat_proto_clean {
	u8	l3proto;
	u8	l4proto;
};

/* kill conntracks with affected NAT section */
static int nf_nat_proto_remove(struct nf_conn *i, void *data)
{
	const struct nf_nat_proto_clean *clean = data;
	struct nf_conn_nat *nat = nfct_nat(i);

	if (!nat)
		return 0;

	if ((clean->l3proto && nf_ct_l3num(i) != clean->l3proto) ||
	    (clean->l4proto && nf_ct_protonum(i) != clean->l4proto))
		return 0;

	return i->status & IPS_NAT_MASK ? 1 : 0;
}

static int nf_nat_proto_clean(struct nf_conn *ct, void *data)
{
	struct nf_conn_nat *nat = nfct_nat(ct);

	if (nf_nat_proto_remove(ct, data))
		return 1;

	if (!nat || !nat->ct)
		return 0;

	/* This netns is being destroyed, and conntrack has nat null binding.
	 * Remove it from bysource hash, as the table will be freed soon.
	 *
	 * Else, when the conntrack is destoyed, nf_nat_cleanup_conntrack()
	 * will delete entry from already-freed table.
	 */
	if (!del_timer(&ct->timeout))
		return 1;

	spin_lock_bh(&nf_nat_lock);
	hlist_del_rcu(&nat->bysource);
	ct->status &= ~IPS_NAT_DONE_MASK;
	nat->ct = NULL;
	spin_unlock_bh(&nf_nat_lock);

	add_timer(&ct->timeout);

	/* don't delete conntrack.  Although that would make things a lot
	 * simpler, we'd end up flushing all conntracks on nat rmmod.
	 */
	return 0;
}

static void nf_nat_l4proto_clean(u8 l3proto, u8 l4proto)
{
	struct nf_nat_proto_clean clean = {
		.l3proto = l3proto,
		.l4proto = l4proto,
	};
	struct net *net;

	rtnl_lock();
	for_each_net(net)
		nf_ct_iterate_cleanup(net, nf_nat_proto_remove, &clean, 0, 0);
	rtnl_unlock();
}

static void nf_nat_l3proto_clean(u8 l3proto)
{
	struct nf_nat_proto_clean clean = {
		.l3proto = l3proto,
	};
	struct net *net;

	rtnl_lock();

	for_each_net(net)
		nf_ct_iterate_cleanup(net, nf_nat_proto_remove, &clean, 0, 0);
	rtnl_unlock();
}

/* Protocol registration. */
int nf_nat_l4proto_register(u8 l3proto, const struct nf_nat_l4proto *l4proto)
{
	const struct nf_nat_l4proto **l4protos;
	unsigned int i;
	int ret = 0;

	mutex_lock(&nf_nat_proto_mutex);
	if (nf_nat_l4protos[l3proto] == NULL) {
		l4protos = kmalloc(IPPROTO_MAX * sizeof(struct nf_nat_l4proto *),
				   GFP_KERNEL);
		if (l4protos == NULL) {
			ret = -ENOMEM;
			goto out;
		}

		for (i = 0; i < IPPROTO_MAX; i++)
			RCU_INIT_POINTER(l4protos[i], &nf_nat_l4proto_unknown);

		/* Before making proto_array visible to lockless readers,
		 * we must make sure its content is committed to memory.
		 */
		smp_wmb();

		nf_nat_l4protos[l3proto] = l4protos;
	}

	if (rcu_dereference_protected(
			nf_nat_l4protos[l3proto][l4proto->l4proto],
			lockdep_is_held(&nf_nat_proto_mutex)
			) != &nf_nat_l4proto_unknown) {
		ret = -EBUSY;
		goto out;
	}
	RCU_INIT_POINTER(nf_nat_l4protos[l3proto][l4proto->l4proto], l4proto);
 out:
	mutex_unlock(&nf_nat_proto_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(nf_nat_l4proto_register);

/* No one stores the protocol anywhere; simply delete it. */
void nf_nat_l4proto_unregister(u8 l3proto, const struct nf_nat_l4proto *l4proto)
{
	mutex_lock(&nf_nat_proto_mutex);
	RCU_INIT_POINTER(nf_nat_l4protos[l3proto][l4proto->l4proto],
			 &nf_nat_l4proto_unknown);
	mutex_unlock(&nf_nat_proto_mutex);
	synchronize_rcu();

	nf_nat_l4proto_clean(l3proto, l4proto->l4proto);
}
EXPORT_SYMBOL_GPL(nf_nat_l4proto_unregister);

int nf_nat_l3proto_register(const struct nf_nat_l3proto *l3proto)
{
	int err;

	err = nf_ct_l3proto_try_module_get(l3proto->l3proto);
	if (err < 0)
		return err;

	mutex_lock(&nf_nat_proto_mutex);
	RCU_INIT_POINTER(nf_nat_l4protos[l3proto->l3proto][IPPROTO_TCP],
			 &nf_nat_l4proto_tcp);
	RCU_INIT_POINTER(nf_nat_l4protos[l3proto->l3proto][IPPROTO_UDP],
			 &nf_nat_l4proto_udp);
	mutex_unlock(&nf_nat_proto_mutex);

	RCU_INIT_POINTER(nf_nat_l3protos[l3proto->l3proto], l3proto);
	return 0;
}
EXPORT_SYMBOL_GPL(nf_nat_l3proto_register);

void nf_nat_l3proto_unregister(const struct nf_nat_l3proto *l3proto)
{
	mutex_lock(&nf_nat_proto_mutex);
	RCU_INIT_POINTER(nf_nat_l3protos[l3proto->l3proto], NULL);
	mutex_unlock(&nf_nat_proto_mutex);
	synchronize_rcu();

	nf_nat_l3proto_clean(l3proto->l3proto);
	nf_ct_l3proto_module_put(l3proto->l3proto);
}
EXPORT_SYMBOL_GPL(nf_nat_l3proto_unregister);

/* No one using conntrack by the time this called. */
static void nf_nat_cleanup_conntrack(struct nf_conn *ct)
{
	struct nf_conn_nat *nat = nf_ct_ext_find(ct, NF_CT_EXT_NAT);

	if (nat == NULL || nat->ct == NULL)
		return;

	NF_CT_ASSERT(nat->ct->status & IPS_SRC_NAT_DONE);

	spin_lock_bh(&nf_nat_lock);
	hlist_del_rcu(&nat->bysource);
	spin_unlock_bh(&nf_nat_lock);
}

static void nf_nat_move_storage(void *new, void *old)
{
	struct nf_conn_nat *new_nat = new;
	struct nf_conn_nat *old_nat = old;
	struct nf_conn *ct = old_nat->ct;

	if (!ct || !(ct->status & IPS_SRC_NAT_DONE))
		return;

	spin_lock_bh(&nf_nat_lock);
	hlist_replace_rcu(&old_nat->bysource, &new_nat->bysource);
	spin_unlock_bh(&nf_nat_lock);
}

static struct nf_ct_ext_type nat_extend __read_mostly = {
	.len		= sizeof(struct nf_conn_nat),
	.align		= __alignof__(struct nf_conn_nat),
	.destroy	= nf_nat_cleanup_conntrack,
	.move		= nf_nat_move_storage,
	.id		= NF_CT_EXT_NAT,
	.flags		= NF_CT_EXT_F_PREALLOC,
};

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

static const struct nla_policy protonat_nla_policy[CTA_PROTONAT_MAX+1] = {
	[CTA_PROTONAT_PORT_MIN]	= { .type = NLA_U16 },
	[CTA_PROTONAT_PORT_MAX]	= { .type = NLA_U16 },
};

static int nfnetlink_parse_nat_proto(struct nlattr *attr,
				     const struct nf_conn *ct,
				     struct nf_nat_range *range)
{
	struct nlattr *tb[CTA_PROTONAT_MAX+1];
	const struct nf_nat_l4proto *l4proto;
	int err;

	err = nla_parse_nested(tb, CTA_PROTONAT_MAX, attr, protonat_nla_policy);
	if (err < 0)
		return err;

	l4proto = __nf_nat_l4proto_find(nf_ct_l3num(ct), nf_ct_protonum(ct));
	if (l4proto->nlattr_to_range)
		err = l4proto->nlattr_to_range(tb, range);

	return err;
}

static const struct nla_policy nat_nla_policy[CTA_NAT_MAX+1] = {
	[CTA_NAT_V4_MINIP]	= { .type = NLA_U32 },
	[CTA_NAT_V4_MAXIP]	= { .type = NLA_U32 },
	[CTA_NAT_V6_MINIP]	= { .len = sizeof(struct in6_addr) },
	[CTA_NAT_V6_MAXIP]	= { .len = sizeof(struct in6_addr) },
	[CTA_NAT_PROTO]		= { .type = NLA_NESTED },
};

static int
nfnetlink_parse_nat(const struct nlattr *nat,
		    const struct nf_conn *ct, struct nf_nat_range *range,
		    const struct nf_nat_l3proto *l3proto)
{
	struct nlattr *tb[CTA_NAT_MAX+1];
	int err;

	memset(range, 0, sizeof(*range));

	err = nla_parse_nested(tb, CTA_NAT_MAX, nat, nat_nla_policy);
	if (err < 0)
		return err;

	err = l3proto->nlattr_to_range(tb, range);
	if (err < 0)
		return err;

	if (!tb[CTA_NAT_PROTO])
		return 0;

	return nfnetlink_parse_nat_proto(tb[CTA_NAT_PROTO], ct, range);
}

/* This function is called under rcu_read_lock() */
static int
nfnetlink_parse_nat_setup(struct nf_conn *ct,
			  enum nf_nat_manip_type manip,
			  const struct nlattr *attr)
{
	struct nf_nat_range range;
	const struct nf_nat_l3proto *l3proto;
	int err;

	/* Should not happen, restricted to creating new conntracks
	 * via ctnetlink.
	 */
	if (WARN_ON_ONCE(nf_nat_initialized(ct, manip)))
		return -EEXIST;

	/* Make sure that L3 NAT is there by when we call nf_nat_setup_info to
	 * attach the null binding, otherwise this may oops.
	 */
	l3proto = __nf_nat_l3proto_find(nf_ct_l3num(ct));
	if (l3proto == NULL)
		return -EAGAIN;

	/* No NAT information has been passed, allocate the null-binding */
	if (attr == NULL)
		return __nf_nat_alloc_null_binding(ct, manip);

	err = nfnetlink_parse_nat(attr, ct, &range, l3proto);
	if (err < 0)
		return err;

	return nf_nat_setup_info(ct, &range, manip);
}
#else
static int
nfnetlink_parse_nat_setup(struct nf_conn *ct,
			  enum nf_nat_manip_type manip,
			  const struct nlattr *attr)
{
	return -EOPNOTSUPP;
}
#endif

static int __net_init nf_nat_net_init(struct net *net)
{
	/* Leave them the same for the moment. */
	net->ct.nat_htable_size = net->ct.htable_size;
	net->ct.nat_bysource = nf_ct_alloc_hashtable(&net->ct.nat_htable_size, 0);
	if (!net->ct.nat_bysource)
		return -ENOMEM;
	return 0;
}

static void __net_exit nf_nat_net_exit(struct net *net)
{
	struct nf_nat_proto_clean clean = {};

	nf_ct_iterate_cleanup(net, nf_nat_proto_clean, &clean, 0, 0);
	synchronize_rcu();
	nf_ct_free_hashtable(net->ct.nat_bysource, net->ct.nat_htable_size);
}

static struct pernet_operations nf_nat_net_ops = {
	.init = nf_nat_net_init,
	.exit = nf_nat_net_exit,
};

static struct nf_ct_helper_expectfn follow_master_nat = {
	.name		= "nat-follow-master",
	.expectfn	= nf_nat_follow_master,
};

static int __init nf_nat_init(void)
{
	int ret;

	ret = nf_ct_extend_register(&nat_extend);
	if (ret < 0) {
		printk(KERN_ERR "nf_nat_core: Unable to register extension\n");
		return ret;
	}

	ret = register_pernet_subsys(&nf_nat_net_ops);
	if (ret < 0)
		goto cleanup_extend;

	nf_ct_helper_expectfn_register(&follow_master_nat);

	/* Initialize fake conntrack so that NAT will skip it */
	nf_ct_untracked_status_or(IPS_NAT_DONE_MASK);

	BUG_ON(nfnetlink_parse_nat_setup_hook != NULL);
	RCU_INIT_POINTER(nfnetlink_parse_nat_setup_hook,
			   nfnetlink_parse_nat_setup);
#ifdef CONFIG_XFRM
	BUG_ON(nf_nat_decode_session_hook != NULL);
	RCU_INIT_POINTER(nf_nat_decode_session_hook, __nf_nat_decode_session);
#endif
	return 0;

 cleanup_extend:
	nf_ct_extend_unregister(&nat_extend);
	return ret;
}

static void __exit nf_nat_cleanup(void)
{
	unsigned int i;

	unregister_pernet_subsys(&nf_nat_net_ops);
	nf_ct_extend_unregister(&nat_extend);
	nf_ct_helper_expectfn_unregister(&follow_master_nat);
	RCU_INIT_POINTER(nfnetlink_parse_nat_setup_hook, NULL);
#ifdef CONFIG_XFRM
	RCU_INIT_POINTER(nf_nat_decode_session_hook, NULL);
#endif
	for (i = 0; i < NFPROTO_NUMPROTO; i++)
		kfree(nf_nat_l4protos[i]);
	synchronize_net();
}

MODULE_LICENSE("GPL");

module_init(nf_nat_init);
module_exit(nf_nat_cleanup);
