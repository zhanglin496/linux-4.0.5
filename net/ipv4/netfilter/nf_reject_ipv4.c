/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/ipv4/nf_reject.h>

const struct tcphdr *nf_reject_ip_tcphdr_get(struct sk_buff *oldskb,
					     struct tcphdr *_oth, int hook)
{
	const struct tcphdr *oth;
	
	//这里检查是否是非第一个分片报文
	//因为除了第一个分片报文包含有tcp首部外
	//其余的分片报文不包含tcp首部
	//而后面reset 需要用到tcp的首部信息
	//这里可以变通使用conntrack的tuple信息来构造报文

	/* IP header checks: fragment. */
	if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
		return NULL;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
				 sizeof(struct tcphdr), _oth);
	if (oth == NULL)
		return NULL;

	/* No RST for RST. */
	if (oth->rst)
		return NULL;

	/* Check checksum */
	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
		return NULL;

	return oth;
}
EXPORT_SYMBOL_GPL(nf_reject_ip_tcphdr_get);

struct iphdr *nf_reject_iphdr_put(struct sk_buff *nskb,
				  const struct sk_buff *oldskb,
				  __be16 protocol, int ttl)
{
	struct iphdr *niph, *oiph = ip_hdr(oldskb);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version	= 4;
	niph->ihl	= sizeof(struct iphdr) / 4;
	niph->tos	= 0;
	niph->id	= 0;
	niph->frag_off	= htons(IP_DF);
	niph->protocol	= protocol;
	niph->check	= 0;
	niph->saddr	= oiph->daddr;
	niph->daddr	= oiph->saddr;
	niph->ttl	= ttl;

	nskb->protocol = htons(ETH_P_IP);

	return niph;
}
EXPORT_SYMBOL_GPL(nf_reject_iphdr_put);

void nf_reject_ip_tcphdr_put(struct sk_buff *nskb, const struct sk_buff *oldskb,
			  const struct tcphdr *oth)
{
	struct iphdr *niph = ip_hdr(nskb);
	struct tcphdr *tcph;

	skb_reset_transport_header(nskb);
	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(*tcph));
	tcph->source	= oth->dest;
	tcph->dest	= oth->source;
	tcph->doff	= sizeof(struct tcphdr) / 4;

	if (oth->ack) {
		tcph->seq = oth->ack_seq;
	} else {
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
				      oldskb->len - ip_hdrlen(oldskb) -
				      (oth->doff << 2));
		tcph->ack = 1;
	}

	tcph->rst	= 1;
	tcph->check = ~tcp_v4_check(sizeof(struct tcphdr), niph->saddr,
				    niph->daddr, 0);
	//要求硬件计算部分校验和
	nskb->ip_summed = CHECKSUM_PARTIAL;
	//指定计算校验和的开始位置偏移
	nskb->csum_start = (unsigned char *)tcph - nskb->head;
	//指定存储校验和的位置偏移
	nskb->csum_offset = offsetof(struct tcphdr, check);
}
EXPORT_SYMBOL_GPL(nf_reject_ip_tcphdr_put);

/* Send RST reply */
void nf_send_reset(struct sk_buff *oldskb, int hook)
{
	struct sk_buff *nskb;
	const struct iphdr *oiph;
	struct iphdr *niph;
	const struct tcphdr *oth;
	struct tcphdr _oth;

	oth = nf_reject_ip_tcphdr_get(oldskb, &_oth, hook);
	if (!oth)
		return;

	if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		return;

	oiph = ip_hdr(oldskb);

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
			 LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb)
		return;

	/* ip_route_me_harder expects skb->dst to be set */
	skb_dst_set_noref(nskb, skb_dst(oldskb));

	skb_reserve(nskb, LL_MAX_HEADER);
	niph = nf_reject_iphdr_put(nskb, oldskb, IPPROTO_TCP,
				   ip4_dst_hoplimit(skb_dst(nskb)));
	nf_reject_ip_tcphdr_put(nskb, oldskb, oth);

	if (ip_route_me_harder(nskb, RTN_UNSPEC))
		goto free_nskb;

	/* "Never happens" */
	if (nskb->len > dst_mtu(skb_dst(nskb)))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	/* If we use ip_local_out for bridged traffic, the MAC source on
	 * the RST will be ours, instead of the destination's.  This confuses
	 * some routers/firewalls, and they drop the packet.  So we need to
	 * build the eth header using the original destination's MAC as the
	 * source, and send the RST packet directly.
	 */
	 //这里的意思是，假设br0 桥接了eth0, eth1, eth2 三个接口
	 //假设收到的数据包的目的地址是eth2
	 //如果直接调用ip_local_out， 那么nskb 的原mac 地址将会是br0 而不是
	 //eth2, 所以这里特殊处理了
	 //原因是nskb->dev此刻是指向br0 的dev实例
	if (oldskb->nf_bridge) {
		//取得原始数据包的以太头
		struct ethhdr *oeth = eth_hdr(oldskb);
		//获取实际的入口设备
		nskb->dev = oldskb->nf_bridge->physindev;
		niph->tot_len = htons(nskb->len);
		ip_send_check(niph);
		//调用入口设备的二层函数构建二层头
		//nskb 二层头的mac地址和oeth 相反，与br0 无关
		if (dev_hard_header(nskb, nskb->dev, ntohs(nskb->protocol),
				    oeth->h_source, oeth->h_dest, nskb->len) < 0)
			goto free_nskb;
		dev_queue_xmit(nskb);
	} else
#endif
		ip_local_out(nskb);

	return;

 free_nskb:
	kfree_skb(nskb);
}
EXPORT_SYMBOL_GPL(nf_send_reset);

MODULE_LICENSE("GPL");
