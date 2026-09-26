/*
 * Copyright (c) 2007-2014 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/openvswitch.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/mpls.h>
#include <net/sctp/checksum.h>

#include "datapath.h"
#include "flow.h"
#include "vport.h"

// 前置声明：动作执行的核心循环。定义在文件后半段，这里先声明以便 sample()、
// recirc 等函数递归调用它。
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      struct sw_flow_key *key,
			      const struct nlattr *attr, int len);

// 延迟动作(deferred action)：一条被推迟执行的动作记录。
// 动机：像 recirc(重新入表)或 sample(采样克隆)这类动作，如果就地递归调用
// do_execute_actions() 去执行，容易造成很深的调用栈甚至无限递归。OVS 的做法
// 是把它们暂存到 per-CPU 的 FIFO 里，等当前这一轮动作全部走完后，在最外层
// (递归层级为 0)再统一取出执行，从而把"深度递归"摊平成"循环处理队列"。
struct deferred_action {
	struct sk_buff *skb;			// 待处理的报文
	const struct nlattr *actions;		// 待执行的动作列表；为 NULL 表示重新入表匹配

	/* Store pkt_key clone when creating deferred action. */
	// 保存创建延迟动作那一刻的流键(flow key)副本，因为原 key 后续可能被改写
	struct sw_flow_key pkt_key;
};

// FIFO 容量上限：一次报文处理最多缓存 10 条延迟动作，超出即丢弃(见 put)。
#define DEFERRED_ACTION_FIFO_SIZE 10
// 延迟动作环形队列(实为一次性使用的线性队列，处理完后重置)。
struct action_fifo {
	int head;				// 入队位置(生产者写)
	int tail;				// 出队位置(消费者读)
	/* Deferred action fifo queue storage. */
	struct deferred_action fifo[DEFERRED_ACTION_FIFO_SIZE];
};

// 每 CPU 一份的延迟动作 FIFO。用 per-CPU 是因为动作执行在软中断上下文、
// 关抢占运行，同一 CPU 上不会并发访问，故无需加锁。
static struct action_fifo __percpu *action_fifos;
// 每 CPU 记录当前动作执行的递归层级。0 表示最外层入口，>0 表示正处在
// 延迟动作再次触发的嵌套执行中，用于判断何时该真正处理延迟队列。
static DEFINE_PER_CPU(int, exec_actions_level);

// 复位 FIFO：把 head/tail 归零，表示队列为空。每处理完一个报文都会复位一次。
static void action_fifo_init(struct action_fifo *fifo)
{
	fifo->head = 0;
	fifo->tail = 0;
}

// 队列是否为空：head==tail 即无未消费元素。
static bool action_fifo_is_empty(const struct action_fifo *fifo)
{
	return (fifo->head == fifo->tail);
}

// 出队：返回 tail 处元素并后移 tail。空队列返回 NULL。
static struct deferred_action *action_fifo_get(struct action_fifo *fifo)
{
	if (action_fifo_is_empty(fifo))
		return NULL;

	return &fifo->fifo[fifo->tail++];
}

// 入队：返回可写入的槽位并后移 head。队列已满(达到容量上限)返回 NULL，
// 调用方据此判断"延迟动作过多"并丢弃该动作。
static struct deferred_action *action_fifo_put(struct action_fifo *fifo)
{
	if (fifo->head >= DEFERRED_ACTION_FIFO_SIZE - 1)
		return NULL;

	return &fifo->fifo[fifo->head++];
}

/* Return true if fifo is not full */
// 追加一条延迟动作：在本 CPU 的 FIFO 中占一个槽位，填入报文、动作列表和流键副本。
// 返回槽位指针，NULL 表示队列已满未能入队。skb 与 key 拷贝确保延迟执行时数据仍有效。
static struct deferred_action *add_deferred_actions(struct sk_buff *skb,
						    const struct sw_flow_key *key,
						    const struct nlattr *attr)
{
	struct action_fifo *fifo;
	struct deferred_action *da;

	fifo = this_cpu_ptr(action_fifos);	// 取本 CPU 的 FIFO
	da = action_fifo_put(fifo);
	if (da) {
		da->skb = skb;
		da->actions = attr;
		da->pkt_key = *key;		// 深拷贝流键，避免后续原 key 被改写影响延迟执行
	}

	return da;
}

// 使流键失效：把以太类型清零。当报文头部被改写(如 push/pop MPLS/VLAN)后，
// 缓存的 flow key 已不再准确，标记失效，后续需要时会重新解析(见 is_flow_key_valid)。
static void invalidate_flow_key(struct sw_flow_key *key)
{
	key->eth.type = htons(0);
}

// 流键是否有效：以太类型非 0 即认为有效。
static bool is_flow_key_valid(const struct sw_flow_key *key)
{
	return !!key->eth.type;
}

// push_mpls：在报文最外层压入一个 MPLS 标签栈条目(LSE)。
// 作用：把 MPLS_HLEN(4 字节)插到以太头之后、原网络层之前，并把以太类型改为
// MPLS。由 do_execute_actions 的 OVS_ACTION_ATTR_PUSH_MPLS 分支调用。
// 返回 0 成功，负值为错误码。
static int push_mpls(struct sk_buff *skb, struct sw_flow_key *key,
		     const struct ovs_action_push_mpls *mpls)
{
	__be32 *new_mpls_lse;
	struct ethhdr *hdr;

	/* Networking stack do not allow simultaneous Tunnel and MPLS GSO. */
	// 协议栈不支持隧道封装与 MPLS 同时做 GSO，遇到已封装报文直接拒绝
	if (skb->encapsulation)
		return -ENOTSUPP;

	// 确保头部有 MPLS_HLEN 的可写空间(必要时复制 skb head)
	if (skb_cow_head(skb, MPLS_HLEN) < 0)
		return -ENOMEM;

	// 数据指针前移 MPLS_HLEN，腾出插入空间
	skb_push(skb, MPLS_HLEN);
	// 把以太头整体向前搬 MPLS_HLEN，使得以太头之后空出 4 字节放 MPLS 标签
	memmove(skb_mac_header(skb) - MPLS_HLEN, skb_mac_header(skb),
		skb->mac_len);
	skb_reset_mac_header(skb);

	// 在以太头之后写入 MPLS 标签栈条目
	new_mpls_lse = (__be32 *)skb_mpls_header(skb);
	*new_mpls_lse = mpls->mpls_lse;

	// 若整包校验和已算好(CHECKSUM_COMPLETE)，把新插入的 4 字节增量加进去，
	// 避免整包重算
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_add(skb->csum, csum_partial(new_mpls_lse,
							     MPLS_HLEN, 0));

	// 以太类型改成 MPLS(单播/多播)，表示后面跟的是 MPLS 而非原来的 IP 等
	hdr = eth_hdr(skb);
	hdr->h_proto = mpls->mpls_ethertype;

	// 记录内层原始协议，供 GSO/隧道等场景还原
	if (!skb->inner_protocol)
		skb_set_inner_protocol(skb, skb->protocol);
	skb->protocol = mpls->mpls_ethertype;

	invalidate_flow_key(key);		// 头部已变，流键失效
	return 0;
}

// pop_mpls：弹出最外层 MPLS 标签，把以太类型恢复为 ethertype 指定的协议。
// 与 push_mpls 相反，删除以太头后的 4 字节 MPLS 条目。
static int pop_mpls(struct sk_buff *skb, struct sw_flow_key *key,
		    const __be16 ethertype)
{
	struct ethhdr *hdr;
	int err;

	// 确保 [以太头 + MPLS] 范围可写
	err = skb_ensure_writable(skb, skb->mac_len + MPLS_HLEN);
	if (unlikely(err))
		return err;

	// 从接收校验和里扣掉即将被删除的 MPLS 4 字节
	skb_postpull_rcsum(skb, skb_mpls_header(skb), MPLS_HLEN);

	// 以太头整体后移 MPLS_HLEN，覆盖掉 MPLS 条目
	memmove(skb_mac_header(skb) + MPLS_HLEN, skb_mac_header(skb),
		skb->mac_len);

	// 数据指针后移，正式丢弃这 4 字节
	__skb_pull(skb, MPLS_HLEN);
	skb_reset_mac_header(skb);

	/* skb_mpls_header() is used to locate the ethertype
	 * field correctly in the presence of VLAN tags.
	 */
	// 借助 skb_mpls_header() 在有 VLAN 标签时也能正确定位以太类型字段并改写
	hdr = (struct ethhdr *)(skb_mpls_header(skb) - ETH_HLEN);
	hdr->h_proto = ethertype;
	if (eth_p_mpls(skb->protocol))
		skb->protocol = ethertype;

	invalidate_flow_key(key);		// 头部已变，流键失效
	return 0;
}

/* 'KEY' must not have any bits set outside of the 'MASK' */
// 带掩码的字段合成宏：MASK 为 1 的位取 KEY 的值，为 0 的位保留 OLD 的原值。
// 前提是 KEY 在 MASK 之外不能有置位(userspace 已保证 KEY = 目标值 & MASK)。
#define MASKED(OLD, KEY, MASK) ((KEY) | ((OLD) & ~(MASK)))
// SET_MASKED：把上面合成结果写回 OLD 变量。
#define SET_MASKED(OLD, KEY, MASK) ((OLD) = MASKED(OLD, KEY, MASK))

// set_mpls：修改最外层 MPLS 标签栈条目(带掩码，可只改部分位，如仅改 TTL/EXP)。
static int set_mpls(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const __be32 *mpls_lse, const __be32 *mask)
{
	__be32 *stack;
	__be32 lse;
	int err;

	err = skb_ensure_writable(skb, skb->mac_len + MPLS_HLEN);
	if (unlikely(err))
		return err;

	// 按掩码合成新的 LSE 值
	stack = (__be32 *)skb_mpls_header(skb);
	lse = MASKED(*stack, *mpls_lse, *mask);
	// CHECKSUM_COMPLETE 时增量更新：用"旧值取反 + 新值"参与校验和修正
	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		__be32 diff[] = { ~(*stack), lse };

		skb->csum = ~csum_partial((char *)diff, sizeof(diff),
					  ~skb->csum);
	}

	*stack = lse;				// 写回报文
	flow_key->mpls.top_lse = lse;		// 同步更新流键
	return 0;
}

// pop_vlan：弹出报文的 802.1Q VLAN 标签。
// skb_vlan_pop 会处理内联标签与 skb 元数据标签两种情形。弹出后如果还残留标签
// (双层 VLAN/QinQ)则整键失效，否则清零流键里的 tci。
static int pop_vlan(struct sk_buff *skb, struct sw_flow_key *key)
{
	int err;

	err = skb_vlan_pop(skb);
	if (skb_vlan_tag_present(skb))
		invalidate_flow_key(key);
	else
		key->eth.tci = 0;
	return err;
}

// push_vlan：压入一个 VLAN 标签(vlan_tpid + vlan_tci)。
// 若已存在标签(将变成 QinQ)则整键失效；否则把新 tci 记入流键。
// 注意传给 skb_vlan_push 的 tci 要去掉 VLAN_TAG_PRESENT 存在位。
static int push_vlan(struct sk_buff *skb, struct sw_flow_key *key,
		     const struct ovs_action_push_vlan *vlan)
{
	if (skb_vlan_tag_present(skb))
		invalidate_flow_key(key);
	else
		key->eth.tci = vlan->vlan_tci;
	return skb_vlan_push(skb, vlan->vlan_tpid,
			     ntohs(vlan->vlan_tci) & ~VLAN_TAG_PRESENT);
}

/* 'src' is already properly masked. */
// 带掩码复制 6 字节 MAC 地址。按 3 个 16 位字处理：掩码位为 1 处取 src，
// 为 0 处保留 dst 原值。src 已经被上层按掩码处理过。
static void ether_addr_copy_masked(u8 *dst_, const u8 *src_, const u8 *mask_)
{
	u16 *dst = (u16 *)dst_;
	const u16 *src = (const u16 *)src_;
	const u16 *mask = (const u16 *)mask_;

	SET_MASKED(dst[0], src[0], mask[0]);
	SET_MASKED(dst[1], src[1], mask[1]);
	SET_MASKED(dst[2], src[2], mask[2]);
}

// set_eth_addr：按掩码改写以太头的源/目的 MAC 地址。
// 由于 MAC 地址参与二层校验(如接收侧 CHECKSUM_COMPLETE)，改写前后需要
// 用 postpull/postpush rcsum 从校验和里扣除旧 12 字节、再加回新 12 字节。
static int set_eth_addr(struct sk_buff *skb, struct sw_flow_key *flow_key,
			const struct ovs_key_ethernet *key,
			const struct ovs_key_ethernet *mask)
{
	int err;

	err = skb_ensure_writable(skb, ETH_HLEN);
	if (unlikely(err))
		return err;

	// 改前：从校验和中扣掉旧的源+目的 MAC(ETH_ALEN*2 = 12 字节)
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);

	// 按掩码写入新的源、目的 MAC
	ether_addr_copy_masked(eth_hdr(skb)->h_source, key->eth_src,
			       mask->eth_src);
	ether_addr_copy_masked(eth_hdr(skb)->h_dest, key->eth_dst,
			       mask->eth_dst);

	// 改后：把新的 12 字节加回校验和
	ovs_skb_postpush_rcsum(skb, eth_hdr(skb), ETH_ALEN * 2);

	// 同步更新流键中的 MAC，保持后续动作/匹配一致
	ether_addr_copy(flow_key->eth.src, eth_hdr(skb)->h_source);
	ether_addr_copy(flow_key->eth.dst, eth_hdr(skb)->h_dest);
	return 0;
}

// set_ip_addr：改写 IPv4 头中的一个地址(源或目的)，并同步修正 L3/L4 校验和。
// 原因：IPv4 地址是 IP 首部校验和以及 TCP/UDP 伪首部校验和的输入，改地址必须
// 增量更新这些校验和，否则报文会被对端丢弃。用增量更新(csum_replace/
// inet_proto_csum_replace4)而非整包重算，代价 O(1)。
static void set_ip_addr(struct sk_buff *skb, struct iphdr *nh,
			__be32 *addr, __be32 new_addr)
{
	int transport_len = skb->len - skb_transport_offset(skb);

	// TCP：伪首部含 IP 地址，需增量修正 TCP 校验和
	if (nh->protocol == IPPROTO_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace4(&tcp_hdr(skb)->check, skb,
						 *addr, new_addr, 1);
	} else if (nh->protocol == IPPROTO_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			// UDP 校验和可选(为 0 表示不校验)。仅当已启用校验或
			// 硬件将补算(CHECKSUM_PARTIAL)时才修正
			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				inet_proto_csum_replace4(&uh->check, skb,
							 *addr, new_addr, 1);
				// 修正后若结果为 0，用 0xFFFF 表示(UDP 中 0 有特殊含义)
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}

	csum_replace4(&nh->check, *addr, new_addr);	// 增量修正 IP 首部校验和
	skb_clear_hash(skb);			// 地址变了，缓存的 skb 哈希失效
	*addr = new_addr;			// 最后写入新地址
}

// update_ipv6_checksum：IPv6 地址改写后修正 L4 校验和。
// IPv6 首部无校验和字段，但 TCP/UDP/ICMPv6 的伪首部都含完整 128 位地址，
// 故改地址必须增量更新对应传输层校验和(inet_proto_csum_replace16)。
static void update_ipv6_checksum(struct sk_buff *skb, u8 l4_proto,
				 __be32 addr[4], const __be32 new_addr[4])
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (l4_proto == NEXTHDR_TCP) {
		if (likely(transport_len >= sizeof(struct tcphdr)))
			inet_proto_csum_replace16(&tcp_hdr(skb)->check, skb,
						  addr, new_addr, 1);
	} else if (l4_proto == NEXTHDR_UDP) {
		if (likely(transport_len >= sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			// IPv6 下 UDP 校验和强制存在，逻辑同 IPv4
			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				inet_proto_csum_replace16(&uh->check, skb,
							  addr, new_addr, 1);
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	} else if (l4_proto == NEXTHDR_ICMP) {
		// ICMPv6 校验和也含伪首部地址，同样需要修正
		if (likely(transport_len >= sizeof(struct icmp6hdr)))
			inet_proto_csum_replace16(&icmp6_hdr(skb)->icmp6_cksum,
						  skb, addr, new_addr, 1);
	}
}

// 按掩码合成 128 位 IPv6 地址(逐 32 位)：掩码位为 1 取 addr，为 0 保留 old。
static void mask_ipv6_addr(const __be32 old[4], const __be32 addr[4],
			   const __be32 mask[4], __be32 masked[4])
{
	masked[0] = MASKED(old[0], addr[0], mask[0]);
	masked[1] = MASKED(old[1], addr[1], mask[1]);
	masked[2] = MASKED(old[2], addr[2], mask[2]);
	masked[3] = MASKED(old[3], addr[3], mask[3]);
}

// set_ipv6_addr：写入新的 IPv6 地址。recalculate_csum 控制是否修正 L4 校验和
// (某些含 Routing 扩展头的情形，目的地址是路由段终点、此刻不算校验和)。
static void set_ipv6_addr(struct sk_buff *skb, u8 l4_proto,
			  __be32 addr[4], const __be32 new_addr[4],
			  bool recalculate_csum)
{
	if (recalculate_csum)
		update_ipv6_checksum(skb, l4_proto, addr, new_addr);

	skb_clear_hash(skb);			// 地址变，哈希失效
	memcpy(addr, new_addr, sizeof(__be32[4]));	// 写入 16 字节新地址
}

// set_ipv6_fl：按掩码设置 IPv6 20 位流标签(flow label)。
static void set_ipv6_fl(struct ipv6hdr *nh, u32 fl, u32 mask)
{
	/* Bits 21-24 are always unmasked, so this retains their values. */
	// flow_lbl[0] 高 4 位属于 traffic class，掩码高位为 0 从而保留不动
	SET_MASKED(nh->flow_lbl[0], (u8)(fl >> 16), (u8)(mask >> 16));
	SET_MASKED(nh->flow_lbl[1], (u8)(fl >> 8), (u8)(mask >> 8));
	SET_MASKED(nh->flow_lbl[2], (u8)fl, (u8)mask);
}

// set_ip_ttl：按掩码改写 IPv4 TTL，并增量修正 IP 首部校验和。
// TTL 与上一字节 protocol 共处同一 16 位字，故用 csum_replace2 以 (ttl<<8)
// 的形式做 16 位增量修正。
static void set_ip_ttl(struct sk_buff *skb, struct iphdr *nh, u8 new_ttl,
		       u8 mask)
{
	new_ttl = MASKED(nh->ttl, new_ttl, mask);

	csum_replace2(&nh->check, htons(nh->ttl << 8), htons(new_ttl << 8));
	nh->ttl = new_ttl;
}

// set_ipv4：执行 OVS_KEY_ATTR_IPV4 设置动作，按掩码改写 IPv4 头的
// 源/目的地址、TOS(DSCP+ECN)、TTL，并逐项同步流键与校验和。
static int set_ipv4(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const struct ovs_key_ipv4 *key,
		    const struct ovs_key_ipv4 *mask)
{
	struct iphdr *nh;
	__be32 new_addr;
	int err;

	// 确保 IPv4 首部范围可写
	err = skb_ensure_writable(skb, skb_network_offset(skb) +
				  sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	nh = ip_hdr(skb);

	/* Setting an IP addresses is typically only a side effect of
	 * matching on them in the current userspace implementation, so it
	 * makes sense to check if the value actually changed.
	 */
	// userspace 里"设置地址"常只是匹配的副作用，值往往没真的变，故先比较，
	// 只有确实变化才改写并修正校验和，省去无谓开销
	if (mask->ipv4_src) {
		new_addr = MASKED(nh->saddr, key->ipv4_src, mask->ipv4_src);

		if (unlikely(new_addr != nh->saddr)) {
			set_ip_addr(skb, nh, &nh->saddr, new_addr);
			flow_key->ipv4.addr.src = new_addr;
		}
	}
	if (mask->ipv4_dst) {
		new_addr = MASKED(nh->daddr, key->ipv4_dst, mask->ipv4_dst);

		if (unlikely(new_addr != nh->daddr)) {
			set_ip_addr(skb, nh, &nh->daddr, new_addr);
			flow_key->ipv4.addr.dst = new_addr;
		}
	}
	if (mask->ipv4_tos) {
		// 改 DS 字段(TOS)，ipv4_change_dsfield 内部会修正 IP 校验和
		ipv4_change_dsfield(nh, ~mask->ipv4_tos, key->ipv4_tos);
		flow_key->ip.tos = nh->tos;
	}
	if (mask->ipv4_ttl) {
		set_ip_ttl(skb, nh, key->ipv4_ttl, mask->ipv4_ttl);
		flow_key->ip.ttl = nh->ttl;
	}

	return 0;
}

// IPv6 掩码是否非零(四段任一非零)：用于判断该字段是否需要设置。
static bool is_ipv6_mask_nonzero(const __be32 addr[4])
{
	return !!(addr[0] | addr[1] | addr[2] | addr[3]);
}

// set_ipv6：执行 OVS_KEY_ATTR_IPV6 设置动作，按掩码改写 IPv6 头的
// 源/目的地址、traffic class、flow label、hop limit，并同步流键与 L4 校验和。
static int set_ipv6(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const struct ovs_key_ipv6 *key,
		    const struct ovs_key_ipv6 *mask)
{
	struct ipv6hdr *nh;
	int err;

	err = skb_ensure_writable(skb, skb_network_offset(skb) +
				  sizeof(struct ipv6hdr));
	if (unlikely(err))
		return err;

	nh = ipv6_hdr(skb);

	/* Setting an IP addresses is typically only a side effect of
	 * matching on them in the current userspace implementation, so it
	 * makes sense to check if the value actually changed.
	 */
	// 同 set_ipv4：仅在地址确实变化时才改写并更新校验和
	if (is_ipv6_mask_nonzero(mask->ipv6_src)) {
		__be32 *saddr = (__be32 *)&nh->saddr;
		__be32 masked[4];

		mask_ipv6_addr(saddr, key->ipv6_src, mask->ipv6_src, masked);

		if (unlikely(memcmp(saddr, masked, sizeof(masked)))) {
			set_ipv6_addr(skb, key->ipv6_proto, saddr, masked,
				      true);
			memcpy(&flow_key->ipv6.addr.src, masked,
			       sizeof(flow_key->ipv6.addr.src));
		}
	}
	if (is_ipv6_mask_nonzero(mask->ipv6_dst)) {
		unsigned int offset = 0;
		int flags = IP6_FH_F_SKIP_RH;
		bool recalc_csum = true;
		__be32 *daddr = (__be32 *)&nh->daddr;
		__be32 masked[4];

		mask_ipv6_addr(daddr, key->ipv6_dst, mask->ipv6_dst, masked);

		if (unlikely(memcmp(daddr, masked, sizeof(masked)))) {
			// 存在 Routing 扩展头时，当前目的地址只是中间跳，L4
			// 校验和是按最终目的算的，此时不应重算(recalc_csum=false)
			if (ipv6_ext_hdr(nh->nexthdr))
				recalc_csum = (ipv6_find_hdr(skb, &offset,
							     NEXTHDR_ROUTING,
							     NULL, &flags)
					       != NEXTHDR_ROUTING);

			set_ipv6_addr(skb, key->ipv6_proto, daddr, masked,
				      recalc_csum);
			memcpy(&flow_key->ipv6.addr.dst, masked,
			       sizeof(flow_key->ipv6.addr.dst));
		}
	}
	if (mask->ipv6_tclass) {
		// traffic class(相当于 IPv4 的 TOS)，IPv6 无首部校验和无需修正
		ipv6_change_dsfield(nh, ~mask->ipv6_tclass, key->ipv6_tclass);
		flow_key->ip.tos = ipv6_get_dsfield(nh);
	}
	if (mask->ipv6_label) {
		set_ipv6_fl(nh, ntohl(key->ipv6_label),
			    ntohl(mask->ipv6_label));
		flow_key->ipv6.label =
		    *(__be32 *)nh & htonl(IPV6_FLOWINFO_FLOWLABEL);
	}
	if (mask->ipv6_hlimit) {
		// hop limit(相当于 IPv4 的 TTL)
		SET_MASKED(nh->hop_limit, key->ipv6_hlimit, mask->ipv6_hlimit);
		flow_key->ip.ttl = nh->hop_limit;
	}
	return 0;
}

/* Must follow skb_ensure_writable() since that can move the skb data. */
// set_tp_port：改写传输层端口(16 位)并增量修正该协议的校验和(check)。
// 必须在 skb_ensure_writable() 之后调用，因为后者可能搬动 skb 数据、使指针失效。
static void set_tp_port(struct sk_buff *skb, __be16 *port,
			__be16 new_port, __sum16 *check)
{
	inet_proto_csum_replace2(check, skb, *port, new_port, 0);
	*port = new_port;
}

// set_udp：按掩码改写 UDP 源/目的端口，并处理 UDP 校验和。
static int set_udp(struct sk_buff *skb, struct sw_flow_key *flow_key,
		   const struct ovs_key_udp *key,
		   const struct ovs_key_udp *mask)
{
	struct udphdr *uh;
	__be16 src, dst;
	int err;

	err = skb_ensure_writable(skb, skb_transport_offset(skb) +
				  sizeof(struct udphdr));
	if (unlikely(err))
		return err;

	uh = udp_hdr(skb);
	/* Either of the masks is non-zero, so do not bother checking them. */
	// 至少有一个掩码非零(否则不会走到这)，直接按掩码合成新端口
	src = MASKED(uh->source, key->udp_src, mask->udp_src);
	dst = MASKED(uh->dest, key->udp_dst, mask->udp_dst);

	// UDP 校验和已启用且非硬件补算：改端口需增量修正校验和
	if (uh->check && skb->ip_summed != CHECKSUM_PARTIAL) {
		if (likely(src != uh->source)) {
			set_tp_port(skb, &uh->source, src, &uh->check);
			flow_key->tp.src = src;
		}
		if (likely(dst != uh->dest)) {
			set_tp_port(skb, &uh->dest, dst, &uh->check);
			flow_key->tp.dst = dst;
		}

		// 结果为 0 用 0xFFFF 表示(UDP 中 0 表示未计算校验和)
		if (unlikely(!uh->check))
			uh->check = CSUM_MANGLED_0;
	} else {
		// 无校验和(check==0)或硬件补算：直接写端口即可
		uh->source = src;
		uh->dest = dst;
		flow_key->tp.src = src;
		flow_key->tp.dst = dst;
	}

	skb_clear_hash(skb);			// 端口变，哈希失效

	return 0;
}

// set_tcp：按掩码改写 TCP 源/目的端口。TCP 校验和强制存在，逐个端口增量修正。
static int set_tcp(struct sk_buff *skb, struct sw_flow_key *flow_key,
		   const struct ovs_key_tcp *key,
		   const struct ovs_key_tcp *mask)
{
	struct tcphdr *th;
	__be16 src, dst;
	int err;

	err = skb_ensure_writable(skb, skb_transport_offset(skb) +
				  sizeof(struct tcphdr));
	if (unlikely(err))
		return err;

	th = tcp_hdr(skb);
	src = MASKED(th->source, key->tcp_src, mask->tcp_src);
	if (likely(src != th->source)) {
		set_tp_port(skb, &th->source, src, &th->check);
		flow_key->tp.src = src;
	}
	dst = MASKED(th->dest, key->tcp_dst, mask->tcp_dst);
	if (likely(dst != th->dest)) {
		set_tp_port(skb, &th->dest, dst, &th->check);
		flow_key->tp.dst = dst;
	}
	skb_clear_hash(skb);

	return 0;
}

// set_sctp：按掩码改写 SCTP 源/目的端口。
// SCTP 用的是 CRC32c 校验(位于整个 SCTP 报文之上)，无法像 TCP/UDP 那样做
// 16 位增量修正，故这里的做法是：先记录旧值和"重算的正确旧值"，改完端口后
// 再重算一次，用 old ^ old_correct ^ new 的方式把原本可能存在的校验错误
// 一并透传出去(而不是无脑修正成正确值)。
static int set_sctp(struct sk_buff *skb, struct sw_flow_key *flow_key,
		    const struct ovs_key_sctp *key,
		    const struct ovs_key_sctp *mask)
{
	unsigned int sctphoff = skb_transport_offset(skb);
	struct sctphdr *sh;
	__le32 old_correct_csum, new_csum, old_csum;
	int err;

	err = skb_ensure_writable(skb, sctphoff + sizeof(struct sctphdr));
	if (unlikely(err))
		return err;

	sh = sctp_hdr(skb);
	old_csum = sh->checksum;			// 报文中携带的旧校验和
	old_correct_csum = sctp_compute_cksum(skb, sctphoff);	// 改前重算的正确值

	sh->source = MASKED(sh->source, key->sctp_src, mask->sctp_src);
	sh->dest = MASKED(sh->dest, key->sctp_dst, mask->sctp_dst);

	new_csum = sctp_compute_cksum(skb, sctphoff);	// 改后重算的正确值

	/* Carry any checksum errors through. */
	// 透传原有校验错误：若原报文校验本就错误，改端口后仍保持"错误"状态，
	// 不替 sender 修正
	sh->checksum = old_csum ^ old_correct_csum ^ new_csum;

	skb_clear_hash(skb);
	flow_key->tp.src = sh->source;
	flow_key->tp.dst = sh->dest;

	return 0;
}

// do_output：把报文从 out_port 指定的 vport 发出。
// 找不到该 vport 则释放 skb。注意本函数会消费(发送或释放)传入的 skb，
// 因此调用方在需要保留原 skb 时必须先克隆。
static void do_output(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct vport *vport = ovs_vport_rcu(dp, out_port);

	if (likely(vport))
		ovs_vport_send(vport, skb);
	else
		kfree_skb(skb);
}

// output_userspace：把报文上送(upcall)给用户态控制面(如 ovs-vswitchd)。
// 作用：解析 OVS_USERSPACE_ATTR_* 属性，组装 upcall 元数据(用户数据、目标
// netlink portid、出口隧道信息)，再调 ovs_dp_upcall 走 netlink 发给用户态。
// 典型用于流表 miss 或显式 userspace/sample 动作。
static int output_userspace(struct datapath *dp, struct sk_buff *skb,
			    struct sw_flow_key *key, const struct nlattr *attr)
{
	struct ovs_tunnel_info info;
	struct dp_upcall_info upcall;
	const struct nlattr *a;
	int rem;

	upcall.cmd = OVS_PACKET_CMD_ACTION;
	upcall.userdata = NULL;
	upcall.portid = 0;
	upcall.egress_tun_info = NULL;

	// 遍历嵌套属性，逐项填充 upcall 元数据
	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_USERSPACE_ATTR_USERDATA:
			// 随包上送的私有数据(用户态用来区分动作来源)
			upcall.userdata = a;
			break;

		case OVS_USERSPACE_ATTR_PID:
			// 接收本 upcall 的用户态 netlink 端口号
			upcall.portid = nla_get_u32(a);
			break;

		case OVS_USERSPACE_ATTR_EGRESS_TUN_PORT: {
			/* Get out tunnel info. */
			// 附带出口隧道信息：查出对应 vport 并取其 egress 隧道元数据
			struct vport *vport;

			vport = ovs_vport_rcu(dp, nla_get_u32(a));
			if (vport) {
				int err;

				err = ovs_vport_get_egress_tun_info(vport, skb,
								    &info);
				if (!err)
					upcall.egress_tun_info = &info;
			}
			break;
		}

		} /* End of switch. */
	}

	return ovs_dp_upcall(dp, skb, key, &upcall);
}

// sample：按概率执行一组嵌套动作，主要用于采样上送(sFlow 等)。
// 解析 PROBABILITY(命中概率)与 ACTIONS(嵌套动作列表)。用随机数决定是否执行，
// 未命中则直接返回。命中后：若嵌套只是单个 userspace 动作则特判为直接上送；
// 否则克隆 skb 并把动作丢进延迟队列，避免在此处深度递归执行。
static int sample(struct datapath *dp, struct sk_buff *skb,
		  struct sw_flow_key *key, const struct nlattr *attr)
{
	const struct nlattr *acts_list = NULL;
	const struct nlattr *a;
	int rem;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			// 概率判定：随机数 >= 阈值则不采样，直接返回
			if (prandom_u32() >= nla_get_u32(a))
				return 0;
			break;

		case OVS_SAMPLE_ATTR_ACTIONS:
			acts_list = a;		// 记录待执行的嵌套动作列表
			break;
		}
	}

	rem = nla_len(acts_list);
	a = nla_data(acts_list);

	/* Actions list is empty, do nothing */
	// 动作列表为空，什么都不做
	if (unlikely(!rem))
		return 0;

	/* The only known usage of sample action is having a single user-space
	 * action. Treat this usage as a special case.
	 * The output_userspace() should clone the skb to be sent to the
	 * user space. This skb will be consumed by its caller.
	 */
	// 特例优化：sample 已知唯一用法就是"单个 userspace 动作"。此时直接上送，
	// 不必克隆 skb 或走延迟队列(skb 由外层调用链负责消费)
	if (likely(nla_type(a) == OVS_ACTION_ATTR_USERSPACE &&
		   nla_is_last(a, rem)))
		return output_userspace(dp, skb, key, a);

	// 一般情形：克隆一份 skb 供采样动作使用，原 skb 继续走主动作流程
	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		/* Skip the sample action when out of memory. */
		return 0;

	// 把克隆包与嵌套动作加入延迟队列，稍后在最外层统一执行(防止深递归)
	if (!add_deferred_actions(skb, key, a)) {
		if (net_ratelimit())
			pr_warn("%s: deferred actions limit reached, dropping sample action\n",
				ovs_dp_name(dp));

		kfree_skb(skb);			// 队列满则丢弃克隆包
	}
	return 0;
}

// execute_hash：计算并设置 skb 的 OVS 流哈希，供 recirc 后的多路径/负载分担使用。
// 取 skb 的四层哈希，再用 hash_basis 做 jhash 扰动；结果为 0 时强置为 1
// (0 被用作"未设置"的标记)。结果写入 key->ovs_flow_hash。
static void execute_hash(struct sk_buff *skb, struct sw_flow_key *key,
			 const struct nlattr *attr)
{
	struct ovs_action_hash *hash_act = nla_data(attr);
	u32 hash = 0;

	/* OVS_HASH_ALG_L4 is the only possible hash algorithm.  */
	// 目前只支持基于 L4 的哈希算法
	hash = skb_get_hash(skb);
	hash = jhash_1word(hash, hash_act->hash_basis);
	if (!hash)
		hash = 0x1;

	key->ovs_flow_hash = hash;
}

// execute_set_action：执行不带掩码的 OVS_ACTION_ATTR_SET。
// 当前只支持设置隧道(TUNNEL_INFO)——把隧道元数据挂到 OVS_CB(skb) 上，供后续
// 隧道 vport 封装使用。其余类型一律通过 execute_masked_set_action 走带掩码路径。
static int execute_set_action(struct sk_buff *skb,
			      struct sw_flow_key *flow_key,
			      const struct nlattr *a)
{
	/* Only tunnel set execution is supported without a mask. */
	if (nla_type(a) == OVS_KEY_ATTR_TUNNEL_INFO) {
		OVS_CB(skb)->egress_tun_info = nla_data(a);
		return 0;
	}

	return -EINVAL;
}

/* Mask is at the midpoint of the data. */
// 取掩码指针：带掩码的 SET 动作里，数据布局是[值][掩码]两份紧邻，掩码正好
// 位于数据中点，即在"值"结构体之后一个单位处。
#define get_mask(a, type) ((const type)nla_data(a) + 1)

// execute_masked_set_action：执行带掩码的字段设置(OVS_ACTION_ATTR_SET_MASKED)。
// 相比不带掩码的 SET，掩码允许只改字段中的部分位(如只改 DSCP 而不动 ECN)。
// 按 key 类型分派到 skb->priority/mark 或各协议头的 set_* 修改函数。
static int execute_masked_set_action(struct sk_buff *skb,
				     struct sw_flow_key *flow_key,
				     const struct nlattr *a)
{
	int err = 0;

	switch (nla_type(a)) {
	case OVS_KEY_ATTR_PRIORITY:
		// skb 的 QoS 优先级(元数据，非报文内容)
		SET_MASKED(skb->priority, nla_get_u32(a), *get_mask(a, u32 *));
		flow_key->phy.priority = skb->priority;
		break;

	case OVS_KEY_ATTR_SKB_MARK:
		// skb 的 mark 标记(供路由/iptables 等使用)
		SET_MASKED(skb->mark, nla_get_u32(a), *get_mask(a, u32 *));
		flow_key->phy.skb_mark = skb->mark;
		break;

	case OVS_KEY_ATTR_TUNNEL_INFO:
		/* Masked data not supported for tunnel. */
		// 隧道信息不支持带掩码设置
		err = -EINVAL;
		break;

	case OVS_KEY_ATTR_ETHERNET:
		err = set_eth_addr(skb, flow_key, nla_data(a),
				   get_mask(a, struct ovs_key_ethernet *));
		break;

	case OVS_KEY_ATTR_IPV4:
		err = set_ipv4(skb, flow_key, nla_data(a),
			       get_mask(a, struct ovs_key_ipv4 *));
		break;

	case OVS_KEY_ATTR_IPV6:
		err = set_ipv6(skb, flow_key, nla_data(a),
			       get_mask(a, struct ovs_key_ipv6 *));
		break;

	case OVS_KEY_ATTR_TCP:
		err = set_tcp(skb, flow_key, nla_data(a),
			      get_mask(a, struct ovs_key_tcp *));
		break;

	case OVS_KEY_ATTR_UDP:
		err = set_udp(skb, flow_key, nla_data(a),
			      get_mask(a, struct ovs_key_udp *));
		break;

	case OVS_KEY_ATTR_SCTP:
		err = set_sctp(skb, flow_key, nla_data(a),
			       get_mask(a, struct ovs_key_sctp *));
		break;

	case OVS_KEY_ATTR_MPLS:
		err = set_mpls(skb, flow_key, nla_data(a), get_mask(a,
								    __be32 *));
		break;
	}

	return err;
}

// execute_recirc：执行"重新入表"(recirculation)动作，用于多级流水线处理。
// 作用：给报文打上 recirc_id，然后把它作为延迟动作(actions=NULL 表示重新走
// ovs_dp_process_packet 匹配流表)放入 FIFO，等本轮动作结束后再送回流表。
// 用延迟队列而非就地递归，是为避免多级 recirc 造成过深/无限的调用栈递归。
static int execute_recirc(struct datapath *dp, struct sk_buff *skb,
			  struct sw_flow_key *key,
			  const struct nlattr *a, int rem)
{
	struct deferred_action *da;

	// recirc 需要有效的流键；若之前被 push/pop 等操作置为失效，先重新解析
	if (!is_flow_key_valid(key)) {
		int err;

		err = ovs_flow_key_update(skb, key);
		if (err)
			return err;
	}
	BUG_ON(!is_flow_key_valid(key));

	if (!nla_is_last(a, rem)) {
		/* Recirc action is the not the last action
		 * of the action list, need to clone the skb.
		 */
		// recirc 不是最后一个动作：后面还有动作要在原 skb 上执行，
		// 故克隆一份给 recirc 用
		skb = skb_clone(skb, GFP_ATOMIC);

		/* Skip the recirc action when out of memory, but
		 * continue on with the rest of the action list.
		 */
		// 内存不足则跳过 recirc，但主动作列表继续执行
		if (!skb)
			return 0;
	}

	// 入延迟队列(actions=NULL 意味着重新入表匹配)，并写入 recirc_id
	da = add_deferred_actions(skb, key, NULL);
	if (da) {
		da->pkt_key.recirc_id = nla_get_u32(a);
	} else {
		kfree_skb(skb);			// 队列满则丢弃

		if (net_ratelimit())
			pr_warn("%s: deferred action limit reached, drop recirc action\n",
				ovs_dp_name(dp));
	}

	return 0;
}

/* Execute a list of actions against 'skb'. */
// do_execute_actions：动作执行的核心循环。对一个 skb 依次执行 netlink 编码的
// 动作列表(attr 起、共 len 字节)。这是把"匹配到流表项"转化为"实际报文处理"
// 的引擎。被 ovs_execute_actions(对外入口)和延迟动作处理递归调用。
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      struct sw_flow_key *key,
			      const struct nlattr *attr, int len)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that.
	 */
	// 每个 output 动作都需要一份独立的 skb 克隆，但绝大多数流只有单个 output。
	// 为避免"先克隆再释放原包"的浪费，这里用 prev_port 把 output 延后一步：
	// 遇到 output 先记下端口，等看到下一个动作时才真正克隆并发送前一个;
	// 若 output 是最后一个动作(循环结束时),就直接把原 skb 发出，无需克隆。
	int prev_port = -1;
	const struct nlattr *a;
	int rem;

	for (a = attr, rem = len; rem > 0;
	     a = nla_next(a, &rem)) {
		int err = 0;

		// 处理上一轮挂起的 output：克隆一份发出去，原 skb 留给后续动作
		if (unlikely(prev_port != -1)) {
			struct sk_buff *out_skb = skb_clone(skb, GFP_ATOMIC);

			if (out_skb)
				do_output(dp, out_skb, prev_port);

			prev_port = -1;
		}

		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			// 从端口发出：先暂存端口，延后到下一轮或循环末尾再发(见上)
			prev_port = nla_get_u32(a);
			break;

		case OVS_ACTION_ATTR_USERSPACE:
			// 上送用户态
			output_userspace(dp, skb, key, a);
			break;

		case OVS_ACTION_ATTR_HASH:
			// 计算并设置 skb 哈希(供 recirc 用)
			execute_hash(skb, key, a);
			break;

		case OVS_ACTION_ATTR_PUSH_MPLS:
			err = push_mpls(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_POP_MPLS:
			err = pop_mpls(skb, key, nla_get_be16(a));
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			err = push_vlan(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_POP_VLAN:
			err = pop_vlan(skb, key);
			break;

		case OVS_ACTION_ATTR_RECIRC:
			// 重新入表(多级流水线)，通过延迟队列实现
			err = execute_recirc(dp, skb, key, a, rem);
			if (nla_is_last(a, rem)) {
				/* If this is the last action, the skb has
				 * been consumed or freed.
				 * Return immediately.
				 */
				// recirc 是最后一个动作时,skb 已被 execute_recirc
				// 消费(入队或释放),不能再碰,直接返回
				return err;
			}
			break;

		case OVS_ACTION_ATTR_SET:
			// 设置字段(不带掩码,当前仅隧道)
			err = execute_set_action(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SET_MASKED:
		case OVS_ACTION_ATTR_SET_TO_MASKED:
			// 带掩码设置字段(可只改部分位)
			err = execute_masked_set_action(skb, key, nla_data(a));
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			// 按概率采样执行嵌套动作
			err = sample(dp, skb, key, a);
			break;
		}

		// 任一动作出错:释放 skb 并中止本动作列表
		if (unlikely(err)) {
			kfree_skb(skb);
			return err;
		}
	}

	// 循环结束:若还有挂起的 output,此时是最后动作,直接发原 skb(免克隆);
	// 否则没有出口,消费掉 skb
	if (prev_port != -1)
		do_output(dp, skb, prev_port);
	else
		consume_skb(skb);

	return 0;
}

// process_deferred_actions：在最外层统一处理本 CPU 延迟队列里累积的动作。
// 循环出队执行,直到队列清空:actions 非 NULL 则执行其动作列表(如 sample 的
// 嵌套动作),为 NULL 则重新送回流表匹配(recirc)。这是"把深递归摊平成循环"
// 设计的落地点。注意执行过程中可能再产生新的延迟动作,故用 while 直到空。
static void process_deferred_actions(struct datapath *dp)
{
	struct action_fifo *fifo = this_cpu_ptr(action_fifos);

	/* Do not touch the FIFO in case there is no deferred actions. */
	// 队列为空则直接返回,常见快路径
	if (action_fifo_is_empty(fifo))
		return;

	/* Finishing executing all deferred actions. */
	do {
		struct deferred_action *da = action_fifo_get(fifo);
		struct sk_buff *skb = da->skb;
		struct sw_flow_key *key = &da->pkt_key;
		const struct nlattr *actions = da->actions;

		if (actions)
			// 有动作列表:执行它(sample 的嵌套动作)
			do_execute_actions(dp, skb, key, actions,
					   nla_len(actions));
		else
			// 无动作列表:重新走流表匹配(recirc)
			ovs_dp_process_packet(skb, key);
	} while (!action_fifo_is_empty(fifo));

	/* Reset FIFO for the next packet.  */
	// 处理完复位队列,供下一个报文使用
	action_fifo_init(fifo);
}

/* Execute a list of actions against 'skb'. */
// ovs_execute_actions：动作执行的对外总入口(datapath 匹配到流后调用)。
// 作用:维护 per-CPU 递归层级;执行主动作列表;仅在最外层(level==0)才处理
// 延迟动作队列,从而保证嵌套/recirc 产生的延迟动作被批量、非递归地处理完。
int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct sw_flow_actions *acts,
			struct sw_flow_key *key)
{
	// 读取进入前的递归层级:0 说明这是最外层调用
	int level = this_cpu_read(exec_actions_level);
	int err;

	this_cpu_inc(exec_actions_level);	// 进入,层级 +1
	OVS_CB(skb)->egress_tun_info = NULL;	// 清空隧道出口信息
	err = do_execute_actions(dp, skb, key,
				 acts->actions, acts->actions_len);

	// 只有最外层负责清空延迟队列;嵌套调用只入队不处理,避免深递归
	if (!level)
		process_deferred_actions(dp);

	this_cpu_dec(exec_actions_level);	// 退出,层级 -1
	return err;
}

// action_fifos_init：模块初始化时分配 per-CPU 延迟动作 FIFO。返回 0 成功。
int action_fifos_init(void)
{
	action_fifos = alloc_percpu(struct action_fifo);
	if (!action_fifos)
		return -ENOMEM;

	return 0;
}

// action_fifos_exit：模块卸载时释放 per-CPU FIFO。
void action_fifos_exit(void)
{
	free_percpu(action_fifos);
}
