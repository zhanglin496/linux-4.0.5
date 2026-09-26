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

#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/llc_pdu.h>
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/llc.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/rcupdate.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/mpls.h>
#include <linux/sctp.h>
#include <linux/smp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/rculist.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/ipv6.h>
#include <net/mpls.h>
#include <net/ndisc.h>

#include "datapath.h"
#include "flow.h"
#include "flow_netlink.h"

// 把以 jiffies 表示的“最后使用时刻”换算为绝对的毫秒时间戳。
// 入参 flow_jiffies 是某流上次被命中时记录的 jiffies；
// 做法：取当前墙钟时间(cur_ms)，减去从 flow_jiffies 到现在的空闲毫秒数(idle_ms)，
// 即可还原出该流上次被使用时的绝对毫秒时间。返回值供上报给用户态使用。
u64 ovs_flow_used_time(unsigned long flow_jiffies)
{
	struct timespec cur_ts;
	u64 cur_ms, idle_ms;

	// 取当前时间
	ktime_get_ts(&cur_ts);
	// 距上次使用已过去多少毫秒（用 jiffies 差换算）
	idle_ms = jiffies_to_msecs(jiffies - flow_jiffies);
	// 当前时间换算成毫秒
	cur_ms = (u64)cur_ts.tv_sec * MSEC_PER_SEC +
		 cur_ts.tv_nsec / NSEC_PER_MSEC;

	// 当前时间 - 空闲时长 = 上次使用的绝对时间
	return cur_ms - idle_ms;
}

// 取 TCP 头中的标志位（低 12 位），转为 be16。0x0FFF 屏蔽掉数据偏移/保留位。
#define TCP_FLAGS_BE16(tp) (*(__be16 *)&tcp_flag_word(tp) & htons(0x0FFF))

// 报文命中流表项时更新统计（包数、字节数、最后使用时间、TCP 标志）。
// 核心是 per-NUMA-node 的统计设计：为减少多核跨 NUMA 节点写同一 cache line
// 造成的竞争，每个节点尽量更新“自己节点”的 flow_stats。
//   - stats[0] 在建流时预分配，作为兜底；
//   - 其他节点的 stats 在该节点首次命中时按需分配；
//   - stats_last_writer 记录上一次写 stats[0] 的节点，用来判断当前节点
//     是否应该为自己单独分配统计，从而把不同节点的写分散到各自的内存上。
void ovs_flow_stats_update(struct sw_flow *flow, __be16 tcp_flags,
			   const struct sk_buff *skb)
{
	struct flow_stats *stats;
	// 当前 CPU 所在的 NUMA 节点
	int node = numa_node_id();
	// 统计字节数时把被硬件剥离的 VLAN 头长度补回来
	int len = skb->len + (skb_vlan_tag_present(skb) ? VLAN_HLEN : 0);

	// 优先取本节点专属统计
	stats = rcu_dereference(flow->stats[node]);

	/* Check if already have node-specific stats. */
	// 本节点已有专属统计：直接加锁更新
	if (likely(stats)) {
		spin_lock(&stats->lock);
		/* Mark if we write on the pre-allocated stats. */
		// 若正在写的是节点 0 的预分配统计，记录写者为节点 0
		if (node == 0 && unlikely(flow->stats_last_writer != node))
			flow->stats_last_writer = node;
	} else {
		// 本节点尚无专属统计，回退到预分配的 stats[0]
		stats = rcu_dereference(flow->stats[0]); /* Pre-allocated. */
		spin_lock(&stats->lock);

		/* If the current NUMA-node is the only writer on the
		 * pre-allocated stats keep using them.
		 */
		// 若本节点不是上次写 stats[0] 的节点，说明有多个节点在写同一份
		// 预分配统计，产生跨节点竞争，考虑为本节点单独分配统计。
		if (unlikely(flow->stats_last_writer != node)) {
			/* A previous locker may have already allocated the
			 * stats, so we need to check again.  If node-specific
			 * stats were already allocated, we update the pre-
			 * allocated stats as we have already locked them.
			 */
			// stats_last_writer==NUMA_NO_NODE 表示还从未有人写过，
			// 此时无需分配；同时再次确认本节点确实还没有专属统计
			//（可能有其他持锁者刚分配完），避免重复分配。
			if (likely(flow->stats_last_writer != NUMA_NO_NODE)
			    && likely(!rcu_access_pointer(flow->stats[node]))) {
				/* Try to allocate node-specific stats. */
				struct flow_stats *new_stats;

				// 在本节点上分配统计；__GFP_NOMEMALLOC 避免动用
				// 紧急内存储备，分配失败可容忍（退回用 stats[0]）。
				new_stats =
					kmem_cache_alloc_node(flow_stats_cache,
							      GFP_THISNODE |
							      __GFP_NOMEMALLOC,
							      node);
				if (likely(new_stats)) {
					// 用当前这一个报文初始化新统计
					new_stats->used = jiffies;
					new_stats->packet_count = 1;
					new_stats->byte_count = len;
					new_stats->tcp_flags = tcp_flags;
					spin_lock_init(&new_stats->lock);

					// 发布本节点专属统计，后续该节点直接走它
					rcu_assign_pointer(flow->stats[node],
							   new_stats);
					goto unlock;
				}
			}
			// 未分配（或分配失败）：仍写 stats[0]，并把写者标记为本节点
			flow->stats_last_writer = node;
		}
	}

	// 常规路径：在选定的 stats 上累加本次报文
	stats->used = jiffies;
	stats->packet_count++;
	stats->byte_count += len;
	stats->tcp_flags |= tcp_flags;
unlock:
	spin_unlock(&stats->lock);
}

/* Must be called with rcu_read_lock or ovs_mutex. */
// 汇总一条流在所有 NUMA 节点上的统计，供上报给用户态。
// 累加各节点的包数/字节数，对 tcp_flags 取并集，used 取最新（最大）值。
void ovs_flow_stats_get(const struct sw_flow *flow,
			struct ovs_flow_stats *ovs_stats,
			unsigned long *used, __be16 *tcp_flags)
{
	int node;

	// 输出参数清零
	*used = 0;
	*tcp_flags = 0;
	memset(ovs_stats, 0, sizeof(*ovs_stats));

	// 遍历每个 NUMA 节点的统计
	for_each_node(node) {
		struct flow_stats *stats = rcu_dereference_ovsl(flow->stats[node]);

		// 只有该节点分配过统计才需累加
		if (stats) {
			/* Local CPU may write on non-local stats, so we must
			 * block bottom-halves here.
			 */
			// 本地 CPU 可能通过 stats[0] 回退路径写非本地统计，
			// 因此这里要关下半部再加锁，避免与软中断上下文竞争。
			spin_lock_bh(&stats->lock);
			// used 取所有节点中最近的一次
			if (!*used || time_after(stats->used, *used))
				*used = stats->used;
			// TCP 标志取并集
			*tcp_flags |= stats->tcp_flags;
			// 包数、字节数累加
			ovs_stats->n_packets += stats->packet_count;
			ovs_stats->n_bytes += stats->byte_count;
			spin_unlock_bh(&stats->lock);
		}
	}
}

/* Called with ovs_mutex. */
// 清零一条流在所有 NUMA 节点上的统计（用于 dump-and-reset 等场景）。
void ovs_flow_stats_clear(struct sw_flow *flow)
{
	int node;

	for_each_node(node) {
		struct flow_stats *stats = ovsl_dereference(flow->stats[node]);

		if (stats) {
			spin_lock_bh(&stats->lock);
			stats->used = 0;
			stats->packet_count = 0;
			stats->byte_count = 0;
			stats->tcp_flags = 0;
			spin_unlock_bh(&stats->lock);
		}
	}
}

// 确保 skb 线性区至少有 len 字节可读：不足则尝试 pskb_may_pull 拉取。
// 返回 0 表示可安全访问前 len 字节；否则返回负错误码，防止后续越界读。
static int check_header(struct sk_buff *skb, int len)
{
	// 报文总长都不够，直接报错
	if (unlikely(skb->len < len))
		return -EINVAL;
	// 拉取失败（无法把前 len 字节线性化）
	if (unlikely(!pskb_may_pull(skb, len)))
		return -ENOMEM;
	return 0;
}

// 校验 ARP 头是否完整可读（从网络层偏移起需容纳一个 arp_eth_header）。
static bool arphdr_ok(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_network_offset(skb) +
				  sizeof(struct arp_eth_header));
}

// 校验 IPv4 头：先保证基本 iphdr 可读，再按 IHL 取真实头长，
// 确认头长合法且报文足够长，最后把 transport_header 定位到 IP 载荷起点。
static int check_iphdr(struct sk_buff *skb)
{
	unsigned int nh_ofs = skb_network_offset(skb);
	unsigned int ip_len;
	int err;

	// 先保证固定 20 字节 IP 头可读
	err = check_header(skb, nh_ofs + sizeof(struct iphdr));
	if (unlikely(err))
		return err;

	// 依据 IHL 得到含选项的真实 IP 头长
	ip_len = ip_hdrlen(skb);
	// 头长不能小于最小值，且报文要能容纳整个 IP 头
	if (unlikely(ip_len < sizeof(struct iphdr) ||
		     skb->len < nh_ofs + ip_len))
		return -EINVAL;

	// 传输层头紧跟 IP 头之后
	skb_set_transport_header(skb, nh_ofs + ip_len);
	return 0;
}

// 校验 TCP 头：先确保基本 tcphdr 可读，再按数据偏移取真实头长并校验。
static bool tcphdr_ok(struct sk_buff *skb)
{
	int th_ofs = skb_transport_offset(skb);
	int tcp_len;

	// 固定 20 字节 TCP 头是否可读
	if (unlikely(!pskb_may_pull(skb, th_ofs + sizeof(struct tcphdr))))
		return false;

	// 含选项的真实 TCP 头长
	tcp_len = tcp_hdrlen(skb);
	// 头长合法且报文足够长
	if (unlikely(tcp_len < sizeof(struct tcphdr) ||
		     skb->len < th_ofs + tcp_len))
		return false;

	return true;
}

// 校验 UDP 头是否完整可读。
static bool udphdr_ok(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_transport_offset(skb) +
				  sizeof(struct udphdr));
}

// 校验 SCTP 头是否完整可读。
static bool sctphdr_ok(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_transport_offset(skb) +
				  sizeof(struct sctphdr));
}

// 校验 ICMP 头是否完整可读。
static bool icmphdr_ok(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_transport_offset(skb) +
				  sizeof(struct icmphdr));
}

// 解析 IPv6 头及其扩展头链，填充 key 的 ip/ipv6 字段，并处理分片。
// 返回值：IPv6 头 + 扩展头的总长度（nh_len），失败返回负错误码。
// 该长度用于定位真正的上层协议（transport header）位置。
static int parse_ipv6hdr(struct sk_buff *skb, struct sw_flow_key *key)
{
	unsigned int nh_ofs = skb_network_offset(skb);
	unsigned int nh_len;
	int payload_ofs;
	struct ipv6hdr *nh;
	uint8_t nexthdr;
	__be16 frag_off;
	int err;

	// 先确保固定 40 字节 IPv6 头可读
	err = check_header(skb, nh_ofs + sizeof(*nh));
	if (unlikely(err))
		return err;

	nh = ipv6_hdr(skb);
	// 首个 Next Header 值与载荷起始偏移
	nexthdr = nh->nexthdr;
	payload_ofs = (u8 *)(nh + 1) - skb->data;

	// 从固定头提取 key 字段：协议先置 NONE，稍后按扩展头结果更新
	key->ip.proto = NEXTHDR_NONE;
	key->ip.tos = ipv6_get_dsfield(nh);		// DSCP/ECN
	key->ip.ttl = nh->hop_limit;			// 跳数限制（等价 TTL）
	// 20 位流标签
	key->ipv6.label = *(__be32 *)nh & htonl(IPV6_FLOWINFO_FLOWLABEL);
	key->ipv6.addr.src = nh->saddr;
	key->ipv6.addr.dst = nh->daddr;

	// 跳过所有扩展头，得到最终上层协议 nexthdr 与分片偏移 frag_off
	payload_ofs = ipv6_skip_exthdr(skb, payload_ofs, &nexthdr, &frag_off);
	if (unlikely(payload_ofs < 0))
		return -EINVAL;

	// 依据分片偏移判断分片类型
	if (frag_off) {
		// 偏移非 0（去掉低 3 位标志后仍非 0）：非首片
		if (frag_off & htons(~0x7))
			key->ip.frag = OVS_FRAG_TYPE_LATER;
		else
			key->ip.frag = OVS_FRAG_TYPE_FIRST;
	} else {
		key->ip.frag = OVS_FRAG_TYPE_NONE;
	}

	// IPv6 头 + 扩展头总长度
	nh_len = payload_ofs - nh_ofs;
	// 定位传输层头位置
	skb_set_transport_header(skb, nh_ofs + nh_len);
	// 记录真正的上层协议
	key->ip.proto = nexthdr;
	return nh_len;
}

// 校验 ICMPv6 头是否完整可读。
static bool icmp6hdr_ok(struct sk_buff *skb)
{
	return pskb_may_pull(skb, skb_transport_offset(skb) +
				  sizeof(struct icmp6hdr));
}

// 解析 802.1Q VLAN 标签，把 TCI 写入 key->eth.tci（并置 VLAN_TAG_PRESENT），
// 然后把 skb->data 越过 VLAN 前缀。用于 VLAN 标签仍在报文内（未被硬件剥离）的情形。
static int parse_vlan(struct sk_buff *skb, struct sw_flow_key *key)
{
	// VLAN 前缀：TPID(ETH_P_8021Q) + TCI
	struct qtag_prefix {
		__be16 eth_type; /* ETH_P_8021Q */
		__be16 tci;
	};
	struct qtag_prefix *qp;

	// 至少要有 VLAN 前缀加后续以太类型的空间
	if (unlikely(skb->len < sizeof(struct qtag_prefix) + sizeof(__be16)))
		return 0;

	// 保证这段可线性访问
	if (unlikely(!pskb_may_pull(skb, sizeof(struct qtag_prefix) +
					 sizeof(__be16))))
		return -ENOMEM;

	qp = (struct qtag_prefix *) skb->data;
	// 存 TCI 并标记“存在 VLAN”，便于与硬件剥离场景统一表示
	key->eth.tci = qp->tci | htons(VLAN_TAG_PRESENT);
	// 跳过 VLAN 前缀，使后续解析对齐到内层以太类型
	__skb_pull(skb, sizeof(struct qtag_prefix));

	return 0;
}

// 解析以太类型：处理 Ethernet II 与 802.3/LLC-SNAP 两种封装。
// 返回真正的上层协议类型（be16），出错返回 0。会推进 skb->data 越过已消费的头。
static __be16 parse_ethertype(struct sk_buff *skb)
{
	// LLC/SNAP 头：SNAP 固定 dsap/ssap=0xAA，oui 全 0 时其后跟真正 ethertype
	struct llc_snap_hdr {
		u8  dsap;  /* Always 0xAA */
		u8  ssap;  /* Always 0xAA */
		u8  ctrl;
		u8  oui[3];
		__be16 ethertype;
	};
	struct llc_snap_hdr *llc;
	__be16 proto;

	// 取以太类型字段并跳过它
	proto = *(__be16 *) skb->data;
	__skb_pull(skb, sizeof(__be16));

	// >= 0x0600 表示这是 Ethernet II 的类型字段，直接返回
	if (ntohs(proto) >= ETH_P_802_3_MIN)
		return proto;

	// 否则是 802.3 长度字段：尝试解析 LLC/SNAP
	if (skb->len < sizeof(struct llc_snap_hdr))
		return htons(ETH_P_802_2);

	if (unlikely(!pskb_may_pull(skb, sizeof(struct llc_snap_hdr))))
		return htons(0);

	// 判断是否为标准 SNAP 封装（dsap/ssap=0xAA 且 OUI 为 0）
	llc = (struct llc_snap_hdr *) skb->data;
	if (llc->dsap != LLC_SAP_SNAP ||
	    llc->ssap != LLC_SAP_SNAP ||
	    (llc->oui[0] | llc->oui[1] | llc->oui[2]) != 0)
		return htons(ETH_P_802_2);

	// 是 SNAP：跳过 LLC/SNAP 头，取其中携带的真正 ethertype
	__skb_pull(skb, sizeof(struct llc_snap_hdr));

	if (ntohs(llc->ethertype) >= ETH_P_802_3_MIN)
		return llc->ethertype;

	return htons(ETH_P_802_2);
}

// 解析 ICMPv6：把 type/code 存入 tp 端口字段（复用 16 位端口位置）；
// 对邻居发现报文（NS/NA）进一步解析其中的目标地址与链路层地址选项，填入 key->ipv6.nd。
// 返回 0 成功（含“非 ND、无需深入解析”的正常情况），线性化失败返回 -ENOMEM。
static int parse_icmpv6(struct sk_buff *skb, struct sw_flow_key *key,
			int nh_len)
{
	struct icmp6hdr *icmp = icmp6_hdr(skb);

	/* The ICMPv6 type and code fields use the 16-bit transport port
	 * fields, so we need to store them in 16-bit network byte order.
	 */
	// ICMPv6 的 type/code 借用 tp.src/tp.dst 存放（按 be16）
	key->tp.src = htons(icmp->icmp6_type);
	key->tp.dst = htons(icmp->icmp6_code);
	// 先清空 ND 相关字段
	memset(&key->ipv6.nd, 0, sizeof(key->ipv6.nd));

	// 仅对邻居请求(NS)/邻居通告(NA)且 code==0 的报文解析 ND 选项
	if (icmp->icmp6_code == 0 &&
	    (icmp->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION ||
	     icmp->icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT)) {
		int icmp_len = skb->len - skb_transport_offset(skb);
		struct nd_msg *nd;
		int offset;

		/* In order to process neighbor discovery options, we need the
		 * entire packet.
		 */
		// 长度不足一个 nd_msg，无 ND 选项可解析
		if (unlikely(icmp_len < sizeof(*nd)))
			return 0;

		// 解析 ND 选项需要完整线性报文
		if (unlikely(skb_linearize(skb)))
			return -ENOMEM;

		nd = (struct nd_msg *)skb_transport_header(skb);
		// 记录 ND 目标地址
		key->ipv6.nd.target = nd->target;

		// 遍历后续的 ND 选项（每个选项长度为 nd_opt_len*8 字节）
		icmp_len -= sizeof(*nd);
		offset = 0;
		while (icmp_len >= 8) {
			struct nd_opt_hdr *nd_opt =
				 (struct nd_opt_hdr *)(nd->opt + offset);
			int opt_len = nd_opt->nd_opt_len * 8;

			// 选项长度非法或越界，停止解析
			if (unlikely(!opt_len || opt_len > icmp_len))
				return 0;

			/* Store the link layer address if the appropriate
			 * option is provided.  It is considered an error if
			 * the same link layer option is specified twice.
			 */
			// 源链路层地址选项：记录 sll，重复出现视为非法
			if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LL_ADDR
			    && opt_len == 8) {
				if (unlikely(!is_zero_ether_addr(key->ipv6.nd.sll)))
					goto invalid;
				ether_addr_copy(key->ipv6.nd.sll,
						&nd->opt[offset+sizeof(*nd_opt)]);
			// 目标链路层地址选项：记录 tll，重复出现视为非法
			} else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LL_ADDR
				   && opt_len == 8) {
				if (unlikely(!is_zero_ether_addr(key->ipv6.nd.tll)))
					goto invalid;
				ether_addr_copy(key->ipv6.nd.tll,
						&nd->opt[offset+sizeof(*nd_opt)]);
			}

			// 前进到下一个选项
			icmp_len -= opt_len;
			offset += opt_len;
		}
	}

	return 0;

invalid:
	// 选项异常：清空已提取的 ND 字段，但仍按成功返回（key 视为不含 ND 信息）
	memset(&key->ipv6.nd.target, 0, sizeof(key->ipv6.nd.target));
	memset(key->ipv6.nd.sll, 0, sizeof(key->ipv6.nd.sll));
	memset(key->ipv6.nd.tll, 0, sizeof(key->ipv6.nd.tll));

	return 0;
}

/**
 * key_extract - extracts a flow key from an Ethernet frame.
 * @skb: sk_buff that contains the frame, with skb->data pointing to the
 * Ethernet header
 * @key: output flow key
 *
 * The caller must ensure that skb->len >= ETH_HLEN.
 *
 * Returns 0 if successful, otherwise a negative errno value.
 *
 * Initializes @skb header pointers as follows:
 *
 *    - skb->mac_header: the Ethernet header.
 *
 *    - skb->network_header: just past the Ethernet header, or just past the
 *      VLAN header, to the first byte of the Ethernet payload.
 *
 *    - skb->transport_header: If key->eth.type is ETH_P_IP or ETH_P_IPV6
 *      on output, then just past the IP header, if one is present and
 *      of a correct length, otherwise the same as skb->network_header.
 *      For other key->eth.type values it is left untouched.
 */
static int key_extract(struct sk_buff *skb, struct sw_flow_key *key)
{
	int error;
	struct ethhdr *eth;

	/* Flags are always used as part of stats */
	// tp.flags 会作为统计的一部分，先清零
	key->tp.flags = 0;

	// 此刻 skb->data 指向以太头，记为 mac header
	skb_reset_mac_header(skb);

	/* Link layer.  We are guaranteed to have at least the 14 byte Ethernet
	 * header in the linear data area.
	 */
	// 提取源/目的 MAC
	eth = eth_hdr(skb);
	ether_addr_copy(key->eth.src, eth->h_source);
	ether_addr_copy(key->eth.dst, eth->h_dest);

	// 跳过两个 MAC 地址（12 字节），使 data 指向以太类型字段
	__skb_pull(skb, 2 * ETH_ALEN);
	/* We are going to push all headers that we pull, so no need to
	 * update skb->csum here.
	 */
	// 后面所有 pull 的头最终都会被 push 回去，故此处无需维护 csum

	// 提取 VLAN：优先用硬件已剥离到 skb 的 vlan_tci；
	// 否则若报文内含 802.1Q 标签则调用 parse_vlan 就地解析
	key->eth.tci = 0;
	if (skb_vlan_tag_present(skb))
		key->eth.tci = htons(skb->vlan_tci);
	else if (eth->h_proto == htons(ETH_P_8021Q))
		if (unlikely(parse_vlan(skb, key)))
			return -ENOMEM;

	// 解析（可能经 LLC/SNAP 的）以太类型
	key->eth.type = parse_ethertype(skb);
	if (unlikely(key->eth.type == htons(0)))
		return -ENOMEM;

	// 此刻 data 指向 L3 头，记为 network header；mac_len 为 L2 头长度
	skb_reset_network_header(skb);
	skb_reset_mac_len(skb);
	// 把之前 pull 掉的 L2 头重新 push 回去，恢复 data 指向以太头，
	// 但 network/mac header 偏移已正确设置，供上层直接取头。
	__skb_push(skb, skb->data - skb_mac_header(skb));

	/* Network layer. */
	// 根据以太类型分流处理 IPv4 / ARP-RARP / MPLS / IPv6
	if (key->eth.type == htons(ETH_P_IP)) {
		struct iphdr *nh;
		__be16 offset;

		// 校验并定位 IPv4 头；失败则清空相关字段
		error = check_iphdr(skb);
		if (unlikely(error)) {
			memset(&key->ip, 0, sizeof(key->ip));
			memset(&key->ipv4, 0, sizeof(key->ipv4));
			// -EINVAL 表示头长/长度异常：把 transport 指向 network
			// 头，视作无 L4 信息但整体解析成功。
			if (error == -EINVAL) {
				skb->transport_header = skb->network_header;
				error = 0;
			}
			return error;
		}

		// 提取 IPv4 地址与 proto/tos/ttl
		nh = ip_hdr(skb);
		key->ipv4.addr.src = nh->saddr;
		key->ipv4.addr.dst = nh->daddr;

		key->ip.proto = nh->protocol;
		key->ip.tos = nh->tos;
		key->ip.ttl = nh->ttl;

		// 判断分片类型
		offset = nh->frag_off & htons(IP_OFFSET);
		if (offset) {
			// 分片偏移非 0：非首片，后续无 L4 头可解析
			key->ip.frag = OVS_FRAG_TYPE_LATER;
			return 0;
		}
		// MF 位置位，或 GSO UDP（将被分片）：首片
		if (nh->frag_off & htons(IP_MF) ||
			skb_shinfo(skb)->gso_type & SKB_GSO_UDP)
			key->ip.frag = OVS_FRAG_TYPE_FIRST;
		else
			key->ip.frag = OVS_FRAG_TYPE_NONE;

		/* Transport layer. */
		// 按 L4 协议提取端口/标志；头不完整则清零 tp
		if (key->ip.proto == IPPROTO_TCP) {
			if (tcphdr_ok(skb)) {
				struct tcphdr *tcp = tcp_hdr(skb);
				key->tp.src = tcp->source;
				key->tp.dst = tcp->dest;
				key->tp.flags = TCP_FLAGS_BE16(tcp);
			} else {
				memset(&key->tp, 0, sizeof(key->tp));
			}

		} else if (key->ip.proto == IPPROTO_UDP) {
			if (udphdr_ok(skb)) {
				struct udphdr *udp = udp_hdr(skb);
				key->tp.src = udp->source;
				key->tp.dst = udp->dest;
			} else {
				memset(&key->tp, 0, sizeof(key->tp));
			}
		} else if (key->ip.proto == IPPROTO_SCTP) {
			if (sctphdr_ok(skb)) {
				struct sctphdr *sctp = sctp_hdr(skb);
				key->tp.src = sctp->source;
				key->tp.dst = sctp->dest;
			} else {
				memset(&key->tp, 0, sizeof(key->tp));
			}
		} else if (key->ip.proto == IPPROTO_ICMP) {
			if (icmphdr_ok(skb)) {
				struct icmphdr *icmp = icmp_hdr(skb);
				/* The ICMP type and code fields use the 16-bit
				 * transport port fields, so we need to store
				 * them in 16-bit network byte order. */
				// ICMP 的 type/code 借用端口字段存放
				key->tp.src = htons(icmp->type);
				key->tp.dst = htons(icmp->code);
			} else {
				memset(&key->tp, 0, sizeof(key->tp));
			}
		}

	} else if (key->eth.type == htons(ETH_P_ARP) ||
		   key->eth.type == htons(ETH_P_RARP)) {
		// ARP/RARP：复用 ipv4 分支存放 IP 与硬件地址
		struct arp_eth_header *arp;
		bool arp_available = arphdr_ok(skb);

		arp = (struct arp_eth_header *)skb_network_header(skb);

		// 仅处理标准的以太网 + IPv4 ARP（硬件/协议类型与长度均匹配）
		if (arp_available &&
		    arp->ar_hrd == htons(ARPHRD_ETHER) &&
		    arp->ar_pro == htons(ETH_P_IP) &&
		    arp->ar_hln == ETH_ALEN &&
		    arp->ar_pln == 4) {

			/* We only match on the lower 8 bits of the opcode. */
			// 仅匹配 opcode 的低 8 位（request/reply 等）
			if (ntohs(arp->ar_op) <= 0xff)
				key->ip.proto = ntohs(arp->ar_op);
			else
				key->ip.proto = 0;

			// 发送/目标 IP 与硬件地址
			memcpy(&key->ipv4.addr.src, arp->ar_sip, sizeof(key->ipv4.addr.src));
			memcpy(&key->ipv4.addr.dst, arp->ar_tip, sizeof(key->ipv4.addr.dst));
			ether_addr_copy(key->ipv4.arp.sha, arp->ar_sha);
			ether_addr_copy(key->ipv4.arp.tha, arp->ar_tha);
		} else {
			// 非标准 ARP：清空相关字段
			memset(&key->ip, 0, sizeof(key->ip));
			memset(&key->ipv4, 0, sizeof(key->ipv4));
		}
	} else if (eth_p_mpls(key->eth.type)) {
		size_t stack_len = MPLS_HLEN;

		/* In the presence of an MPLS label stack the end of the L2
		 * header and the beginning of the L3 header differ.
		 *
		 * Advance network_header to the beginning of the L3
		 * header. mac_len corresponds to the end of the L2 header.
		 */
		// 逐层扫描 MPLS 标签栈：只保存栈顶标签(top_lse)到 key，
		// 并把 network_header 推进到栈底之后（真正的 L3 头起点）。
		while (1) {
			__be32 lse;

			// 保证当前这层标签可读
			error = check_header(skb, skb->mac_len + stack_len);
			if (unlikely(error))
				return 0;

			memcpy(&lse, skb_network_header(skb), MPLS_HLEN);

			// 只记录栈顶标签
			if (stack_len == MPLS_HLEN)
				memcpy(&key->mpls.top_lse, &lse, MPLS_HLEN);

			// network header 移到本层之后
			skb_set_network_header(skb, skb->mac_len + stack_len);
			// S 位（栈底标志）置位：标签栈结束
			if (lse & htonl(MPLS_LS_S_MASK))
				break;

			stack_len += MPLS_HLEN;
		}
	} else if (key->eth.type == htons(ETH_P_IPV6)) {
		int nh_len;             /* IPv6 Header + Extensions */

		// 解析 IPv6 头及扩展头，得到头总长 nh_len
		nh_len = parse_ipv6hdr(skb, key);
		if (unlikely(nh_len < 0)) {
			// 解析失败：清空 IP/IPv6 字段
			memset(&key->ip, 0, sizeof(key->ip));
			memset(&key->ipv6.addr, 0, sizeof(key->ipv6.addr));
			// -EINVAL 同 IPv4：视作无 L4，整体成功
			if (nh_len == -EINVAL) {
				skb->transport_header = skb->network_header;
				error = 0;
			} else {
				error = nh_len;
			}
			return error;
		}

		// 非首片则无 L4 头；GSO UDP 视为首片
		if (key->ip.frag == OVS_FRAG_TYPE_LATER)
			return 0;
		if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP)
			key->ip.frag = OVS_FRAG_TYPE_FIRST;

		/* Transport layer. */
		// 按 IPv6 上层协议提取 L4 字段
		if (key->ip.proto == NEXTHDR_TCP) {
			if (tcphdr_ok(skb)) {
				struct tcphdr *tcp = tcp_hdr(skb);
				key->tp.src = tcp->source;
				key->tp.dst = tcp->dest;
				key->tp.flags = TCP_FLAGS_BE16(tcp);
			} else {
				memset(&key->tp, 0, sizeof(key->tp));
			}
		} else if (key->ip.proto == NEXTHDR_UDP) {
			if (udphdr_ok(skb)) {
				struct udphdr *udp = udp_hdr(skb);
				key->tp.src = udp->source;
				key->tp.dst = udp->dest;
			} else {
				memset(&key->tp, 0, sizeof(key->tp));
			}
		} else if (key->ip.proto == NEXTHDR_SCTP) {
			if (sctphdr_ok(skb)) {
				struct sctphdr *sctp = sctp_hdr(skb);
				key->tp.src = sctp->source;
				key->tp.dst = sctp->dest;
			} else {
				memset(&key->tp, 0, sizeof(key->tp));
			}
		} else if (key->ip.proto == NEXTHDR_ICMP) {
			if (icmp6hdr_ok(skb)) {
				// ICMPv6 需进一步解析 ND 选项
				error = parse_icmpv6(skb, key, nh_len);
				if (error)
					return error;
			} else {
				memset(&key->tp, 0, sizeof(key->tp));
			}
		}
	}
	return 0;
}

// 对外入口：对已提取过的报文重新解析 key（如执行完某些 action 后需重算）。
// 只重解析报文字段部分，不触碰隧道/物理等元数据。
int ovs_flow_key_update(struct sk_buff *skb, struct sw_flow_key *key)
{
	return key_extract(skb, key);
}

// 对外入口：收包路径上从报文提取完整 key。
// 先填入隧道元数据（若有）和物理元数据（优先级、入端口、skb mark 等），
// 再调用 key_extract 提取 L2/L3/L4 报文字段。
int ovs_flow_key_extract(const struct ovs_tunnel_info *tun_info,
			 struct sk_buff *skb, struct sw_flow_key *key)
{
	/* Extract metadata from packet. */
	// 处理隧道元数据
	if (tun_info) {
		// 拷贝隧道 key
		memcpy(&key->tun_key, &tun_info->tunnel, sizeof(key->tun_key));

		if (tun_info->options) {
			// 编译期断言：options_len 的取值范围不会超出 tun_opts 容量
			BUILD_BUG_ON((1 << (sizeof(tun_info->options_len) *
						   8)) - 1
					> sizeof(key->tun_opts));
			// 把隧道选项右对齐拷入 tun_opts 末尾（见 TUN_METADATA_OPTS）
			memcpy(TUN_METADATA_OPTS(key, tun_info->options_len),
			       tun_info->options, tun_info->options_len);
			key->tun_opts_len = tun_info->options_len;
		} else {
			key->tun_opts_len = 0;
		}
	} else  {
		// 无隧道：清零隧道 key 与选项长度
		key->tun_opts_len = 0;
		memset(&key->tun_key, 0, sizeof(key->tun_key));
	}

	// 填充物理/元数据字段
	key->phy.priority = skb->priority;
	key->phy.in_port = OVS_CB(skb)->input_vport->port_no;
	key->phy.skb_mark = skb->mark;
	key->ovs_flow_hash = 0;
	key->recirc_id = 0;

	// 提取报文各层字段
	return key_extract(skb, key);
}

// 对外入口：从用户态下发的 netlink 属性提取 key（如添加流表项时）。
// 先按元数据大小清零 key，再从属性解析元数据，最后从随附报文提取字段。
int ovs_flow_key_extract_userspace(const struct nlattr *attr,
				   struct sk_buff *skb,
				   struct sw_flow_key *key, bool log)
{
	int err;

	// 只需清零元数据区（报文字段会在 key_extract 中被填充）
	memset(key, 0, OVS_SW_FLOW_KEY_METADATA_SIZE);

	/* Extract metadata from netlink attributes. */
	// 从 netlink 属性解析元数据（隧道、in_port、priority 等）
	err = ovs_nla_get_flow_metadata(attr, key, log);
	if (err)
		return err;

	// 从报文提取 L2/L3/L4 字段
	return key_extract(skb, key);
}
