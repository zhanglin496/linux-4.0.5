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

#ifndef FLOW_H
#define FLOW_H 1

#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/flex_array.h>
#include <net/inet_ecn.h>

struct sk_buff;

/* Used to memset ovs_key_ipv4_tunnel padding. */
// 隧道 key 的“有效数据长度”：从结构体起始到 tp_dst 字段末尾。
// 由于结构体带 __packed/__aligned，编译器可能在尾部补齐 padding；
// 该宏给出真正有意义的字节数，供 memset 清零尾部 padding 时使用，
// 保证按字节比较/哈希 key 时不会受到未初始化 padding 的干扰。
#define OVS_TUNNEL_KEY_SIZE					\
	(offsetof(struct ovs_key_ipv4_tunnel, tp_dst) +		\
	 FIELD_SIZEOF(struct ovs_key_ipv4_tunnel, tp_dst))

// 封装隧道（如 VXLAN/GRE/Geneve 等）的匹配键：
// 描述外层隧道头部信息，作为 sw_flow_key 的一部分参与流表匹配。
struct ovs_key_ipv4_tunnel {
	__be64 tun_id;		// 隧道 ID（如 VXLAN VNI、GRE key），网络字节序
	__be32 ipv4_src;	// 外层 IP 源地址
	__be32 ipv4_dst;	// 外层 IP 目的地址
	__be16 tun_flags;	// 隧道标志位（是否有 key、checksum 等）
	u8   ipv4_tos;		// 外层 IP ToS/DSCP
	u8   ipv4_ttl;		// 外层 IP TTL
	__be16 tp_src;		// 外层传输层源端口（如 UDP 源端口）
	__be16 tp_dst;		// 外层传输层目的端口（如 VXLAN 的 4789）
} __packed __aligned(4); /* Minimize padding. */

// 收包路径上携带的隧道信息：除隧道 key 外，还可携带变长的隧道选项
// （如 Geneve options），用于把外层隧道元数据传递给 key 提取流程。
struct ovs_tunnel_info {
	struct ovs_key_ipv4_tunnel tunnel;	// 解析出的隧道 key
	const void *options;			// 指向变长隧道选项的指针（可为 NULL）
	u8 options_len;				// 选项长度（字节）
};

/* Store options at the end of the array if they are less than the
 * maximum size. This allows us to get the benefits of variable length
 * matching for small options.
 */
// 隧道选项（tun_opts）采用“右对齐”存放：把变长选项放到 tun_opts[255]
// 数组的末尾，而不是从头开始。这样当选项较短时，前面未使用的字节保持为 0，
// 掩码匹配时可以像固定长度字段一样按字节比较，实现对小选项的变长通配匹配。
// OFFSET：给定选项长度，计算它在数组内的起始下标（从末尾往回数）。
#define TUN_METADATA_OFFSET(opt_len) \
	(FIELD_SIZEOF(struct sw_flow_key, tun_opts) - opt_len)
// OPTS：返回该选项在 key 内的实际写入地址（数组末尾的对齐位置）。
#define TUN_METADATA_OPTS(flow_key, opt_len) \
	((void *)((flow_key)->tun_opts + TUN_METADATA_OFFSET(opt_len)))

// 隧道信息初始化的底层实现：把各字段填入 tun_info->tunnel，
// 并清零结构体尾部 padding，最后记录选项指针与长度。
static inline void __ovs_flow_tun_info_init(struct ovs_tunnel_info *tun_info,
					    __be32 saddr, __be32 daddr,
					    u8 tos, u8 ttl,
					    __be16 tp_src,
					    __be16 tp_dst,
					    __be64 tun_id,
					    __be16 tun_flags,
					    const void *opts,
					    u8 opts_len)
{
	tun_info->tunnel.tun_id = tun_id;
	tun_info->tunnel.ipv4_src = saddr;
	tun_info->tunnel.ipv4_dst = daddr;
	tun_info->tunnel.ipv4_tos = tos;
	tun_info->tunnel.ipv4_ttl = ttl;
	tun_info->tunnel.tun_flags = tun_flags;

	/* For the tunnel types on the top of IPsec, the tp_src and tp_dst of
	 * the upper tunnel are used.
	 * E.g: GRE over IPSEC, the tp_src and tp_port are zero.
	 */
	tun_info->tunnel.tp_src = tp_src;
	tun_info->tunnel.tp_dst = tp_dst;

	/* Clear struct padding. */
	// 若结构体因对齐而带有尾部 padding，则将其清零，避免未初始化字节
	// 影响后续对隧道 key 的按字节比较与哈希。
	if (sizeof(tun_info->tunnel) != OVS_TUNNEL_KEY_SIZE)
		memset((unsigned char *)&tun_info->tunnel + OVS_TUNNEL_KEY_SIZE,
		       0, sizeof(tun_info->tunnel) - OVS_TUNNEL_KEY_SIZE);

	tun_info->options = opts;
	tun_info->options_len = opts_len;
}

// 便捷封装：直接从 IPv4 报文头 iph 取出源/目的地址、ToS、TTL，
// 再调用 __ovs_flow_tun_info_init 完成隧道信息初始化。
static inline void ovs_flow_tun_info_init(struct ovs_tunnel_info *tun_info,
					  const struct iphdr *iph,
					  __be16 tp_src,
					  __be16 tp_dst,
					  __be64 tun_id,
					  __be16 tun_flags,
					  const void *opts,
					  u8 opts_len)
{
	__ovs_flow_tun_info_init(tun_info, iph->saddr, iph->daddr,
				 iph->tos, iph->ttl,
				 tp_src, tp_dst,
				 tun_id, tun_flags,
				 opts, opts_len);
}

#define OVS_SW_FLOW_KEY_METADATA_SIZE			\
	(offsetof(struct sw_flow_key, recirc_id) +	\
	FIELD_SIZEOF(struct sw_flow_key, recirc_id))

// sw_flow_key：从报文提取出的“匹配键”，是 OVS 流表查找的核心。
// 布局上分为“元数据区”（隧道 + 物理端口等，位于结构体前部，到 recirc_id
// 结束，长度即 OVS_SW_FLOW_KEY_METADATA_SIZE）和“报文字段区”（L2/L3/L4）。
// 整个结构体按 long 对齐，以便掩码匹配时能够以机器字为单位批量比较，加速查找。
struct sw_flow_key {
	// 隧道选项缓冲区：变长选项右对齐存放于此（见 TUN_METADATA_* 宏）。
	u8 tun_opts[255];		//255 字节，隧道选项最大容量
	u8 tun_opts_len;		// 实际使用的隧道选项长度
	struct ovs_key_ipv4_tunnel tun_key;  /* Encapsulating tunnel key. */
	// 物理/QoS 元数据：紧跟在 tun_key 之后，__packed 保证无空洞。
	struct {
		u32	priority;	/* Packet QoS priority. */
		u32	skb_mark;	/* SKB mark. */
		u16	in_port;	/* Input switch port (or DP_MAX_PORTS). */
	} __packed phy; /* Safe when right after 'tun_key'. */
	u32 ovs_flow_hash;		/* Datapath computed hash value.  */
	u32 recirc_id;			/* Recirculation ID.  */
	// 以太层字段：源/目的 MAC、VLAN TCI、以太类型。
	struct {
		u8     src[ETH_ALEN];	/* Ethernet source address. */
		u8     dst[ETH_ALEN];	/* Ethernet destination address. */
		__be16 tci;		/* 0 if no VLAN, VLAN_TAG_PRESENT set otherwise. */
		__be16 type;		/* Ethernet frame type. */
	} eth;
	// MPLS 与 IP 三层字段共用同一块空间（同一报文不会同时是两者）。
	union {
		struct {
			__be32 top_lse;	/* top label stack entry */
		} mpls;
		struct {
			u8     proto;	/* IP protocol or lower 8 bits of ARP opcode. */
			u8     tos;	    /* IP ToS. */
			u8     ttl;	    /* IP TTL/hop limit. */
			u8     frag;	/* One of OVS_FRAG_TYPE_*. */
		} ip;
	};
	// 传输层字段：TCP/UDP/SCTP 端口，或复用为 ICMP 的 type/code；flags 存 TCP 标志。
	struct {
		__be16 src;		/* TCP/UDP/SCTP source port. */
		__be16 dst;		/* TCP/UDP/SCTP destination port. */
		__be16 flags;		/* TCP flags. */
	} tp;
	// IPv4 与 IPv6 地址族字段共用空间（由 eth.type 决定使用哪一支）。
	union {
		struct {
			struct {
				__be32 src;	/* IP source address. */
				__be32 dst;	/* IP destination address. */
			} addr;
			// ARP 报文复用 ipv4 分支：地址存于 addr，硬件地址存于 arp。
			struct {
				u8 sha[ETH_ALEN];	/* ARP source hardware address. */
				u8 tha[ETH_ALEN];	/* ARP target hardware address. */
			} arp;
		} ipv4;
		struct {
			struct {
				struct in6_addr src;	/* IPv6 source address. */
				struct in6_addr dst;	/* IPv6 destination address. */
			} addr;
			__be32 label;			/* IPv6 flow label. */
			// 邻居发现（NS/NA）相关字段：目标地址与链路层地址。
			struct {
				struct in6_addr target;	/* ND target address. */
				u8 sll[ETH_ALEN];	/* ND source link layer address. */
				u8 tll[ETH_ALEN];	/* ND target link layer address. */
			} nd;
		} ipv6;
	};
} __aligned(BITS_PER_LONG/8); /* Ensure that we can do comparisons as longs. */

// 描述 key 中参与匹配的字节区间 [start, end)，配合掩码只比较相关字段，
// 避免逐字节比较整个 key。
struct sw_flow_key_range {
	unsigned short int start;
	unsigned short int end;
};

// 流表掩码：与 key 配合实现通配（wildcard）匹配。
// 报文 key 先按 mask 逐字（在 range 范围内）做 AND，再去和流表项比较。
struct sw_flow_mask {
	int ref_count;			// 引用计数（多个流可共享同一掩码）
	struct rcu_head rcu;		// RCU 释放
	struct list_head list;		// 挂入 datapath 的掩码链表
	struct sw_flow_key_range range;	// 该掩码有效的 key 字节区间
	struct sw_flow_key key;		// 掩码本身（各字段的比特位）
};

// 匹配描述：把待匹配 key、有效区间与掩码打包，供流表增删改查使用。
struct sw_flow_match {
	struct sw_flow_key *key;
	struct sw_flow_key_range range;
	struct sw_flow_mask *mask;
};

#define MAX_UFID_LENGTH 16 /* 128 bits */

// 流的标识符：可以是用户态下发的 UFID（唯一流 ID），
// 也可以在没有 UFID 时退化为指向未经掩码处理的原始 key 的指针。
struct sw_flow_id {
	u32 ufid_len;			// >0 表示使用 ufid；=0 表示使用 unmasked_key
	union {
		u32 ufid[MAX_UFID_LENGTH / 4];
		struct sw_flow_key *unmasked_key;
	};
};

// 流的动作列表：变长数组，存储一串 netlink 属性形式的 action。
struct sw_flow_actions {
	struct rcu_head rcu;
	u32 actions_len;		// actions 数据总长度（字节）
	struct nlattr actions[];	// 变长动作序列
};

// 单个（每 NUMA 节点一份）流统计。用独立自旋锁保护，避免与其他节点竞争。
struct flow_stats {
	u64 packet_count;		/* Number of packets matched. */
	u64 byte_count;			/* Number of bytes matched. */
	unsigned long used;		/* Last used time (in jiffies). */
	spinlock_t lock;		/* Lock for atomic stats update. */
	__be16 tcp_flags;		/* Union of seen TCP flags. */
};

// 流表项：一条 key -> actions 的映射，是流表的基本单元。
struct sw_flow {
	struct rcu_head rcu;
	// 分别挂入“按 key 哈希”和“按 UFID 哈希”两张表；node[2] 支持
	// 哈希表扩容期间新旧两桶并存。
	struct {
		struct hlist_node node[2];
		u32 hash;
	} flow_table, ufid_table;
	int stats_last_writer;		/* NUMA-node id of the last writer on
					 * 'stats[0]'.
					 */
	struct sw_flow_key key;		// 掩码处理后的匹配 key
	struct sw_flow_id id;		// 流标识（UFID 或原始 key）
	struct sw_flow_mask *mask;	// 该流使用的掩码
	struct sw_flow_actions __rcu *sf_acts;	// 命中后执行的动作
	// per-NUMA-node 统计数组：stats[0] 在创建流时预分配，其余节点
	// 在首次有该节点报文命中时按需分配（持 stats[0].lock 时分配）。
	// 这样各 CPU 尽量更新本地节点的统计，避免跨节点 cache line 竞争。
	struct flow_stats __rcu *stats[]; /* One for each NUMA node.  First one
					   * is allocated at flow creation time,
					   * the rest are allocated on demand
					   * while holding the 'stats[0].lock'.
					   */
};

// OVS 内部使用的 ARP 头（以太网 + IPv4），__packed 保证与线上格式一致。
struct arp_eth_header {
	__be16      ar_hrd;	/* format of hardware address   */
	__be16      ar_pro;	/* format of protocol address   */
	unsigned char   ar_hln;	/* length of hardware address   */
	unsigned char   ar_pln;	/* length of protocol address   */
	__be16      ar_op;	/* ARP opcode (command)     */

	/* Ethernet+IPv4 specific members. */
	unsigned char       ar_sha[ETH_ALEN];	/* sender hardware address  */
	unsigned char       ar_sip[4];		/* sender IP address        */
	unsigned char       ar_tha[ETH_ALEN];	/* target hardware address  */
	unsigned char       ar_tip[4];		/* target IP address        */
} __packed;

static inline bool ovs_identifier_is_ufid(const struct sw_flow_id *sfid)
{
	// ufid_len 非 0 表示该流用 UFID 标识
	return sfid->ufid_len;
}

static inline bool ovs_identifier_is_key(const struct sw_flow_id *sfid)
{
	// 反之则用原始 key 标识
	return !ovs_identifier_is_ufid(sfid);
}

void ovs_flow_stats_update(struct sw_flow *, __be16 tcp_flags,
			   const struct sk_buff *);
void ovs_flow_stats_get(const struct sw_flow *, struct ovs_flow_stats *,
			unsigned long *used, __be16 *tcp_flags);
void ovs_flow_stats_clear(struct sw_flow *);
u64 ovs_flow_used_time(unsigned long flow_jiffies);

int ovs_flow_key_update(struct sk_buff *skb, struct sw_flow_key *key);
int ovs_flow_key_extract(const struct ovs_tunnel_info *tun_info,
			 struct sk_buff *skb,
			 struct sw_flow_key *key);
/* Extract key from packet coming from userspace. */
int ovs_flow_key_extract_userspace(const struct nlattr *attr,
				   struct sk_buff *skb,
				   struct sw_flow_key *key, bool log);

#endif /* flow.h */
