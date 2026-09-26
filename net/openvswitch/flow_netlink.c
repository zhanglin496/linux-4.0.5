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

#include "flow.h"
#include "datapath.h"
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
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/rculist.h>
#include <net/geneve.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/mpls.h>

#include "flow_netlink.h"
#include "vport-vxlan.h"

/*
 * 本文件是 Open vSwitch 控制面协议的“编解码层”：负责在
 * 用户态 (ovs-vswitchd) 使用的 netlink 属性 (OVS_KEY_ATTR_* /
 * OVS_ACTION_ATTR_* / OVS_TUNNEL_KEY_ATTR_*) 与内核内部的流表结构
 * (sw_flow_key / sw_flow_mask / sw_flow_actions) 之间做双向转换。
 *
 * 两个方向：
 *  1) 属性 -> 内核结构（解析）：ovs_nla_get_match / ovs_key_from_nlattrs
 *     等。除了填字段，还要做严格的合法性校验，并记录“被触及字段”的
 *     字节范围 (sw_flow_key_range)，供 megaflow 掩码匹配使用。
 *  2) 内核结构 -> 属性（序列化）：__ovs_nla_put_key / ovs_nla_put_actions
 *     等，用于向用户态 dump 流表。序列化会省略默认值（如全 0 字段）
 *     以减小报文体积。
 */

/* 属性长度校验表的元素：len 为期望字节数；若为 OVS_ATTR_NESTED 表示
 * 该属性是嵌套的（长度不定），next 指向其内层属性的长度表。 */
struct ovs_len_tbl {
	int len;
	const struct ovs_len_tbl *next;
};

/* len 字段取此值表示“嵌套属性”，长度不做固定校验 */
#define OVS_ATTR_NESTED -1

/*
 * update_range - 扩展 match 中“被写过的字段”范围。
 *
 * OVS 的 megaflow 机制只对 key 中实际参与匹配的字节做哈希/比较，
 * 因此每写一个字段都要把该字段占据的字节区间并入 range。范围按
 * sizeof(long) 对齐（向下取整 start，向上取整 end），便于后续以字长
 * 为单位做批量比较。is_mask 决定更新的是 key 的范围还是 mask 的范围。
 */
static void update_range(struct sw_flow_match *match,
			 size_t offset, size_t size, bool is_mask)
{
	struct sw_flow_key_range *range;
	size_t start = rounddown(offset, sizeof(long));
	size_t end = roundup(offset + size, sizeof(long));

	if (!is_mask)
		range = &match->range;
	else
		range = &match->mask->range;

	/* range 尚未初始化（start==end）时直接置为本次区间 */
	if (range->start == range->end) {
		range->start = start;
		range->end = end;
		return;
	}

	/* 否则把新区间并入已有区间（取并集） */
	if (range->start > start)
		range->start = start;

	if (range->end < end)
		range->end = end;
}

/* 以下三个宏是解析阶段往 sw_flow_key 写字段的统一入口：既写值，又通过
 * update_range 记录字段范围。is_mask 为真时写 mask->key，否则写 key。 */

/* 写单个标量字段（by value） */
#define SW_FLOW_KEY_PUT(match, field, value, is_mask) \
	do { \
		update_range(match, offsetof(struct sw_flow_key, field),    \
			     sizeof((match)->key->field), is_mask);	    \
		if (is_mask)						    \
			(match)->mask->key.field = value;		    \
		else							    \
			(match)->key->field = value;		            \
	} while (0)

/* 按“字节偏移”拷贝一段数据到 key（用于变长/隧道选项等场景） */
#define SW_FLOW_KEY_MEMCPY_OFFSET(match, offset, value_p, len, is_mask)	    \
	do {								    \
		update_range(match, offset, len, is_mask);		    \
		if (is_mask)						    \
			memcpy((u8 *)&(match)->mask->key + offset, value_p, \
			       len);					   \
		else							    \
			memcpy((u8 *)(match)->key + offset, value_p, len);  \
	} while (0)

/* 按“字段名”拷贝一段数据（如 MAC 地址、IPv6 地址） */
#define SW_FLOW_KEY_MEMCPY(match, field, value_p, len, is_mask)		      \
	SW_FLOW_KEY_MEMCPY_OFFSET(match, offsetof(struct sw_flow_key, field), \
				  value_p, len, is_mask)

/* 把某字段整块置为同一字节值（如把 mask 字段整体设为 0xff 做精确匹配） */
#define SW_FLOW_KEY_MEMSET_FIELD(match, field, value, is_mask)		    \
	do {								    \
		update_range(match, offsetof(struct sw_flow_key, field),    \
			     sizeof((match)->key->field), is_mask);	    \
		if (is_mask)						    \
			memset((u8 *)&(match)->mask->key.field, value,      \
			       sizeof((match)->mask->key.field));	    \
		else							    \
			memset((u8 *)&(match)->key->field, value,           \
			       sizeof((match)->key->field));                \
	} while (0)

/*
 * match_validate - 校验解析出来的 key/mask 属性组合是否自洽。
 *
 * 调用者：ovs_nla_get_match 在解析完 key 和 mask 后调用。
 * 思路：
 *  - key_expected：根据已解析出的 eth.type / ip.proto 推导出“这个流按理
 *    应该出现哪些属性”。例如以太类型是 IPv4 且上层是 TCP，就应该带
 *    OVS_KEY_ATTR_IPV4 和 OVS_KEY_ATTR_TCP。缺了就报错。
 *  - mask_allowed：哪些属性允许出现在 mask 中。L3/L4 掩码只有在对应的
 *    以太类型/协议做了精确匹配 (mask==0xffff/0xff) 时才允许通配，否则
 *    掩码含义不明确。TUNNEL/IN_PORT/ETHERTYPE 总是允许。
 * 返回值：合法返回 true，否则打印错误并返回 false。
 */
static bool match_validate(const struct sw_flow_match *match,
			   u64 key_attrs, u64 mask_attrs, bool log)
{
	/* 以太头是最基本的，任何流都必须有 */
	u64 key_expected = 1 << OVS_KEY_ATTR_ETHERNET;
	u64 mask_allowed = key_attrs;  /* At most allow all key attributes */

	/* The following mask attributes allowed only if they
	 * pass the validation tests. */
	/* 先把所有 L3/L4 掩码从允许集合中去掉，下面按需重新放行 */
	mask_allowed &= ~((1 << OVS_KEY_ATTR_IPV4)
			| (1 << OVS_KEY_ATTR_IPV6)
			| (1 << OVS_KEY_ATTR_TCP)
			| (1 << OVS_KEY_ATTR_TCP_FLAGS)
			| (1 << OVS_KEY_ATTR_UDP)
			| (1 << OVS_KEY_ATTR_SCTP)
			| (1 << OVS_KEY_ATTR_ICMP)
			| (1 << OVS_KEY_ATTR_ICMPV6)
			| (1 << OVS_KEY_ATTR_ARP)
			| (1 << OVS_KEY_ATTR_ND)
			| (1 << OVS_KEY_ATTR_MPLS));

	/* Always allowed mask fields. */
	mask_allowed |= ((1 << OVS_KEY_ATTR_TUNNEL)
		       | (1 << OVS_KEY_ATTR_IN_PORT)
		       | (1 << OVS_KEY_ATTR_ETHERTYPE));

	/* Check key attributes. */
	/* ARP/RARP：应带 ARP 属性；仅当以太类型做了精确匹配才允许 ARP 掩码 */
	if (match->key->eth.type == htons(ETH_P_ARP)
			|| match->key->eth.type == htons(ETH_P_RARP)) {
		key_expected |= 1 << OVS_KEY_ATTR_ARP;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1 << OVS_KEY_ATTR_ARP;
	}

	if (eth_p_mpls(match->key->eth.type)) {
		key_expected |= 1 << OVS_KEY_ATTR_MPLS;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1 << OVS_KEY_ATTR_MPLS;
	}

	/* IPv4：需要 IPV4 属性；非分片后续包时，再根据 L4 协议要求 TCP/UDP/
	 * SCTP/ICMP 属性。OVS_FRAG_TYPE_LATER 表示 IP 分片的非首片，此时没有
	 * L4 头，故不要求 L4 属性。 */
	if (match->key->eth.type == htons(ETH_P_IP)) {
		key_expected |= 1 << OVS_KEY_ATTR_IPV4;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1 << OVS_KEY_ATTR_IPV4;

		if (match->key->ip.frag != OVS_FRAG_TYPE_LATER) {
			if (match->key->ip.proto == IPPROTO_UDP) {
				key_expected |= 1 << OVS_KEY_ATTR_UDP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1 << OVS_KEY_ATTR_UDP;
			}

			if (match->key->ip.proto == IPPROTO_SCTP) {
				key_expected |= 1 << OVS_KEY_ATTR_SCTP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1 << OVS_KEY_ATTR_SCTP;
			}

			if (match->key->ip.proto == IPPROTO_TCP) {
				key_expected |= 1 << OVS_KEY_ATTR_TCP;
				key_expected |= 1 << OVS_KEY_ATTR_TCP_FLAGS;
				if (match->mask && (match->mask->key.ip.proto == 0xff)) {
					mask_allowed |= 1 << OVS_KEY_ATTR_TCP;
					mask_allowed |= 1 << OVS_KEY_ATTR_TCP_FLAGS;
				}
			}

			if (match->key->ip.proto == IPPROTO_ICMP) {
				key_expected |= 1 << OVS_KEY_ATTR_ICMP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1 << OVS_KEY_ATTR_ICMP;
			}
		}
	}

	if (match->key->eth.type == htons(ETH_P_IPV6)) {
		key_expected |= 1 << OVS_KEY_ATTR_IPV6;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1 << OVS_KEY_ATTR_IPV6;

		if (match->key->ip.frag != OVS_FRAG_TYPE_LATER) {
			if (match->key->ip.proto == IPPROTO_UDP) {
				key_expected |= 1 << OVS_KEY_ATTR_UDP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1 << OVS_KEY_ATTR_UDP;
			}

			if (match->key->ip.proto == IPPROTO_SCTP) {
				key_expected |= 1 << OVS_KEY_ATTR_SCTP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1 << OVS_KEY_ATTR_SCTP;
			}

			if (match->key->ip.proto == IPPROTO_TCP) {
				key_expected |= 1 << OVS_KEY_ATTR_TCP;
				key_expected |= 1 << OVS_KEY_ATTR_TCP_FLAGS;
				if (match->mask && (match->mask->key.ip.proto == 0xff)) {
					mask_allowed |= 1 << OVS_KEY_ATTR_TCP;
					mask_allowed |= 1 << OVS_KEY_ATTR_TCP_FLAGS;
				}
			}

			if (match->key->ip.proto == IPPROTO_ICMPV6) {
				key_expected |= 1 << OVS_KEY_ATTR_ICMPV6;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1 << OVS_KEY_ATTR_ICMPV6;

				/* 邻居请求/通告 (NS/NA) 才携带 ND 属性 */
				if (match->key->tp.src ==
						htons(NDISC_NEIGHBOUR_SOLICITATION) ||
				    match->key->tp.src == htons(NDISC_NEIGHBOUR_ADVERTISEMENT)) {
					key_expected |= 1 << OVS_KEY_ATTR_ND;
					if (match->mask && (match->mask->key.tp.src == htons(0xff)))
						mask_allowed |= 1 << OVS_KEY_ATTR_ND;
				}
			}
		}
	}

	if ((key_attrs & key_expected) != key_expected) {
		/* Key attributes check failed. */
		/* 缺少必需的 key 属性 */
		OVS_NLERR(log, "Missing key (keys=%llx, expected=%llx)",
			  (unsigned long long)key_attrs,
			  (unsigned long long)key_expected);
		return false;
	}

	if ((mask_attrs & mask_allowed) != mask_attrs) {
		/* Mask attributes check failed. */
		/* mask 中出现了不允许通配的属性 */
		OVS_NLERR(log, "Unexpected mask (mask=%llx, allowed=%llx)",
			  (unsigned long long)mask_attrs,
			  (unsigned long long)mask_allowed);
		return false;
	}

	return true;
}

/*
 * ovs_tun_key_attr_size - 计算序列化一个隧道 key 到 netlink 所需的最大字节数。
 * 调用者用它预留 skb 空间。每一项对应一个 OVS_TUNNEL_KEY_ATTR_* 属性，
 * nla_total_size(n) 含属性头 + n 字节 payload 的对齐后大小。
 * 新增隧道字段时需同步更新此函数。
 */
size_t ovs_tun_key_attr_size(void)
{
	/* Whenever adding new OVS_TUNNEL_KEY_ FIELDS, we should consider
	 * updating this function.
	 */
	return    nla_total_size(8)    /* OVS_TUNNEL_KEY_ATTR_ID */
		+ nla_total_size(4)    /* OVS_TUNNEL_KEY_ATTR_IPV4_SRC */
		+ nla_total_size(4)    /* OVS_TUNNEL_KEY_ATTR_IPV4_DST */
		+ nla_total_size(1)    /* OVS_TUNNEL_KEY_ATTR_TOS */
		+ nla_total_size(1)    /* OVS_TUNNEL_KEY_ATTR_TTL */
		+ nla_total_size(0)    /* OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT */
		+ nla_total_size(0)    /* OVS_TUNNEL_KEY_ATTR_CSUM */
		+ nla_total_size(0)    /* OVS_TUNNEL_KEY_ATTR_OAM */
		+ nla_total_size(256)  /* OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS */
		/* OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS is mutually exclusive with
		 * OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS and covered by it.
		 */
		+ nla_total_size(2)    /* OVS_TUNNEL_KEY_ATTR_TP_SRC */
		+ nla_total_size(2);   /* OVS_TUNNEL_KEY_ATTR_TP_DST */
}

/*
 * ovs_key_attr_size - 计算序列化一个完整 flow key 到 netlink 的最大字节数。
 * 同样用于预留 skb 空间。注意此处只累加“同一报文可能同时出现”的属性子集
 * （例如 IPv6 与 ICMPv6/ND 是最大组合），并非把所有 OVS_KEY_ATTR_* 相加。
 */
size_t ovs_key_attr_size(void)
{
	/* Whenever adding new OVS_KEY_ FIELDS, we should consider
	 * updating this function.
	 */
	/* 编译期断言：确认枚举值未被意外改动 */
	BUILD_BUG_ON(OVS_KEY_ATTR_TUNNEL_INFO != 22);

	return    nla_total_size(4)   /* OVS_KEY_ATTR_PRIORITY */
		+ nla_total_size(0)   /* OVS_KEY_ATTR_TUNNEL */
		  + ovs_tun_key_attr_size()
		+ nla_total_size(4)   /* OVS_KEY_ATTR_IN_PORT */
		+ nla_total_size(4)   /* OVS_KEY_ATTR_SKB_MARK */
		+ nla_total_size(4)   /* OVS_KEY_ATTR_DP_HASH */
		+ nla_total_size(4)   /* OVS_KEY_ATTR_RECIRC_ID */
		+ nla_total_size(12)  /* OVS_KEY_ATTR_ETHERNET */
		+ nla_total_size(2)   /* OVS_KEY_ATTR_ETHERTYPE */
		+ nla_total_size(4)   /* OVS_KEY_ATTR_VLAN */
		+ nla_total_size(0)   /* OVS_KEY_ATTR_ENCAP */
		+ nla_total_size(2)   /* OVS_KEY_ATTR_ETHERTYPE */
		+ nla_total_size(40)  /* OVS_KEY_ATTR_IPV6 */
		+ nla_total_size(2)   /* OVS_KEY_ATTR_ICMPV6 */
		+ nla_total_size(28); /* OVS_KEY_ATTR_ND */
}

/* 隧道内层属性 (OVS_TUNNEL_KEY_ATTR_*) 的期望长度表。GENEVE/VXLAN 选项
 * 是嵌套/变长的，标记为 OVS_ATTR_NESTED。 */
static const struct ovs_len_tbl ovs_tunnel_key_lens[OVS_TUNNEL_KEY_ATTR_MAX + 1] = {
	[OVS_TUNNEL_KEY_ATTR_ID]	    = { .len = sizeof(u64) },
	[OVS_TUNNEL_KEY_ATTR_IPV4_SRC]	    = { .len = sizeof(u32) },
	[OVS_TUNNEL_KEY_ATTR_IPV4_DST]	    = { .len = sizeof(u32) },
	[OVS_TUNNEL_KEY_ATTR_TOS]	    = { .len = 1 },
	[OVS_TUNNEL_KEY_ATTR_TTL]	    = { .len = 1 },
	[OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT] = { .len = 0 },
	[OVS_TUNNEL_KEY_ATTR_CSUM]	    = { .len = 0 },
	[OVS_TUNNEL_KEY_ATTR_TP_SRC]	    = { .len = sizeof(u16) },
	[OVS_TUNNEL_KEY_ATTR_TP_DST]	    = { .len = sizeof(u16) },
	[OVS_TUNNEL_KEY_ATTR_OAM]	    = { .len = 0 },
	[OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS]   = { .len = OVS_ATTR_NESTED },
	[OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS]    = { .len = OVS_ATTR_NESTED },
};

/* The size of the argument for each %OVS_KEY_ATTR_* Netlink attribute.  */
/* 每种 key 属性的期望 payload 长度，解析时用它做长度校验。ENCAP/TUNNEL
 * 是嵌套属性；TUNNEL 的 next 指向上面的隧道内层长度表。 */
static const struct ovs_len_tbl ovs_key_lens[OVS_KEY_ATTR_MAX + 1] = {
	[OVS_KEY_ATTR_ENCAP]	 = { .len = OVS_ATTR_NESTED },
	[OVS_KEY_ATTR_PRIORITY]	 = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_IN_PORT]	 = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_SKB_MARK]	 = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_ETHERNET]	 = { .len = sizeof(struct ovs_key_ethernet) },
	[OVS_KEY_ATTR_VLAN]	 = { .len = sizeof(__be16) },
	[OVS_KEY_ATTR_ETHERTYPE] = { .len = sizeof(__be16) },
	[OVS_KEY_ATTR_IPV4]	 = { .len = sizeof(struct ovs_key_ipv4) },
	[OVS_KEY_ATTR_IPV6]	 = { .len = sizeof(struct ovs_key_ipv6) },
	[OVS_KEY_ATTR_TCP]	 = { .len = sizeof(struct ovs_key_tcp) },
	[OVS_KEY_ATTR_TCP_FLAGS] = { .len = sizeof(__be16) },
	[OVS_KEY_ATTR_UDP]	 = { .len = sizeof(struct ovs_key_udp) },
	[OVS_KEY_ATTR_SCTP]	 = { .len = sizeof(struct ovs_key_sctp) },
	[OVS_KEY_ATTR_ICMP]	 = { .len = sizeof(struct ovs_key_icmp) },
	[OVS_KEY_ATTR_ICMPV6]	 = { .len = sizeof(struct ovs_key_icmpv6) },
	[OVS_KEY_ATTR_ARP]	 = { .len = sizeof(struct ovs_key_arp) },
	[OVS_KEY_ATTR_ND]	 = { .len = sizeof(struct ovs_key_nd) },
	[OVS_KEY_ATTR_RECIRC_ID] = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_DP_HASH]	 = { .len = sizeof(u32) },
	[OVS_KEY_ATTR_TUNNEL]	 = { .len = OVS_ATTR_NESTED,
				     .next = ovs_tunnel_key_lens, },
	[OVS_KEY_ATTR_MPLS]	 = { .len = sizeof(struct ovs_key_mpls) },
};

/* 判断一段内存是否全 0。用于 mask 解析：全 0 掩码字段等价于“通配”，
 * 可以不记录（见 __parse_flow_nlattrs 的 nz 参数）。fp 为 NULL 返回 false。 */
static bool is_all_zero(const u8 *fp, size_t size)
{
	int i;

	if (!fp)
		return false;

	for (i = 0; i < size; i++)
		if (fp[i])
			return false;

	return true;
}

/*
 * __parse_flow_nlattrs - 遍历一串嵌套的 OVS_KEY_ATTR_* 属性，做基础校验，
 * 并把每个属性按类型索引存入 a[]，同时在位图 *attrsp 里置位记录“出现了哪些”。
 *
 * 校验内容：类型是否越界、是否重复出现、长度是否符合 ovs_key_lens 表。
 * nz (non-zero)：为真时（mask 解析）跳过全 0 的属性——全 0 掩码即通配，
 * 不必记录，从而让上层生成更宽的 megaflow。
 * 返回 0 成功，负值失败。
 */
static int __parse_flow_nlattrs(const struct nlattr *attr,
				const struct nlattr *a[],
				u64 *attrsp, bool log, bool nz)
{
	const struct nlattr *nla;
	u64 attrs;
	int rem;

	attrs = *attrsp;
	nla_for_each_nested(nla, attr, rem) {
		u16 type = nla_type(nla);
		int expected_len;

		/* 类型越界 */
		if (type > OVS_KEY_ATTR_MAX) {
			OVS_NLERR(log, "Key type %d is out of range max %d",
				  type, OVS_KEY_ATTR_MAX);
			return -EINVAL;
		}

		/* 同一属性重复出现视为非法 */
		if (attrs & (1 << type)) {
			OVS_NLERR(log, "Duplicate key (type %d).", type);
			return -EINVAL;
		}

		/* 长度校验：嵌套属性 (OVS_ATTR_NESTED) 长度不定，跳过检查 */
		expected_len = ovs_key_lens[type].len;
		if (nla_len(nla) != expected_len && expected_len != OVS_ATTR_NESTED) {
			OVS_NLERR(log, "Key %d has unexpected len %d expected %d",
				  type, nla_len(nla), expected_len);
			return -EINVAL;
		}

		/* nz 时跳过全 0 属性（通配），否则记录该属性 */
		if (!nz || !is_all_zero(nla_data(nla), expected_len)) {
			attrs |= 1 << type;
			a[type] = nla;
		}
	}
	/* nla_for_each_nested 结束后仍有剩余字节，说明消息被截断/畸形 */
	if (rem) {
		OVS_NLERR(log, "Message has %d unknown bytes.", rem);
		return -EINVAL;
	}

	*attrsp = attrs;
	return 0;
}

/* mask 属性解析入口：nz=true，全 0 掩码字段（通配）不记录 */
static int parse_flow_mask_nlattrs(const struct nlattr *attr,
				   const struct nlattr *a[], u64 *attrsp,
				   bool log)
{
	return __parse_flow_nlattrs(attr, a, attrsp, log, true);
}

/* key 属性解析入口：nz=false，所有出现的属性都要记录 */
static int parse_flow_nlattrs(const struct nlattr *attr,
			      const struct nlattr *a[], u64 *attrsp,
			      bool log)
{
	return __parse_flow_nlattrs(attr, a, attrsp, log, false);
}

/*
 * genev_tun_opt_from_nlattr - 解析 Geneve 隧道选项属性到 key->tun_opts。
 * 校验：总长不超过 tun_opts 空间、必须 4 字节对齐。
 * 关键点：必须记录选项长度 tun_opts_len，否则相同前缀但携带更多选项的
 * 报文会被错误匹配。mask 侧比较特殊——它同时查看 key 和 mask（假定 key
 * 已先解析），因为选项是变长的，无法在后续 validate 阶段核对。
 */
static int genev_tun_opt_from_nlattr(const struct nlattr *a,
				     struct sw_flow_match *match, bool is_mask,
				     bool log)
{
	unsigned long opt_key_offset;

	if (nla_len(a) > sizeof(match->key->tun_opts)) {
		OVS_NLERR(log, "Geneve option length err (len %d, max %zu).",
			  nla_len(a), sizeof(match->key->tun_opts));
		return -EINVAL;
	}

	if (nla_len(a) % 4 != 0) {
		OVS_NLERR(log, "Geneve opt len %d is not a multiple of 4.",
			  nla_len(a));
		return -EINVAL;
	}

	/* We need to record the length of the options passed
	 * down, otherwise packets with the same format but
	 * additional options will be silently matched.
	 */
	if (!is_mask) {
		SW_FLOW_KEY_PUT(match, tun_opts_len, nla_len(a),
				false);
	} else {
		/* This is somewhat unusual because it looks at
		 * both the key and mask while parsing the
		 * attributes (and by extension assumes the key
		 * is parsed first). Normally, we would verify
		 * that each is the correct length and that the
		 * attributes line up in the validate function.
		 * However, that is difficult because this is
		 * variable length and we won't have the
		 * information later.
		 */
		if (match->key->tun_opts_len != nla_len(a)) {
			OVS_NLERR(log, "Geneve option len %d != mask len %d",
				  match->key->tun_opts_len, nla_len(a));
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, tun_opts_len, 0xff, true);
	}

	opt_key_offset = TUN_METADATA_OFFSET(nla_len(a));
	SW_FLOW_KEY_MEMCPY_OFFSET(match, opt_key_offset, nla_data(a),
				  nla_len(a), is_mask);
	return 0;
}

/* VXLAN 扩展选项的 netlink 属性策略：目前仅 GBP (Group Based Policy) */
static const struct nla_policy vxlan_opt_policy[OVS_VXLAN_EXT_MAX + 1] = {
	[OVS_VXLAN_EXT_GBP]	= { .type = NLA_U32 },
};

/*
 * vxlan_tun_opt_from_nlattr - 解析 VXLAN 扩展选项到 key->tun_opts。
 * 与 Geneve 类似，也要记录 tun_opts_len；mask 侧 tun_opts_len 置 0xff。
 */
static int vxlan_tun_opt_from_nlattr(const struct nlattr *a,
				     struct sw_flow_match *match, bool is_mask,
				     bool log)
{
	struct nlattr *tb[OVS_VXLAN_EXT_MAX+1];
	unsigned long opt_key_offset;
	struct ovs_vxlan_opts opts;
	int err;

	BUILD_BUG_ON(sizeof(opts) > sizeof(match->key->tun_opts));

	err = nla_parse_nested(tb, OVS_VXLAN_EXT_MAX, a, vxlan_opt_policy);
	if (err < 0)
		return err;

	memset(&opts, 0, sizeof(opts));

	if (tb[OVS_VXLAN_EXT_GBP])
		opts.gbp = nla_get_u32(tb[OVS_VXLAN_EXT_GBP]);

	if (!is_mask)
		SW_FLOW_KEY_PUT(match, tun_opts_len, sizeof(opts), false);
	else
		SW_FLOW_KEY_PUT(match, tun_opts_len, 0xff, true);

	opt_key_offset = TUN_METADATA_OFFSET(sizeof(opts));
	SW_FLOW_KEY_MEMCPY_OFFSET(match, opt_key_offset, &opts, sizeof(opts),
				  is_mask);
	return 0;
}

/*
 * ipv4_tun_from_nlattr - 解析 OVS_KEY_ATTR_TUNNEL 嵌套里的各 IPv4 隧道属性
 * 到 match 的 tun_key/tun_opts。
 * 调用者：metadata_from_nlattrs（key/mask 解析）以及
 * validate_and_copy_set_tun（set tunnel 动作）。
 * 边遍历边把出现过的标志累积到 tun_flags（TUNNEL_KEY/CSUM/OAM 等），最后
 * 一次性写入。GENEVE/VXLAN 选项互斥（只能有一种 metadata 块）。
 * 返回值：>=0 表示 opts_type（选项类型，0 表示没有选项），<0 为错误码。
 */
static int ipv4_tun_from_nlattr(const struct nlattr *attr,
				struct sw_flow_match *match, bool is_mask,
				bool log)
{
	struct nlattr *a;
	int rem;
	bool ttl = false;
	__be16 tun_flags = 0;
	int opts_type = 0;

	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		int err;

		if (type > OVS_TUNNEL_KEY_ATTR_MAX) {
			OVS_NLERR(log, "Tunnel attr %d out of range max %d",
				  type, OVS_TUNNEL_KEY_ATTR_MAX);
			return -EINVAL;
		}

		if (ovs_tunnel_key_lens[type].len != nla_len(a) &&
		    ovs_tunnel_key_lens[type].len != OVS_ATTR_NESTED) {
			OVS_NLERR(log, "Tunnel attr %d has unexpected len %d expected %d",
				  type, nla_len(a), ovs_tunnel_key_lens[type].len);
			return -EINVAL;
		}

		switch (type) {
		case OVS_TUNNEL_KEY_ATTR_ID:
			SW_FLOW_KEY_PUT(match, tun_key.tun_id,
					nla_get_be64(a), is_mask);
			tun_flags |= TUNNEL_KEY;
			break;
		case OVS_TUNNEL_KEY_ATTR_IPV4_SRC:
			SW_FLOW_KEY_PUT(match, tun_key.ipv4_src,
					nla_get_be32(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_IPV4_DST:
			SW_FLOW_KEY_PUT(match, tun_key.ipv4_dst,
					nla_get_be32(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_TOS:
			SW_FLOW_KEY_PUT(match, tun_key.ipv4_tos,
					nla_get_u8(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_TTL:
			SW_FLOW_KEY_PUT(match, tun_key.ipv4_ttl,
					nla_get_u8(a), is_mask);
			ttl = true;
			break;
		case OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT:
			tun_flags |= TUNNEL_DONT_FRAGMENT;
			break;
		case OVS_TUNNEL_KEY_ATTR_CSUM:
			tun_flags |= TUNNEL_CSUM;
			break;
		case OVS_TUNNEL_KEY_ATTR_TP_SRC:
			SW_FLOW_KEY_PUT(match, tun_key.tp_src,
					nla_get_be16(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_TP_DST:
			SW_FLOW_KEY_PUT(match, tun_key.tp_dst,
					nla_get_be16(a), is_mask);
			break;
		case OVS_TUNNEL_KEY_ATTR_OAM:
			tun_flags |= TUNNEL_OAM;
			break;
		case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
			if (opts_type) {
				OVS_NLERR(log, "Multiple metadata blocks provided");
				return -EINVAL;
			}

			err = genev_tun_opt_from_nlattr(a, match, is_mask, log);
			if (err)
				return err;

			tun_flags |= TUNNEL_GENEVE_OPT;
			opts_type = type;
			break;
		case OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS:
			if (opts_type) {
				OVS_NLERR(log, "Multiple metadata blocks provided");
				return -EINVAL;
			}

			err = vxlan_tun_opt_from_nlattr(a, match, is_mask, log);
			if (err)
				return err;

			tun_flags |= TUNNEL_VXLAN_OPT;
			opts_type = type;
			break;
		default:
			OVS_NLERR(log, "Unknown IPv4 tunnel attribute %d",
				  type);
			return -EINVAL;
		}
	}

	SW_FLOW_KEY_PUT(match, tun_key.tun_flags, tun_flags, is_mask);

	/* 遍历后仍有剩余字节表示属性畸形 */
	if (rem > 0) {
		OVS_NLERR(log, "IPv4 tunnel attribute has %d unknown bytes.",
			  rem);
		return -EINVAL;
	}

	/* 只有真实 key（非 mask）才强制要求隧道目的地址和 TTL 存在 */
	if (!is_mask) {
		if (!match->key->tun_key.ipv4_dst) {
			OVS_NLERR(log, "IPv4 tunnel dst address is zero");
			return -EINVAL;
		}

		if (!ttl) {
			OVS_NLERR(log, "IPv4 tunnel TTL not specified.");
			return -EINVAL;
		}
	}

	return opts_type;
}

/*
 * vxlan_opt_to_nlattr - 序列化 VXLAN 选项到 skb（嵌套一层
 * OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS，内含 GBP）。dump 方向使用。
 */
static int vxlan_opt_to_nlattr(struct sk_buff *skb,
			       const void *tun_opts, int swkey_tun_opts_len)
{
	const struct ovs_vxlan_opts *opts = tun_opts;
	struct nlattr *nla;

	nla = nla_nest_start(skb, OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS);
	if (!nla)
		return -EMSGSIZE;

	if (nla_put_u32(skb, OVS_VXLAN_EXT_GBP, opts->gbp) < 0)
		return -EMSGSIZE;

	nla_nest_end(skb, nla);
	return 0;
}

/*
 * __ipv4_tun_to_nlattr - 把内核的 ovs_key_ipv4_tunnel 序列化成一串
 * OVS_TUNNEL_KEY_ATTR_* 属性写入 skb。
 * 序列化遵循“省略默认/零值”原则：源地址、TOS、端口等为 0 时不输出，
 * 以缩小报文；TTL 总是输出（0 也可能有意义）。标志位对应 nla_put_flag。
 * tun_opts 非空时按 GENEVE/VXLAN 追加选项。
 */
static int __ipv4_tun_to_nlattr(struct sk_buff *skb,
				const struct ovs_key_ipv4_tunnel *output,
				const void *tun_opts, int swkey_tun_opts_len)
{
	if (output->tun_flags & TUNNEL_KEY &&
	    nla_put_be64(skb, OVS_TUNNEL_KEY_ATTR_ID, output->tun_id))
		return -EMSGSIZE;
	if (output->ipv4_src &&
	    nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, output->ipv4_src))
		return -EMSGSIZE;
	if (output->ipv4_dst &&
	    nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_DST, output->ipv4_dst))
		return -EMSGSIZE;
	if (output->ipv4_tos &&
	    nla_put_u8(skb, OVS_TUNNEL_KEY_ATTR_TOS, output->ipv4_tos))
		return -EMSGSIZE;
	if (nla_put_u8(skb, OVS_TUNNEL_KEY_ATTR_TTL, output->ipv4_ttl))
		return -EMSGSIZE;
	if ((output->tun_flags & TUNNEL_DONT_FRAGMENT) &&
	    nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT))
		return -EMSGSIZE;
	if ((output->tun_flags & TUNNEL_CSUM) &&
	    nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_CSUM))
		return -EMSGSIZE;
	if (output->tp_src &&
	    nla_put_be16(skb, OVS_TUNNEL_KEY_ATTR_TP_SRC, output->tp_src))
		return -EMSGSIZE;
	if (output->tp_dst &&
	    nla_put_be16(skb, OVS_TUNNEL_KEY_ATTR_TP_DST, output->tp_dst))
		return -EMSGSIZE;
	if ((output->tun_flags & TUNNEL_OAM) &&
	    nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_OAM))
		return -EMSGSIZE;
	if (tun_opts) {
		if (output->tun_flags & TUNNEL_GENEVE_OPT &&
		    nla_put(skb, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,
			    swkey_tun_opts_len, tun_opts))
			return -EMSGSIZE;
		else if (output->tun_flags & TUNNEL_VXLAN_OPT &&
			 vxlan_opt_to_nlattr(skb, tun_opts, swkey_tun_opts_len))
			return -EMSGSIZE;
	}

	return 0;
}

/* ipv4_tun_to_nlattr - 在外层再包一个 OVS_KEY_ATTR_TUNNEL 嵌套属性，
 * 内部调用 __ipv4_tun_to_nlattr 填充。用于 flow key 的 dump。 */
static int ipv4_tun_to_nlattr(struct sk_buff *skb,
			      const struct ovs_key_ipv4_tunnel *output,
			      const void *tun_opts, int swkey_tun_opts_len)
{
	struct nlattr *nla;
	int err;

	nla = nla_nest_start(skb, OVS_KEY_ATTR_TUNNEL);
	if (!nla)
		return -EMSGSIZE;

	err = __ipv4_tun_to_nlattr(skb, output, tun_opts, swkey_tun_opts_len);
	if (err)
		return err;

	nla_nest_end(skb, nla);
	return 0;
}

/* ovs_nla_put_egress_tunnel_key - 序列化出口隧道信息（不含外层 TUNNEL 嵌套），
 * 供 userspace 动作携带 egress tunnel 端口信息时使用。 */
int ovs_nla_put_egress_tunnel_key(struct sk_buff *skb,
				  const struct ovs_tunnel_info *egress_tun_info)
{
	return __ipv4_tun_to_nlattr(skb, &egress_tun_info->tunnel,
				    egress_tun_info->options,
				    egress_tun_info->options_len);
}

/*
 * metadata_from_nlattrs - 解析“元数据”类 key 属性（无法从报文本身提取，
 * 只能由用户态显式提供的字段）：dp_hash、recirc_id、priority、in_port、
 * skb_mark、tunnel。逐个解析并从 *attrs 位图里清除，供上层校验残余。
 * 被 ovs_key_from_nlattrs 和 ovs_nla_get_flow_metadata 复用。
 */
static int metadata_from_nlattrs(struct sw_flow_match *match,  u64 *attrs,
				 const struct nlattr **a, bool is_mask,
				 bool log)
{
	if (*attrs & (1 << OVS_KEY_ATTR_DP_HASH)) {
		u32 hash_val = nla_get_u32(a[OVS_KEY_ATTR_DP_HASH]);

		SW_FLOW_KEY_PUT(match, ovs_flow_hash, hash_val, is_mask);
		*attrs &= ~(1 << OVS_KEY_ATTR_DP_HASH);
	}

	if (*attrs & (1 << OVS_KEY_ATTR_RECIRC_ID)) {
		u32 recirc_id = nla_get_u32(a[OVS_KEY_ATTR_RECIRC_ID]);

		SW_FLOW_KEY_PUT(match, recirc_id, recirc_id, is_mask);
		*attrs &= ~(1 << OVS_KEY_ATTR_RECIRC_ID);
	}

	if (*attrs & (1 << OVS_KEY_ATTR_PRIORITY)) {
		SW_FLOW_KEY_PUT(match, phy.priority,
			  nla_get_u32(a[OVS_KEY_ATTR_PRIORITY]), is_mask);
		*attrs &= ~(1 << OVS_KEY_ATTR_PRIORITY);
	}

	if (*attrs & (1 << OVS_KEY_ATTR_IN_PORT)) {
		u32 in_port = nla_get_u32(a[OVS_KEY_ATTR_IN_PORT]);

		if (is_mask) {
			in_port = 0xffffffff; /* Always exact match in_port. */
		} else if (in_port >= DP_MAX_PORTS) {
			/* 端口号越界 */
			OVS_NLERR(log, "Port %d exceeds max allowable %d",
				  in_port, DP_MAX_PORTS);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, phy.in_port, in_port, is_mask);
		*attrs &= ~(1 << OVS_KEY_ATTR_IN_PORT);
	} else if (!is_mask) {
		/* key 未指定 in_port 时置为哨兵值 DP_MAX_PORTS（表示未知） */
		SW_FLOW_KEY_PUT(match, phy.in_port, DP_MAX_PORTS, is_mask);
	}

	if (*attrs & (1 << OVS_KEY_ATTR_SKB_MARK)) {
		uint32_t mark = nla_get_u32(a[OVS_KEY_ATTR_SKB_MARK]);

		SW_FLOW_KEY_PUT(match, phy.skb_mark, mark, is_mask);
		*attrs &= ~(1 << OVS_KEY_ATTR_SKB_MARK);
	}
	if (*attrs & (1 << OVS_KEY_ATTR_TUNNEL)) {
		if (ipv4_tun_from_nlattr(a[OVS_KEY_ATTR_TUNNEL], match,
					 is_mask, log) < 0)
			return -EINVAL;
		*attrs &= ~(1 << OVS_KEY_ATTR_TUNNEL);
	}
	return 0;
}

/*
 * ovs_key_from_nlattrs - 把已解析入 a[] 的各 OVS_KEY_ATTR_* 属性写入
 * sw_flow_key（或 mask->key）。先处理元数据，再按以太/网络/传输层
 * 逐类写入并从 attrs 清位，最后若 attrs 仍有残余则报“未知属性”错。
 * is_mask 决定写 key 还是 mask，且部分字段在 mask 侧强制精确匹配
 * （如 EtherType、in_port 恒为全 1）。
 */
static int ovs_key_from_nlattrs(struct sw_flow_match *match, u64 attrs,
				const struct nlattr **a, bool is_mask,
				bool log)
{
	int err;

	err = metadata_from_nlattrs(match, &attrs, a, is_mask, log);
	if (err)
		return err;

	if (attrs & (1 << OVS_KEY_ATTR_ETHERNET)) {
		const struct ovs_key_ethernet *eth_key;

		eth_key = nla_data(a[OVS_KEY_ATTR_ETHERNET]);
		SW_FLOW_KEY_MEMCPY(match, eth.src,
				eth_key->eth_src, ETH_ALEN, is_mask);
		SW_FLOW_KEY_MEMCPY(match, eth.dst,
				eth_key->eth_dst, ETH_ALEN, is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_ETHERNET);
	}

	if (attrs & (1 << OVS_KEY_ATTR_VLAN)) {
		__be16 tci;

		tci = nla_get_be16(a[OVS_KEY_ATTR_VLAN]);
		/* OVS 约定 VLAN TCI 必须带 VLAN_TAG_PRESENT 位 */
		if (!(tci & htons(VLAN_TAG_PRESENT))) {
			if (is_mask)
				OVS_NLERR(log, "VLAN TCI mask does not have exact match for VLAN_TAG_PRESENT bit.");
			else
				OVS_NLERR(log, "VLAN TCI does not have VLAN_TAG_PRESENT bit set.");

			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, eth.tci, tci, is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_VLAN);
	}

	if (attrs & (1 << OVS_KEY_ATTR_ETHERTYPE)) {
		__be16 eth_type;

		eth_type = nla_get_be16(a[OVS_KEY_ATTR_ETHERTYPE]);
		if (is_mask) {
			/* Always exact match EtherType. */
			eth_type = htons(0xffff);
		} else if (ntohs(eth_type) < ETH_P_802_3_MIN) {
			OVS_NLERR(log, "EtherType %x is less than min %x",
				  ntohs(eth_type), ETH_P_802_3_MIN);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, eth.type, eth_type, is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_ETHERTYPE);
	} else if (!is_mask) {
		/* key 未给 EtherType：默认按 802.2（无 EtherType 的 LLC 帧） */
		SW_FLOW_KEY_PUT(match, eth.type, htons(ETH_P_802_2), is_mask);
	}

	if (attrs & (1 << OVS_KEY_ATTR_IPV4)) {
		const struct ovs_key_ipv4 *ipv4_key;

		ipv4_key = nla_data(a[OVS_KEY_ATTR_IPV4]);
		if (!is_mask && ipv4_key->ipv4_frag > OVS_FRAG_TYPE_MAX) {
			OVS_NLERR(log, "IPv4 frag type %d is out of range max %d",
				  ipv4_key->ipv4_frag, OVS_FRAG_TYPE_MAX);
			return -EINVAL;
		}
		SW_FLOW_KEY_PUT(match, ip.proto,
				ipv4_key->ipv4_proto, is_mask);
		SW_FLOW_KEY_PUT(match, ip.tos,
				ipv4_key->ipv4_tos, is_mask);
		SW_FLOW_KEY_PUT(match, ip.ttl,
				ipv4_key->ipv4_ttl, is_mask);
		SW_FLOW_KEY_PUT(match, ip.frag,
				ipv4_key->ipv4_frag, is_mask);
		SW_FLOW_KEY_PUT(match, ipv4.addr.src,
				ipv4_key->ipv4_src, is_mask);
		SW_FLOW_KEY_PUT(match, ipv4.addr.dst,
				ipv4_key->ipv4_dst, is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_IPV4);
	}

	if (attrs & (1 << OVS_KEY_ATTR_IPV6)) {
		const struct ovs_key_ipv6 *ipv6_key;

		ipv6_key = nla_data(a[OVS_KEY_ATTR_IPV6]);
		if (!is_mask && ipv6_key->ipv6_frag > OVS_FRAG_TYPE_MAX) {
			OVS_NLERR(log, "IPv6 frag type %d is out of range max %d",
				  ipv6_key->ipv6_frag, OVS_FRAG_TYPE_MAX);
			return -EINVAL;
		}

		if (!is_mask && ipv6_key->ipv6_label & htonl(0xFFF00000)) {
			OVS_NLERR(log, "IPv6 flow label %x is out of range (max=%x).\n",
				  ntohl(ipv6_key->ipv6_label), (1 << 20) - 1);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, ipv6.label,
				ipv6_key->ipv6_label, is_mask);
		SW_FLOW_KEY_PUT(match, ip.proto,
				ipv6_key->ipv6_proto, is_mask);
		SW_FLOW_KEY_PUT(match, ip.tos,
				ipv6_key->ipv6_tclass, is_mask);
		SW_FLOW_KEY_PUT(match, ip.ttl,
				ipv6_key->ipv6_hlimit, is_mask);
		SW_FLOW_KEY_PUT(match, ip.frag,
				ipv6_key->ipv6_frag, is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.addr.src,
				ipv6_key->ipv6_src,
				sizeof(match->key->ipv6.addr.src),
				is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.addr.dst,
				ipv6_key->ipv6_dst,
				sizeof(match->key->ipv6.addr.dst),
				is_mask);

		attrs &= ~(1 << OVS_KEY_ATTR_IPV6);
	}

	if (attrs & (1 << OVS_KEY_ATTR_ARP)) {
		const struct ovs_key_arp *arp_key;

		arp_key = nla_data(a[OVS_KEY_ATTR_ARP]);
		if (!is_mask && (arp_key->arp_op & htons(0xff00))) {
			OVS_NLERR(log, "Unknown ARP opcode (opcode=%d).",
				  arp_key->arp_op);
			return -EINVAL;
		}

		SW_FLOW_KEY_PUT(match, ipv4.addr.src,
				arp_key->arp_sip, is_mask);
		SW_FLOW_KEY_PUT(match, ipv4.addr.dst,
			arp_key->arp_tip, is_mask);
		/* ARP opcode 借用 ip.proto 字段存储（复用 key 布局） */
		SW_FLOW_KEY_PUT(match, ip.proto,
				ntohs(arp_key->arp_op), is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv4.arp.sha,
				arp_key->arp_sha, ETH_ALEN, is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv4.arp.tha,
				arp_key->arp_tha, ETH_ALEN, is_mask);

		attrs &= ~(1 << OVS_KEY_ATTR_ARP);
	}

	if (attrs & (1 << OVS_KEY_ATTR_MPLS)) {
		const struct ovs_key_mpls *mpls_key;

		mpls_key = nla_data(a[OVS_KEY_ATTR_MPLS]);
		SW_FLOW_KEY_PUT(match, mpls.top_lse,
				mpls_key->mpls_lse, is_mask);

		attrs &= ~(1 << OVS_KEY_ATTR_MPLS);
	 }

	if (attrs & (1 << OVS_KEY_ATTR_TCP)) {
		const struct ovs_key_tcp *tcp_key;

		tcp_key = nla_data(a[OVS_KEY_ATTR_TCP]);
		SW_FLOW_KEY_PUT(match, tp.src, tcp_key->tcp_src, is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst, tcp_key->tcp_dst, is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_TCP);
	}

	if (attrs & (1 << OVS_KEY_ATTR_TCP_FLAGS)) {
		SW_FLOW_KEY_PUT(match, tp.flags,
				nla_get_be16(a[OVS_KEY_ATTR_TCP_FLAGS]),
				is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_TCP_FLAGS);
	}

	if (attrs & (1 << OVS_KEY_ATTR_UDP)) {
		const struct ovs_key_udp *udp_key;

		udp_key = nla_data(a[OVS_KEY_ATTR_UDP]);
		SW_FLOW_KEY_PUT(match, tp.src, udp_key->udp_src, is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst, udp_key->udp_dst, is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_UDP);
	}

	if (attrs & (1 << OVS_KEY_ATTR_SCTP)) {
		const struct ovs_key_sctp *sctp_key;

		sctp_key = nla_data(a[OVS_KEY_ATTR_SCTP]);
		SW_FLOW_KEY_PUT(match, tp.src, sctp_key->sctp_src, is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst, sctp_key->sctp_dst, is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_SCTP);
	}

	if (attrs & (1 << OVS_KEY_ATTR_ICMP)) {
		const struct ovs_key_icmp *icmp_key;

		icmp_key = nla_data(a[OVS_KEY_ATTR_ICMP]);
		SW_FLOW_KEY_PUT(match, tp.src,
				htons(icmp_key->icmp_type), is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst,
				htons(icmp_key->icmp_code), is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_ICMP);
	}

	if (attrs & (1 << OVS_KEY_ATTR_ICMPV6)) {
		const struct ovs_key_icmpv6 *icmpv6_key;

		icmpv6_key = nla_data(a[OVS_KEY_ATTR_ICMPV6]);
		SW_FLOW_KEY_PUT(match, tp.src,
				htons(icmpv6_key->icmpv6_type), is_mask);
		SW_FLOW_KEY_PUT(match, tp.dst,
				htons(icmpv6_key->icmpv6_code), is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_ICMPV6);
	}

	if (attrs & (1 << OVS_KEY_ATTR_ND)) {
		const struct ovs_key_nd *nd_key;

		nd_key = nla_data(a[OVS_KEY_ATTR_ND]);
		SW_FLOW_KEY_MEMCPY(match, ipv6.nd.target,
			nd_key->nd_target,
			sizeof(match->key->ipv6.nd.target),
			is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.nd.sll,
			nd_key->nd_sll, ETH_ALEN, is_mask);
		SW_FLOW_KEY_MEMCPY(match, ipv6.nd.tll,
				nd_key->nd_tll, ETH_ALEN, is_mask);
		attrs &= ~(1 << OVS_KEY_ATTR_ND);
	}

	if (attrs != 0) {
		/* 解析完仍有未清除的属性，说明存在不支持/多余的 key */
		OVS_NLERR(log, "Unknown key attributes %llx",
			  (unsigned long long)attrs);
		return -EINVAL;
	}

	return 0;
}

/*
 * nlattr_set - 递归地把一串（可能嵌套的）属性的 payload 全部 memset 为 val。
 * 用于从 key 属性流克隆出“精确匹配掩码”：把值全置 0xff。tbl 提供嵌套判定，
 * 遇到嵌套属性则带上其内层长度表递归下去。
 */
static void nlattr_set(struct nlattr *attr, u8 val,
		       const struct ovs_len_tbl *tbl)
{
	struct nlattr *nla;
	int rem;

	/* The nlattr stream should already have been validated */
	/* 此前已校验过属性流，这里不再检查长度 */
	nla_for_each_nested(nla, attr, rem) {
		if (tbl && tbl[nla_type(nla)].len == OVS_ATTR_NESTED)
			nlattr_set(nla, val, tbl[nla_type(nla)].next);
		else
			memset(nla_data(nla), val, nla_len(nla));
	}
}

/* mask_set_nlattr - 以顶层 key 长度表为起点，把属性流整体设为 val */
static void mask_set_nlattr(struct nlattr *attr, u8 val)
{
	nlattr_set(attr, val, ovs_key_lens);
}

/**
 * ovs_nla_get_match - parses Netlink attributes into a flow key and
 * mask. In case the 'mask' is NULL, the flow is treated as exact match
 * flow. Otherwise, it is treated as a wildcarded flow, except the mask
 * does not include any don't care bit.
 * @match: receives the extracted flow match information.
 * @key: Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink attribute
 * sequence. The fields should of the packet that triggered the creation
 * of this flow.
 * @mask: Optional. Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink
 * attribute specifies the mask field of the wildcarded flow.
 * @log: Boolean to allow kernel error logging.  Normally true, but when
 * probing for feature compatibility this should be passed in as false to
 * suppress unnecessary error logging.
 */
int ovs_nla_get_match(struct sw_flow_match *match,
		      const struct nlattr *nla_key,
		      const struct nlattr *nla_mask,
		      bool log)
{
	const struct nlattr *a[OVS_KEY_ATTR_MAX + 1];
	const struct nlattr *encap;
	struct nlattr *newmask = NULL;
	u64 key_attrs = 0;
	u64 mask_attrs = 0;
	bool encap_valid = false;
	int err;

	err = parse_flow_nlattrs(nla_key, a, &key_attrs, log);
	if (err)
		return err;

	/* 处理 802.1Q VLAN 帧：VLAN 帧的内层 key 属性被再包一层
	 * OVS_KEY_ATTR_ENCAP，需要先展开这层嵌套后继续解析。 */
	if ((key_attrs & (1 << OVS_KEY_ATTR_ETHERNET)) &&
	    (key_attrs & (1 << OVS_KEY_ATTR_ETHERTYPE)) &&
	    (nla_get_be16(a[OVS_KEY_ATTR_ETHERTYPE]) == htons(ETH_P_8021Q))) {
		__be16 tci;

		if (!((key_attrs & (1 << OVS_KEY_ATTR_VLAN)) &&
		      (key_attrs & (1 << OVS_KEY_ATTR_ENCAP)))) {
			OVS_NLERR(log, "Invalid Vlan frame.");
			return -EINVAL;
		}

		key_attrs &= ~(1 << OVS_KEY_ATTR_ETHERTYPE);
		tci = nla_get_be16(a[OVS_KEY_ATTR_VLAN]);
		encap = a[OVS_KEY_ATTR_ENCAP];
		key_attrs &= ~(1 << OVS_KEY_ATTR_ENCAP);
		encap_valid = true;

		if (tci & htons(VLAN_TAG_PRESENT)) {
			/* 正常带 tag：解析 encap 内的内层 key 属性 */
			err = parse_flow_nlattrs(encap, a, &key_attrs, log);
			if (err)
				return err;
		} else if (!tci) {
			/* Corner case for truncated 802.1Q header. */
			/* tci 为 0：802.1Q 头被截断的边角情况，encap 必须为空 */
			if (nla_len(encap)) {
				OVS_NLERR(log, "Truncated 802.1Q header has non-zero encap attribute.");
				return -EINVAL;
			}
		} else {
			OVS_NLERR(log, "Encap attr is set for non-VLAN frame");
			return  -EINVAL;
		}
	}

	/* 先解析 key（is_mask=false） */
	err = ovs_key_from_nlattrs(match, key_attrs, a, false, log);
	if (err)
		return err;

	if (match->mask) {
		if (!nla_mask) {
			/* Create an exact match mask. We need to set to 0xff
			 * all the 'match->mask' fields that have been touched
			 * in 'match->key'. We cannot simply memset
			 * 'match->mask', because padding bytes and fields not
			 * specified in 'match->key' should be left to 0.
			 * Instead, we use a stream of netlink attributes,
			 * copied from 'key' and set to 0xff.
			 * ovs_key_from_nlattrs() will take care of filling
			 * 'match->mask' appropriately.
			 */
			newmask = kmemdup(nla_key,
					  nla_total_size(nla_len(nla_key)),
					  GFP_KERNEL);
			if (!newmask)
				return -ENOMEM;

			mask_set_nlattr(newmask, 0xff);

			/* The userspace does not send tunnel attributes that
			 * are 0, but we should not wildcard them nonetheless.
			 */
			if (match->key->tun_key.ipv4_dst)
				SW_FLOW_KEY_MEMSET_FIELD(match, tun_key,
							 0xff, true);

			nla_mask = newmask;
		}

		err = parse_flow_mask_nlattrs(nla_mask, a, &mask_attrs, log);
		if (err)
			goto free_newmask;

		/* Always match on tci. */
		/* VLAN TCI 恒做精确匹配 */
		SW_FLOW_KEY_PUT(match, eth.tci, htons(0xffff), true);

		/* mask 侧同样要展开 VLAN encap 嵌套；且要求对 TPID 精确匹配 */
		if (mask_attrs & 1 << OVS_KEY_ATTR_ENCAP) {
			__be16 eth_type = 0;
			__be16 tci = 0;

			if (!encap_valid) {
				OVS_NLERR(log, "Encap mask attribute is set for non-VLAN frame.");
				err = -EINVAL;
				goto free_newmask;
			}

			mask_attrs &= ~(1 << OVS_KEY_ATTR_ENCAP);
			if (a[OVS_KEY_ATTR_ETHERTYPE])
				eth_type = nla_get_be16(a[OVS_KEY_ATTR_ETHERTYPE]);

			if (eth_type == htons(0xffff)) {
				mask_attrs &= ~(1 << OVS_KEY_ATTR_ETHERTYPE);
				encap = a[OVS_KEY_ATTR_ENCAP];
				err = parse_flow_mask_nlattrs(encap, a,
							      &mask_attrs, log);
				if (err)
					goto free_newmask;
			} else {
				OVS_NLERR(log, "VLAN frames must have an exact match on the TPID (mask=%x).",
					  ntohs(eth_type));
				err = -EINVAL;
				goto free_newmask;
			}

			if (a[OVS_KEY_ATTR_VLAN])
				tci = nla_get_be16(a[OVS_KEY_ATTR_VLAN]);

			if (!(tci & htons(VLAN_TAG_PRESENT))) {
				OVS_NLERR(log, "VLAN tag present bit must have an exact match (tci_mask=%x).",
					  ntohs(tci));
				err = -EINVAL;
				goto free_newmask;
			}
		}

		err = ovs_key_from_nlattrs(match, mask_attrs, a, true, log);
		if (err)
			goto free_newmask;
	}

	/* key/mask 组合的最终自洽性校验 */
	if (!match_validate(match, key_attrs, mask_attrs, log))
		err = -EINVAL;

free_newmask:
	kfree(newmask);
	return err;
}

/* get_ufid_len - 读取并校验 UFID 属性长度（1..MAX_UFID_LENGTH），
 * 非法返回 0。UFID 是用户态给流分配的唯一标识，可替代整条 key 作索引。 */
static size_t get_ufid_len(const struct nlattr *attr, bool log)
{
	size_t len;

	if (!attr)
		return 0;

	len = nla_len(attr);
	if (len < 1 || len > MAX_UFID_LENGTH) {
		OVS_NLERR(log, "ufid size %u bytes exceeds the range (1, %d)",
			  nla_len(attr), MAX_UFID_LENGTH);
		return 0;
	}

	return len;
}

/* Initializes 'flow->ufid', returning true if 'attr' contains a valid UFID,
 * or false otherwise.
 */
bool ovs_nla_get_ufid(struct sw_flow_id *sfid, const struct nlattr *attr,
		      bool log)
{
	sfid->ufid_len = get_ufid_len(attr, log);
	if (sfid->ufid_len)
		memcpy(sfid->ufid, nla_data(attr), sfid->ufid_len);

	return sfid->ufid_len;
}

/*
 * ovs_nla_get_identifier - 确定流的标识 (sw_flow_id)。
 * 若用户态提供了合法 UFID 则用之；否则回退为“存一份未掩码的 key”作标识。
 */
int ovs_nla_get_identifier(struct sw_flow_id *sfid, const struct nlattr *ufid,
			   const struct sw_flow_key *key, bool log)
{
	struct sw_flow_key *new_key;

	if (ovs_nla_get_ufid(sfid, ufid, log))
		return 0;

	/* If UFID was not provided, use unmasked key. */
	/* 没有 UFID：复制一份未掩码 key 作为标识 */
	new_key = kmalloc(sizeof(*new_key), GFP_KERNEL);
	if (!new_key)
		return -ENOMEM;
	memcpy(new_key, key, sizeof(*key));
	sfid->unmasked_key = new_key;

	return 0;
}

/* 读取 UFID 标志属性（如 dump 时的过滤标志），缺省为 0 */
u32 ovs_nla_get_ufid_flags(const struct nlattr *attr)
{
	return attr ? nla_get_u32(attr) : 0;
}

/**
 * ovs_nla_get_flow_metadata - parses Netlink attributes into a flow key.
 * @key: Receives extracted in_port, priority, tun_key and skb_mark.
 * @attr: Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink attribute
 * sequence.
 * @log: Boolean to allow kernel error logging.  Normally true, but when
 * probing for feature compatibility this should be passed in as false to
 * suppress unnecessary error logging.
 *
 * This parses a series of Netlink attributes that form a flow key, which must
 * take the same form accepted by flow_from_nlattrs(), but only enough of it to
 * get the metadata, that is, the parts of the flow key that cannot be
 * extracted from the packet itself.
 */

int ovs_nla_get_flow_metadata(const struct nlattr *attr,
			      struct sw_flow_key *key,
			      bool log)
{
	const struct nlattr *a[OVS_KEY_ATTR_MAX + 1];
	struct sw_flow_match match;
	u64 attrs = 0;
	int err;

	err = parse_flow_nlattrs(attr, a, &attrs, log);
	if (err)
		return -EINVAL;

	memset(&match, 0, sizeof(match));
	match.key = key;

	/* 默认 in_port 为未知哨兵，metadata_from_nlattrs 可能覆盖它 */
	key->phy.in_port = DP_MAX_PORTS;

	return metadata_from_nlattrs(&match, &attrs, a, false, log);
}

/*
 * __ovs_nla_put_key - 把一个 sw_flow_key（key 或 mask）序列化成一串
 * OVS_KEY_ATTR_* 属性写入 skb。这是 dump 方向的核心。
 * swkey 提供“类型判定”依据（如以太类型决定要不要输出 IPv4/IPv6 子属性），
 * output 提供实际输出的值（is_mask 时是掩码值）。
 * 任一 nla_put 失败即跳到 nla_put_failure 返回 -EMSGSIZE。
 */
static int __ovs_nla_put_key(const struct sw_flow_key *swkey,
			     const struct sw_flow_key *output, bool is_mask,
			     struct sk_buff *skb)
{
	struct ovs_key_ethernet *eth_key;
	struct nlattr *nla, *encap;

	if (nla_put_u32(skb, OVS_KEY_ATTR_RECIRC_ID, output->recirc_id))
		goto nla_put_failure;

	if (nla_put_u32(skb, OVS_KEY_ATTR_DP_HASH, output->ovs_flow_hash))
		goto nla_put_failure;

	if (nla_put_u32(skb, OVS_KEY_ATTR_PRIORITY, output->phy.priority))
		goto nla_put_failure;

	/* 有隧道目的地址（或正在输出 mask）时才输出隧道 key。
	 * TUNNEL_OPTIONS_PRESENT 表示带 GENEVE/VXLAN 选项，需一并序列化。 */
	if ((swkey->tun_key.ipv4_dst || is_mask)) {
		const void *opts = NULL;

		if (output->tun_key.tun_flags & TUNNEL_OPTIONS_PRESENT)
			opts = TUN_METADATA_OPTS(output, swkey->tun_opts_len);

		if (ipv4_tun_to_nlattr(skb, &output->tun_key, opts,
				       swkey->tun_opts_len))
			goto nla_put_failure;
	}

	if (swkey->phy.in_port == DP_MAX_PORTS) {
		/* in_port 为哨兵（未知）：仅当 mask 精确匹配时输出全 1 */
		if (is_mask && (output->phy.in_port == 0xffff))
			if (nla_put_u32(skb, OVS_KEY_ATTR_IN_PORT, 0xffffffff))
				goto nla_put_failure;
	} else {
		u16 upper_u16;
		/* mask 侧高 16 位补 0xffff，表示对 in_port 精确匹配 */
		upper_u16 = !is_mask ? 0 : 0xffff;

		if (nla_put_u32(skb, OVS_KEY_ATTR_IN_PORT,
				(upper_u16 << 16) | output->phy.in_port))
			goto nla_put_failure;
	}

	if (nla_put_u32(skb, OVS_KEY_ATTR_SKB_MARK, output->phy.skb_mark))
		goto nla_put_failure;

	nla = nla_reserve(skb, OVS_KEY_ATTR_ETHERNET, sizeof(*eth_key));
	if (!nla)
		goto nla_put_failure;

	eth_key = nla_data(nla);
	ether_addr_copy(eth_key->eth_src, output->eth.src);
	ether_addr_copy(eth_key->eth_dst, output->eth.dst);

	/* 带 VLAN 时输出 8021Q 的 ETHERTYPE + VLAN TCI，并开一层 ENCAP 嵌套
	 * 以承载内层 key。tci 为 0 是截断 VLAN 的边角情况，直接收尾。 */
	if (swkey->eth.tci || swkey->eth.type == htons(ETH_P_8021Q)) {
		__be16 eth_type;
		eth_type = !is_mask ? htons(ETH_P_8021Q) : htons(0xffff);
		if (nla_put_be16(skb, OVS_KEY_ATTR_ETHERTYPE, eth_type) ||
		    nla_put_be16(skb, OVS_KEY_ATTR_VLAN, output->eth.tci))
			goto nla_put_failure;
		encap = nla_nest_start(skb, OVS_KEY_ATTR_ENCAP);
		if (!swkey->eth.tci)
			goto unencap;
	} else
		encap = NULL;

	if (swkey->eth.type == htons(ETH_P_802_2)) {
		/*
		 * Ethertype 802.2 is represented in the netlink with omitted
		 * OVS_KEY_ATTR_ETHERTYPE in the flow key attribute, and
		 * 0xffff in the mask attribute.  Ethertype can also
		 * be wildcarded.
		 */
		if (is_mask && output->eth.type)
			if (nla_put_be16(skb, OVS_KEY_ATTR_ETHERTYPE,
						output->eth.type))
				goto nla_put_failure;
		goto unencap;
	}

	if (nla_put_be16(skb, OVS_KEY_ATTR_ETHERTYPE, output->eth.type))
		goto nla_put_failure;

	/* 根据以太类型输出对应的 L3 key 子属性（互斥的一组） */
	if (swkey->eth.type == htons(ETH_P_IP)) {
		struct ovs_key_ipv4 *ipv4_key;

		nla = nla_reserve(skb, OVS_KEY_ATTR_IPV4, sizeof(*ipv4_key));
		if (!nla)
			goto nla_put_failure;
		ipv4_key = nla_data(nla);
		ipv4_key->ipv4_src = output->ipv4.addr.src;
		ipv4_key->ipv4_dst = output->ipv4.addr.dst;
		ipv4_key->ipv4_proto = output->ip.proto;
		ipv4_key->ipv4_tos = output->ip.tos;
		ipv4_key->ipv4_ttl = output->ip.ttl;
		ipv4_key->ipv4_frag = output->ip.frag;
	} else if (swkey->eth.type == htons(ETH_P_IPV6)) {
		struct ovs_key_ipv6 *ipv6_key;

		nla = nla_reserve(skb, OVS_KEY_ATTR_IPV6, sizeof(*ipv6_key));
		if (!nla)
			goto nla_put_failure;
		ipv6_key = nla_data(nla);
		memcpy(ipv6_key->ipv6_src, &output->ipv6.addr.src,
				sizeof(ipv6_key->ipv6_src));
		memcpy(ipv6_key->ipv6_dst, &output->ipv6.addr.dst,
				sizeof(ipv6_key->ipv6_dst));
		ipv6_key->ipv6_label = output->ipv6.label;
		ipv6_key->ipv6_proto = output->ip.proto;
		ipv6_key->ipv6_tclass = output->ip.tos;
		ipv6_key->ipv6_hlimit = output->ip.ttl;
		ipv6_key->ipv6_frag = output->ip.frag;
	} else if (swkey->eth.type == htons(ETH_P_ARP) ||
		   swkey->eth.type == htons(ETH_P_RARP)) {
		struct ovs_key_arp *arp_key;

		nla = nla_reserve(skb, OVS_KEY_ATTR_ARP, sizeof(*arp_key));
		if (!nla)
			goto nla_put_failure;
		arp_key = nla_data(nla);
		memset(arp_key, 0, sizeof(struct ovs_key_arp));
		arp_key->arp_sip = output->ipv4.addr.src;
		arp_key->arp_tip = output->ipv4.addr.dst;
		arp_key->arp_op = htons(output->ip.proto);
		ether_addr_copy(arp_key->arp_sha, output->ipv4.arp.sha);
		ether_addr_copy(arp_key->arp_tha, output->ipv4.arp.tha);
	} else if (eth_p_mpls(swkey->eth.type)) {
		struct ovs_key_mpls *mpls_key;

		nla = nla_reserve(skb, OVS_KEY_ATTR_MPLS, sizeof(*mpls_key));
		if (!nla)
			goto nla_put_failure;
		mpls_key = nla_data(nla);
		mpls_key->mpls_lse = output->mpls.top_lse;
	}

	if ((swkey->eth.type == htons(ETH_P_IP) ||
	     swkey->eth.type == htons(ETH_P_IPV6)) &&
	     swkey->ip.frag != OVS_FRAG_TYPE_LATER) {

		/* 非分片后续片才有 L4 头，按协议输出 TCP/UDP/SCTP/ICMP 子属性 */
		if (swkey->ip.proto == IPPROTO_TCP) {
			struct ovs_key_tcp *tcp_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_TCP, sizeof(*tcp_key));
			if (!nla)
				goto nla_put_failure;
			tcp_key = nla_data(nla);
			tcp_key->tcp_src = output->tp.src;
			tcp_key->tcp_dst = output->tp.dst;
			if (nla_put_be16(skb, OVS_KEY_ATTR_TCP_FLAGS,
					 output->tp.flags))
				goto nla_put_failure;
		} else if (swkey->ip.proto == IPPROTO_UDP) {
			struct ovs_key_udp *udp_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_UDP, sizeof(*udp_key));
			if (!nla)
				goto nla_put_failure;
			udp_key = nla_data(nla);
			udp_key->udp_src = output->tp.src;
			udp_key->udp_dst = output->tp.dst;
		} else if (swkey->ip.proto == IPPROTO_SCTP) {
			struct ovs_key_sctp *sctp_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_SCTP, sizeof(*sctp_key));
			if (!nla)
				goto nla_put_failure;
			sctp_key = nla_data(nla);
			sctp_key->sctp_src = output->tp.src;
			sctp_key->sctp_dst = output->tp.dst;
		} else if (swkey->eth.type == htons(ETH_P_IP) &&
			   swkey->ip.proto == IPPROTO_ICMP) {
			struct ovs_key_icmp *icmp_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_ICMP, sizeof(*icmp_key));
			if (!nla)
				goto nla_put_failure;
			icmp_key = nla_data(nla);
			icmp_key->icmp_type = ntohs(output->tp.src);
			icmp_key->icmp_code = ntohs(output->tp.dst);
		} else if (swkey->eth.type == htons(ETH_P_IPV6) &&
			   swkey->ip.proto == IPPROTO_ICMPV6) {
			struct ovs_key_icmpv6 *icmpv6_key;

			nla = nla_reserve(skb, OVS_KEY_ATTR_ICMPV6,
						sizeof(*icmpv6_key));
			if (!nla)
				goto nla_put_failure;
			icmpv6_key = nla_data(nla);
			icmpv6_key->icmpv6_type = ntohs(output->tp.src);
			icmpv6_key->icmpv6_code = ntohs(output->tp.dst);

			if (icmpv6_key->icmpv6_type == NDISC_NEIGHBOUR_SOLICITATION ||
			    icmpv6_key->icmpv6_type == NDISC_NEIGHBOUR_ADVERTISEMENT) {
				struct ovs_key_nd *nd_key;

				nla = nla_reserve(skb, OVS_KEY_ATTR_ND, sizeof(*nd_key));
				if (!nla)
					goto nla_put_failure;
				nd_key = nla_data(nla);
				memcpy(nd_key->nd_target, &output->ipv6.nd.target,
							sizeof(nd_key->nd_target));
				ether_addr_copy(nd_key->nd_sll, output->ipv6.nd.sll);
				ether_addr_copy(nd_key->nd_tll, output->ipv6.nd.tll);
			}
		}
	}

unencap:
	/* 收尾 VLAN 的 ENCAP 嵌套 */
	if (encap)
		nla_nest_end(skb, encap);

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

/*
 * ovs_nla_put_key - 在外层加一个属性 (attr, 如 OVS_FLOW_ATTR_KEY/MASK) 的
 * 嵌套，把 key 序列化进去。是 __ovs_nla_put_key 的对外包装。
 */
int ovs_nla_put_key(const struct sw_flow_key *swkey,
		    const struct sw_flow_key *output, int attr, bool is_mask,
		    struct sk_buff *skb)
{
	int err;
	struct nlattr *nla;

	nla = nla_nest_start(skb, attr);
	if (!nla)
		return -EMSGSIZE;
	err = __ovs_nla_put_key(swkey, output, is_mask, skb);
	if (err)
		return err;
	nla_nest_end(skb, nla);

	return 0;
}

/* Called with ovs_mutex or RCU read lock. */
/* dump 流标识：有 UFID 用 UFID，否则输出未掩码 key 作为 OVS_FLOW_ATTR_KEY */
int ovs_nla_put_identifier(const struct sw_flow *flow, struct sk_buff *skb)
{
	if (ovs_identifier_is_ufid(&flow->id))
		return nla_put(skb, OVS_FLOW_ATTR_UFID, flow->id.ufid_len,
			       flow->id.ufid);

	return ovs_nla_put_key(flow->id.unmasked_key, flow->id.unmasked_key,
			       OVS_FLOW_ATTR_KEY, false, skb);
}

/* Called with ovs_mutex or RCU read lock. */
/* dump 已掩码的 key（即真正参与匹配的 key），作为 OVS_FLOW_ATTR_KEY */
int ovs_nla_put_masked_key(const struct sw_flow *flow, struct sk_buff *skb)
{
	return ovs_nla_put_key(&flow->key, &flow->key,
				OVS_FLOW_ATTR_KEY, false, skb);
}

/* Called with ovs_mutex or RCU read lock. */
/* dump 掩码：swkey 用 flow->key 判类型，output 用 mask->key 输出掩码值 */
int ovs_nla_put_mask(const struct sw_flow *flow, struct sk_buff *skb)
{
	return ovs_nla_put_key(&flow->key, &flow->mask->key,
				OVS_FLOW_ATTR_MASK, true, skb);
}

/* actions 缓冲的最大字节数（32KB），防止用户态构造过大动作链 */
#define MAX_ACTIONS_BUFSIZE	(32 * 1024)

/*
 * nla_alloc_flow_actions - 分配一个 sw_flow_actions 缓冲（含 size 字节动作区）。
 * 动作以“打平的 netlink 属性流”形式存放在 sfa->actions 中。
 */
static struct sw_flow_actions *nla_alloc_flow_actions(int size, bool log)
{
	struct sw_flow_actions *sfa;

	if (size > MAX_ACTIONS_BUFSIZE) {
		OVS_NLERR(log, "Flow action size %u bytes exceeds max", size);
		return ERR_PTR(-EINVAL);
	}

	sfa = kmalloc(sizeof(*sfa) + size, GFP_KERNEL);
	if (!sfa)
		return ERR_PTR(-ENOMEM);

	sfa->actions_len = 0;
	return sfa;
}

/* Schedules 'sf_acts' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
/* 通过 RCU 延迟释放 actions 缓冲，保证并发读者在宽限期内安全访问 */
void ovs_nla_free_flow_actions(struct sw_flow_actions *sf_acts)
{
	kfree_rcu(sf_acts, rcu);
}

/*
 * reserve_sfa_size - 在 actions 缓冲末尾预留 attr_len（对齐后）字节空间。
 * 空间不足时按 2 倍扩容（上限 MAX_ACTIONS_BUFSIZE），拷贝旧内容并释放旧缓冲。
 * 返回指向新预留区起始处的 nlattr 指针；调用者随后填充属性头和数据。
 * 注意 *sfa 可能被替换，故用二级指针。
 */
static struct nlattr *reserve_sfa_size(struct sw_flow_actions **sfa,
				       int attr_len, bool log)
{

	struct sw_flow_actions *acts;
	int new_acts_size;
	int req_size = NLA_ALIGN(attr_len);
	int next_offset = offsetof(struct sw_flow_actions, actions) +
					(*sfa)->actions_len;

	/* 现有 slab 对象剩余空间够用则直接使用 */
	if (req_size <= (ksize(*sfa) - next_offset))
		goto out;

	new_acts_size = ksize(*sfa) * 2;

	/* 扩容不超过上限；若翻倍超限则尽量取到上限，仍不够则报错 */
	if (new_acts_size > MAX_ACTIONS_BUFSIZE) {
		if ((MAX_ACTIONS_BUFSIZE - next_offset) < req_size)
			return ERR_PTR(-EMSGSIZE);
		new_acts_size = MAX_ACTIONS_BUFSIZE;
	}

	acts = nla_alloc_flow_actions(new_acts_size, log);
	if (IS_ERR(acts))
		return (void *)acts;

	memcpy(acts->actions, (*sfa)->actions, (*sfa)->actions_len);
	acts->actions_len = (*sfa)->actions_len;
	kfree(*sfa);
	*sfa = acts;

out:
	(*sfa)->actions_len += req_size;
	return  (struct nlattr *) ((unsigned char *)(*sfa) + next_offset);
}

/*
 * __add_action - 在 actions 缓冲里追加一个属性 (attrtype + data)，
 * 返回新属性的 nlattr 指针（失败返回 ERR_PTR）。data 为 NULL 时只留头，
 * 尾部填充字节清零。
 */
static struct nlattr *__add_action(struct sw_flow_actions **sfa,
				   int attrtype, void *data, int len, bool log)
{
	struct nlattr *a;

	a = reserve_sfa_size(sfa, nla_attr_size(len), log);
	if (IS_ERR(a))
		return a;

	a->nla_type = attrtype;
	a->nla_len = nla_attr_size(len);

	if (data)
		memcpy(nla_data(a), data, len);
	memset((unsigned char *) a + a->nla_len, 0, nla_padlen(len));

	return a;
}

/* add_action - __add_action 的简化包装，只返回错误码（不关心 nlattr 指针） */
static int add_action(struct sw_flow_actions **sfa, int attrtype,
		      void *data, int len, bool log)
{
	struct nlattr *a;

	a = __add_action(sfa, attrtype, data, len, log);

	return PTR_ERR_OR_ZERO(a);
}

/*
 * add_nested_action_start - 开始一个嵌套动作：先写一个长度暂为 0 的头，
 * 返回该头在 actions 区中的偏移，供 add_nested_action_end 回填长度。
 * 类似 nla_nest_start，但作用在 sw_flow_actions 缓冲上。
 */
static inline int add_nested_action_start(struct sw_flow_actions **sfa,
					  int attrtype, bool log)
{
	int used = (*sfa)->actions_len;
	int err;

	err = add_action(sfa, attrtype, NULL, 0, log);
	if (err)
		return err;

	return used;
}

/* add_nested_action_end - 回填嵌套头的长度（当前总长减去起始偏移） */
static inline void add_nested_action_end(struct sw_flow_actions *sfa,
					 int st_offset)
{
	struct nlattr *a = (struct nlattr *) ((unsigned char *)sfa->actions +
							       st_offset);

	a->nla_len = sfa->actions_len - st_offset;
}

/* __ovs_nla_copy_actions 的前置声明：与 validate_and_copy_sample 相互递归
 * （sample 动作内部还能嵌套动作链），故需先声明。 */
static int __ovs_nla_copy_actions(const struct nlattr *attr,
				  const struct sw_flow_key *key,
				  int depth, struct sw_flow_actions **sfa,
				  __be16 eth_type, __be16 vlan_tci, bool log);

/*
 * validate_and_copy_sample - 校验并拷贝 sample 动作。
 * sample = 概率 (OVS_SAMPLE_ATTR_PROBABILITY) + 一组嵌套动作
 * (OVS_SAMPLE_ATTR_ACTIONS)。递归调用 __ovs_nla_copy_actions 处理内层动作，
 * depth+1 用于限制嵌套深度防止栈溢出/环。
 */
static int validate_and_copy_sample(const struct nlattr *attr,
				    const struct sw_flow_key *key, int depth,
				    struct sw_flow_actions **sfa,
				    __be16 eth_type, __be16 vlan_tci, bool log)
{
	const struct nlattr *attrs[OVS_SAMPLE_ATTR_MAX + 1];
	const struct nlattr *probability, *actions;
	const struct nlattr *a;
	int rem, start, err, st_acts;

	memset(attrs, 0, sizeof(attrs));
	/* 遍历 sample 的两个子属性并去重存入 attrs[] */
	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		if (!type || type > OVS_SAMPLE_ATTR_MAX || attrs[type])
			return -EINVAL;
		attrs[type] = a;
	}
	if (rem)
		return -EINVAL;

	/* 概率属性必须存在且为 u32 */
	probability = attrs[OVS_SAMPLE_ATTR_PROBABILITY];
	if (!probability || nla_len(probability) != sizeof(u32))
		return -EINVAL;

	actions = attrs[OVS_SAMPLE_ATTR_ACTIONS];
	if (!actions || (nla_len(actions) && nla_len(actions) < NLA_HDRLEN))
		return -EINVAL;

	/* validation done, copy sample action. */
	/* 校验通过，开始把 sample 动作拷进 sfa 缓冲 */
	start = add_nested_action_start(sfa, OVS_ACTION_ATTR_SAMPLE, log);
	if (start < 0)
		return start;
	err = add_action(sfa, OVS_SAMPLE_ATTR_PROBABILITY,
			 nla_data(probability), sizeof(u32), log);
	if (err)
		return err;
	st_acts = add_nested_action_start(sfa, OVS_SAMPLE_ATTR_ACTIONS, log);
	if (st_acts < 0)
		return st_acts;

	err = __ovs_nla_copy_actions(actions, key, depth + 1, sfa,
				     eth_type, vlan_tci, log);
	if (err)
		return err;

	/* 依次回填内层 actions 与外层 sample 的长度 */
	add_nested_action_end(*sfa, st_acts);
	add_nested_action_end(*sfa, start);

	return 0;
}

/*
 * ovs_match_init - 初始化 sw_flow_match，清零 key（及 mask）并绑定指针。
 * 是外部构造 match 前的标准入口（datapath.c 在解析前调用）。
 */
void ovs_match_init(struct sw_flow_match *match,
		    struct sw_flow_key *key,
		    struct sw_flow_mask *mask)
{
	memset(match, 0, sizeof(*match));
	match->key = key;
	match->mask = mask;

	memset(key, 0, sizeof(*key));

	if (mask) {
		memset(&mask->key, 0, sizeof(mask->key));
		mask->range.start = mask->range.end = 0;
	}
}

/*
 * validate_geneve_opts - 校验 Geneve 选项 TLV 链的自洽性（逐个 option 的
 * 长度不越界），并检测是否含 critical 选项，置 TUNNEL_CRIT_OPT 标志。
 */
static int validate_geneve_opts(struct sw_flow_key *key)
{
	struct geneve_opt *option;
	int opts_len = key->tun_opts_len;
	bool crit_opt = false;

	option = (struct geneve_opt *)TUN_METADATA_OPTS(key, key->tun_opts_len);
	while (opts_len > 0) {
		int len;

		if (opts_len < sizeof(*option))
			return -EINVAL;

		len = sizeof(*option) + option->length * 4;
		if (len > opts_len)
			return -EINVAL;

		crit_opt |= !!(option->type & GENEVE_CRIT_OPT_TYPE);

		option = (struct geneve_opt *)((u8 *)option + len);
		opts_len -= len;
	};

	key->tun_key.tun_flags |= crit_opt ? TUNNEL_CRIT_OPT : 0;

	return 0;
}

/*
 * validate_and_copy_set_tun - 校验并拷贝 “set tunnel” 动作。
 * 复用 ipv4_tun_from_nlattr 解析隧道属性到临时 key，再把隧道信息
 * (ovs_tunnel_info + 选项) 作为 OVS_KEY_ATTR_TUNNEL_INFO 动作存入 sfa。
 * 由于流建立后原始属性会释放，选项数据被复制到 tun_info 之后并让
 * options 指向它，实现自包含存储。
 */
static int validate_and_copy_set_tun(const struct nlattr *attr,
				     struct sw_flow_actions **sfa, bool log)
{
	struct sw_flow_match match;
	struct sw_flow_key key;
	struct ovs_tunnel_info *tun_info;
	struct nlattr *a;
	int err = 0, start, opts_type;

	ovs_match_init(&match, &key, NULL);
	opts_type = ipv4_tun_from_nlattr(nla_data(attr), &match, false, log);
	if (opts_type < 0)
		return opts_type;

	if (key.tun_opts_len) {
		switch (opts_type) {
		case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS:
			err = validate_geneve_opts(&key);
			if (err < 0)
				return err;
			break;
		case OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS:
			break;
		}
	};

	start = add_nested_action_start(sfa, OVS_ACTION_ATTR_SET, log);
	if (start < 0)
		return start;

	a = __add_action(sfa, OVS_KEY_ATTR_TUNNEL_INFO, NULL,
			 sizeof(*tun_info) + key.tun_opts_len, log);
	if (IS_ERR(a))
		return PTR_ERR(a);

	tun_info = nla_data(a);
	tun_info->tunnel = key.tun_key;
	tun_info->options_len = key.tun_opts_len;

	if (tun_info->options_len) {
		/* We need to store the options in the action itself since
		 * everything else will go away after flow setup. We can append
		 * it to tun_info and then point there.
		 */
		memcpy((tun_info + 1),
		       TUN_METADATA_OPTS(&key, key.tun_opts_len), key.tun_opts_len);
		tun_info->options = (tun_info + 1);
	} else {
		tun_info->options = NULL;
	}

	add_nested_action_end(*sfa, start);

	return err;
}

/* Return false if there are any non-masked bits set.
 * Mask follows data immediately, before any netlink padding.
 */
/* validate_masked - 掩码合法性检查：数据区紧跟着同长的掩码区，若数据里
 * 存在“掩码未覆盖 (~mask)”却被置位的比特，则非法。防止用户设置了掩码外
 * 的比特（这些比特不会真正生效，属于错误用法）。 */
static bool validate_masked(u8 *data, int len)
{
	u8 *mask = data + len;

	while (len--)
		if (*data++ & ~*mask++)
			return false;

	return true;
}

/*
 * validate_set - 校验一个 set / set_masked 动作里被设置的 key 字段是否合法。
 * masked 为真时属性含“值+掩码”两段，key_len 取一半。
 * 校验点：字段类型/长度、目标字段必须与当前流的 L3/L4 类型匹配（如
 * 只有 IP+TCP 流才能 set TCP 字段）、不可写字段（proto/frag）不得被改。
 * 另外把“非掩码的普通 set”转换成“掩码 set (SET_TO_MASKED)”统一存储：
 * 掩码全 0xff 表示整字段覆盖，从而内核只需实现一种 masked-set 语义。
 * skip_copy 置真表示本动作已被本函数自行写入 sfa，外层不要再原样拷贝。
 */
static int validate_set(const struct nlattr *a,
			const struct sw_flow_key *flow_key,
			struct sw_flow_actions **sfa,
			bool *skip_copy, __be16 eth_type, bool masked, bool log)
{
	const struct nlattr *ovs_key = nla_data(a);
	int key_type = nla_type(ovs_key);
	size_t key_len;

	/* There can be only one key in a action */
	/* 一个 set 动作只能包含一个 key 属性 */
	if (nla_total_size(nla_len(ovs_key)) != nla_len(a))
		return -EINVAL;

	key_len = nla_len(ovs_key);
	if (masked)
		key_len /= 2;

	/* 类型越界或长度与期望不符则非法 */
	if (key_type > OVS_KEY_ATTR_MAX ||
	    (ovs_key_lens[key_type].len != key_len &&
	     ovs_key_lens[key_type].len != OVS_ATTR_NESTED))
		return -EINVAL;

	/* masked：检查数据未越出掩码范围 */
	if (masked && !validate_masked(nla_data(ovs_key), key_len))
		return -EINVAL;

	switch (key_type) {
	const struct ovs_key_ipv4 *ipv4_key;
	const struct ovs_key_ipv6 *ipv6_key;
	int err;

	case OVS_KEY_ATTR_PRIORITY:
	case OVS_KEY_ATTR_SKB_MARK:
	case OVS_KEY_ATTR_ETHERNET:
		break;

	case OVS_KEY_ATTR_TUNNEL:
		if (eth_p_mpls(eth_type))
			return -EINVAL;

		if (masked)
			return -EINVAL; /* Masked tunnel set not supported. */

		/* 隧道 set 由 validate_and_copy_set_tun 自行写入，跳过外层拷贝 */
		*skip_copy = true;
		err = validate_and_copy_set_tun(a, sfa, log);
		if (err)
			return err;
		break;

	case OVS_KEY_ATTR_IPV4:
		if (eth_type != htons(ETH_P_IP))
			return -EINVAL;

		ipv4_key = nla_data(ovs_key);

		if (masked) {
			const struct ovs_key_ipv4 *mask = ipv4_key + 1;

			/* Non-writeable fields. */
			if (mask->ipv4_proto || mask->ipv4_frag)
				return -EINVAL;
		} else {
			if (ipv4_key->ipv4_proto != flow_key->ip.proto)
				return -EINVAL;

			if (ipv4_key->ipv4_frag != flow_key->ip.frag)
				return -EINVAL;
		}
		break;

	case OVS_KEY_ATTR_IPV6:
		if (eth_type != htons(ETH_P_IPV6))
			return -EINVAL;

		ipv6_key = nla_data(ovs_key);

		if (masked) {
			const struct ovs_key_ipv6 *mask = ipv6_key + 1;

			/* Non-writeable fields. */
			if (mask->ipv6_proto || mask->ipv6_frag)
				return -EINVAL;

			/* Invalid bits in the flow label mask? */
			if (ntohl(mask->ipv6_label) & 0xFFF00000)
				return -EINVAL;
		} else {
			if (ipv6_key->ipv6_proto != flow_key->ip.proto)
				return -EINVAL;

			if (ipv6_key->ipv6_frag != flow_key->ip.frag)
				return -EINVAL;
		}
		if (ntohl(ipv6_key->ipv6_label) & 0xFFF00000)
			return -EINVAL;

		break;

	case OVS_KEY_ATTR_TCP:
		if ((eth_type != htons(ETH_P_IP) &&
		     eth_type != htons(ETH_P_IPV6)) ||
		    flow_key->ip.proto != IPPROTO_TCP)
			return -EINVAL;

		break;

	case OVS_KEY_ATTR_UDP:
		if ((eth_type != htons(ETH_P_IP) &&
		     eth_type != htons(ETH_P_IPV6)) ||
		    flow_key->ip.proto != IPPROTO_UDP)
			return -EINVAL;

		break;

	case OVS_KEY_ATTR_MPLS:
		if (!eth_p_mpls(eth_type))
			return -EINVAL;
		break;

	case OVS_KEY_ATTR_SCTP:
		if ((eth_type != htons(ETH_P_IP) &&
		     eth_type != htons(ETH_P_IPV6)) ||
		    flow_key->ip.proto != IPPROTO_SCTP)
			return -EINVAL;

		break;

	default:
		return -EINVAL;
	}

	/* Convert non-masked non-tunnel set actions to masked set actions. */
	/* 把非掩码的普通 set 统一转成 SET_TO_MASKED：拷贝原值作 key，掩码
	 * 全填 0xff 表示整字段覆盖，内核执行时只需一种 masked-set 逻辑。 */
	if (!masked && key_type != OVS_KEY_ATTR_TUNNEL) {
		int start, len = key_len * 2;
		struct nlattr *at;

		*skip_copy = true;

		start = add_nested_action_start(sfa,
						OVS_ACTION_ATTR_SET_TO_MASKED,
						log);
		if (start < 0)
			return start;

		at = __add_action(sfa, key_type, NULL, len, log);
		if (IS_ERR(at))
			return PTR_ERR(at);

		memcpy(nla_data(at), nla_data(ovs_key), key_len); /* Key. */
		memset(nla_data(at) + key_len, 0xff, key_len);    /* Mask. */
		/* Clear non-writeable bits from otherwise writeable fields. */
		/* IPv6 flow label 只有低 20 位可写，清掉掩码中不可写的高位 */
		if (key_type == OVS_KEY_ATTR_IPV6) {
			struct ovs_key_ipv6 *mask = nla_data(at) + key_len;

			mask->ipv6_label &= htonl(0x000FFFFF);
		}
		add_nested_action_end(*sfa, start);
	}

	return 0;
}

/* validate_userspace - 校验 userspace 动作：必须带非零的目标 PID
 * (OVS_USERSPACE_ATTR_PID)，用于把报文上送到指定用户态套接字。 */
static int validate_userspace(const struct nlattr *attr)
{
	static const struct nla_policy userspace_policy[OVS_USERSPACE_ATTR_MAX + 1] = {
		[OVS_USERSPACE_ATTR_PID] = {.type = NLA_U32 },
		[OVS_USERSPACE_ATTR_USERDATA] = {.type = NLA_UNSPEC },
		[OVS_USERSPACE_ATTR_EGRESS_TUN_PORT] = {.type = NLA_U32 },
	};
	struct nlattr *a[OVS_USERSPACE_ATTR_MAX + 1];
	int error;

	error = nla_parse_nested(a, OVS_USERSPACE_ATTR_MAX,
				 attr, userspace_policy);
	if (error)
		return error;

	if (!a[OVS_USERSPACE_ATTR_PID] ||
	    !nla_get_u32(a[OVS_USERSPACE_ATTR_PID]))
		return -EINVAL;

	return 0;
}

/* copy_action - 把一个已校验的动作属性原样（含头，对齐后长度）拷入 sfa */
static int copy_action(const struct nlattr *from,
		       struct sw_flow_actions **sfa, bool log)
{
	int totlen = NLA_ALIGN(from->nla_len);
	struct nlattr *to;

	to = reserve_sfa_size(sfa, from->nla_len, log);
	if (IS_ERR(to))
		return PTR_ERR(to);

	memcpy(to, from, totlen);
	return 0;
}

/*
 * __ovs_nla_copy_actions - 遍历、校验并拷贝一条动作链到 sfa 缓冲。
 * 这是动作解析的核心：逐个 OVS_ACTION_ATTR_* 检查长度、语义合法性，
 * 大多数动作原样拷贝，少数（set/sample/set tunnel）经转换后由子函数写入
 * （置 skip_copy 跳过原样拷贝）。
 * 通过跟踪 eth_type/vlan_tci 的“沿动作链演化”来校验 push/pop MPLS/VLAN 的
 * 合法性（例如 push MPLS 只允许在已知标签顺序的报文上）。
 * depth 限制 sample 嵌套深度 (SAMPLE_ACTION_DEPTH) 防止无限递归。
 */
static int __ovs_nla_copy_actions(const struct nlattr *attr,
				  const struct sw_flow_key *key,
				  int depth, struct sw_flow_actions **sfa,
				  __be16 eth_type, __be16 vlan_tci, bool log)
{
	const struct nlattr *a;
	int rem, err;

	/* 嵌套过深（sample 套 sample）直接拒绝 */
	if (depth >= SAMPLE_ACTION_DEPTH)
		return -EOVERFLOW;

	nla_for_each_nested(a, attr, rem) {
		/* Expected argument lengths, (u32)-1 for variable length. */
		/* 各动作的期望参数长度；(u32)-1 表示变长 */
		static const u32 action_lens[OVS_ACTION_ATTR_MAX + 1] = {
			[OVS_ACTION_ATTR_OUTPUT] = sizeof(u32),
			[OVS_ACTION_ATTR_RECIRC] = sizeof(u32),
			[OVS_ACTION_ATTR_USERSPACE] = (u32)-1,
			[OVS_ACTION_ATTR_PUSH_MPLS] = sizeof(struct ovs_action_push_mpls),
			[OVS_ACTION_ATTR_POP_MPLS] = sizeof(__be16),
			[OVS_ACTION_ATTR_PUSH_VLAN] = sizeof(struct ovs_action_push_vlan),
			[OVS_ACTION_ATTR_POP_VLAN] = 0,
			[OVS_ACTION_ATTR_SET] = (u32)-1,
			[OVS_ACTION_ATTR_SET_MASKED] = (u32)-1,
			[OVS_ACTION_ATTR_SAMPLE] = (u32)-1,
			[OVS_ACTION_ATTR_HASH] = sizeof(struct ovs_action_hash)
		};
		const struct ovs_action_push_vlan *vlan;
		int type = nla_type(a);
		bool skip_copy;

		if (type > OVS_ACTION_ATTR_MAX ||
		    (action_lens[type] != nla_len(a) &&
		     action_lens[type] != (u32)-1))
			return -EINVAL;

		skip_copy = false;
		switch (type) {
		case OVS_ACTION_ATTR_UNSPEC:
			return -EINVAL;

		case OVS_ACTION_ATTR_USERSPACE:
			err = validate_userspace(a);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_OUTPUT:
			/* 输出端口号必须在合法范围内 */
			if (nla_get_u32(a) >= DP_MAX_PORTS)
				return -EINVAL;
			break;

		case OVS_ACTION_ATTR_HASH: {
			const struct ovs_action_hash *act_hash = nla_data(a);

			switch (act_hash->hash_alg) {
			case OVS_HASH_ALG_L4:
				break;
			default:
				return  -EINVAL;
			}

			break;
		}

		case OVS_ACTION_ATTR_POP_VLAN:
			/* pop VLAN 后当前 vlan_tci 清零，供后续动作判定 */
			vlan_tci = htons(0);
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			vlan = nla_data(a);
			/* 只支持 802.1Q，且必须带 present 位 */
			if (vlan->vlan_tpid != htons(ETH_P_8021Q))
				return -EINVAL;
			if (!(vlan->vlan_tci & htons(VLAN_TAG_PRESENT)))
				return -EINVAL;
			vlan_tci = vlan->vlan_tci;
			break;

		case OVS_ACTION_ATTR_RECIRC:
			break;

		case OVS_ACTION_ATTR_PUSH_MPLS: {
			const struct ovs_action_push_mpls *mpls = nla_data(a);

			if (!eth_p_mpls(mpls->mpls_ethertype))
				return -EINVAL;
			/* Prohibit push MPLS other than to a white list
			 * for packets that have a known tag order.
			 */
			if (vlan_tci & htons(VLAN_TAG_PRESENT) ||
			    (eth_type != htons(ETH_P_IP) &&
			     eth_type != htons(ETH_P_IPV6) &&
			     eth_type != htons(ETH_P_ARP) &&
			     eth_type != htons(ETH_P_RARP) &&
			     !eth_p_mpls(eth_type)))
				return -EINVAL;
			eth_type = mpls->mpls_ethertype;
			break;
		}

		case OVS_ACTION_ATTR_POP_MPLS:
			if (vlan_tci & htons(VLAN_TAG_PRESENT) ||
			    !eth_p_mpls(eth_type))
				return -EINVAL;

			/* Disallow subsequent L2.5+ set and mpls_pop actions
			 * as there is no check here to ensure that the new
			 * eth_type is valid and thus set actions could
			 * write off the end of the packet or otherwise
			 * corrupt it.
			 *
			 * Support for these actions is planned using packet
			 * recirculation.
			 */
			eth_type = htons(0);
			break;

		case OVS_ACTION_ATTR_SET:
			/* 普通 set：masked=false，validate_set 内会转成 masked 存储 */
			err = validate_set(a, key, sfa,
					   &skip_copy, eth_type, false, log);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SET_MASKED:
			/* 用户态直接给出带掩码的 set */
			err = validate_set(a, key, sfa,
					   &skip_copy, eth_type, true, log);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = validate_and_copy_sample(a, key, depth, sfa,
						       eth_type, vlan_tci, log);
			if (err)
				return err;
			/* sample 已由子函数写入，跳过原样拷贝 */
			skip_copy = true;
			break;

		default:
			OVS_NLERR(log, "Unknown Action type %d", type);
			return -EINVAL;
		}
		if (!skip_copy) {
			err = copy_action(a, sfa, log);
			if (err)
				return err;
		}
	}

	/* 遍历结束仍有剩余字节说明动作链畸形 */
	if (rem > 0)
		return -EINVAL;

	return 0;
}

/* 'key' must be the masked key. */
/*
 * ovs_nla_copy_actions - 动作解析对外入口。
 * 先按输入长度分配 sfa 缓冲，再调 __ovs_nla_copy_actions 从 depth 0 开始
 * 校验并拷贝，初始 eth_type/vlan_tci 取自流的 key。失败时释放缓冲。
 * 注意 key 必须是“已掩码的 key”（真正参与匹配的 key）。
 */
int ovs_nla_copy_actions(const struct nlattr *attr,
			 const struct sw_flow_key *key,
			 struct sw_flow_actions **sfa, bool log)
{
	int err;

	*sfa = nla_alloc_flow_actions(nla_len(attr), log);
	if (IS_ERR(*sfa))
		return PTR_ERR(*sfa);

	err = __ovs_nla_copy_actions(attr, key, 0, sfa, key->eth.type,
				     key->eth.tci, log);
	if (err)
		kfree(*sfa);

	return err;
}

/*
 * sample_action_to_attr - 把内部存储的 sample 动作序列化回 netlink（dump）。
 * 概率原样输出；ACTIONS 子属性递归调用 ovs_nla_put_actions 序列化内层动作。
 */
static int sample_action_to_attr(const struct nlattr *attr, struct sk_buff *skb)
{
	const struct nlattr *a;
	struct nlattr *start;
	int err = 0, rem;

	start = nla_nest_start(skb, OVS_ACTION_ATTR_SAMPLE);
	if (!start)
		return -EMSGSIZE;

	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		struct nlattr *st_sample;

		switch (type) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			if (nla_put(skb, OVS_SAMPLE_ATTR_PROBABILITY,
				    sizeof(u32), nla_data(a)))
				return -EMSGSIZE;
			break;
		case OVS_SAMPLE_ATTR_ACTIONS:
			st_sample = nla_nest_start(skb, OVS_SAMPLE_ATTR_ACTIONS);
			if (!st_sample)
				return -EMSGSIZE;
			err = ovs_nla_put_actions(nla_data(a), nla_len(a), skb);
			if (err)
				return err;
			nla_nest_end(skb, st_sample);
			break;
		}
	}

	nla_nest_end(skb, start);
	return err;
}

/*
 * set_action_to_attr - 把内部 set 动作序列化回 netlink（dump）。
 * 隧道信息 (OVS_KEY_ATTR_TUNNEL_INFO) 需展开成隧道属性；其余 key 类型
 * 直接原样放回一个 OVS_ACTION_ATTR_SET 属性。
 */
static int set_action_to_attr(const struct nlattr *a, struct sk_buff *skb)
{
	const struct nlattr *ovs_key = nla_data(a);
	int key_type = nla_type(ovs_key);
	struct nlattr *start;
	int err;

	switch (key_type) {
	case OVS_KEY_ATTR_TUNNEL_INFO: {
		struct ovs_tunnel_info *tun_info = nla_data(ovs_key);

		start = nla_nest_start(skb, OVS_ACTION_ATTR_SET);
		if (!start)
			return -EMSGSIZE;

		err = ipv4_tun_to_nlattr(skb, &tun_info->tunnel,
					 tun_info->options_len ?
						tun_info->options : NULL,
					 tun_info->options_len);
		if (err)
			return err;
		nla_nest_end(skb, start);
		break;
	}
	default:
		if (nla_put(skb, OVS_ACTION_ATTR_SET, nla_len(a), ovs_key))
			return -EMSGSIZE;
		break;
	}

	return 0;
}

/*
 * masked_set_action_to_set_action_attr - 把内部的 SET_TO_MASKED 动作在 dump
 * 时还原成普通 SET 动作（去掉掩码部分，只输出前半段的 key）。这是
 * validate_set 中“普通 set -> masked set”转换的逆操作，保证 dump 出的
 * 动作与用户态原始下发的形态一致。
 */
static int masked_set_action_to_set_action_attr(const struct nlattr *a,
						struct sk_buff *skb)
{
	const struct nlattr *ovs_key = nla_data(a);
	struct nlattr *nla;
	size_t key_len = nla_len(ovs_key) / 2;

	/* Revert the conversion we did from a non-masked set action to
	 * masked set action.
	 */
	nla = nla_nest_start(skb, OVS_ACTION_ATTR_SET);
	if (!nla)
		return -EMSGSIZE;

	if (nla_put(skb, nla_type(ovs_key), key_len, nla_data(ovs_key)))
		return -EMSGSIZE;

	nla_nest_end(skb, nla);
	return 0;
}

/*
 * ovs_nla_put_actions - 把内部存储的整条动作链序列化回 netlink 属性（dump）。
 * 大多数动作原样输出；set/set_to_masked/sample 需要经专门函数还原成用户态
 * 可识别的形态（与解析时的转换互逆）。
 */
int ovs_nla_put_actions(const struct nlattr *attr, int len, struct sk_buff *skb)
{
	const struct nlattr *a;
	int rem, err;

	nla_for_each_attr(a, attr, len, rem) {
		int type = nla_type(a);

		switch (type) {
		case OVS_ACTION_ATTR_SET:
			err = set_action_to_attr(a, skb);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SET_TO_MASKED:
			err = masked_set_action_to_set_action_attr(a, skb);
			if (err)
				return err;
			break;

		case OVS_ACTION_ATTR_SAMPLE:
			err = sample_action_to_attr(a, skb);
			if (err)
				return err;
			break;
		default:
			if (nla_put(skb, type, nla_len(a), nla_data(a)))
				return -EMSGSIZE;
			break;
		}
	}

	return 0;
}
