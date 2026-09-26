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

/*
 * OVS GRE 隧道端口（vport-type-3）
 *
 * GRE（Generic Routing Encapsulation，通用路由封装）是一种把二层以太帧
 * 直接封装进 IP 报文（IP 协议号 47）的 overlay 隧道，不经过 UDP。OVS 用它
 * 把内层帧封入 "外层 IP + GRE 头 + 内层以太帧"，实现跨三层的虚拟二层网络。
 *
 * 与 Geneve/VXLAN（基于 UDP 端口区分）不同，GRE 通过内核的 gre_cisco
 * 协议框架注册收包 handler：整台机器同一 net namespace 内只有一个 GRE
 * vport（保存在 ovs_net->vport_net.gre_vport）。
 *   收包路径：gre_rcv <- gre_cisco 框架 -> 用 GRE key/seq 组装隧道 key ->
 *             ovs_vport_receive 送入 datapath。
 *   发包路径：gre_tnl_send -> 查路由 -> __build_header 追加 GRE 头 ->
 *             iptunnel_xmit 追加外层 IP 头并发送。
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/if.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_tunnel.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/in_route.h>
#include <linux/inetdevice.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/rculist.h>
#include <net/route.h>
#include <net/xfrm.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/gre.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/protocol.h>

#include "datapath.h"
#include "vport.h"

static struct vport_ops ovs_gre_vport_ops;

/* Returns the least-significant 32 bits of a __be64. */
// GRE 头的 key 只有 32 位，而 OVS 内部隧道 ID 是 64 位；发包时取低 32 位作 key。
static __be32 be64_get_low32(__be64 x)
{
#ifdef __BIG_ENDIAN
	return (__force __be32)x;
#else
	return (__force __be32)((__force u64)x >> 32);
#endif
}

// 只保留 GRE 隧道支持并关心的标志位（校验和、key），过滤掉其余位。
static __be16 filter_tnl_flags(__be16 flags)
{
	return flags & (TUNNEL_CSUM | TUNNEL_KEY);
}

// 构造并压入 GRE 隧道头。
// 先按需处理 offload/GSO（依据是否需要校验和），再用出口隧道 key 填 GRE 头
// 字段：flags（CSUM/KEY）、内层协议（ETH_P_TEB 表示承载透明以太桥接帧）、
// key（隧道 ID 低 32 位）、seq。返回处理后的 skb（可能已重新分配）。
static struct sk_buff *__build_header(struct sk_buff *skb,
				      int tunnel_hlen)
{
	struct tnl_ptk_info tpi;
	const struct ovs_key_ipv4_tunnel *tun_key;

	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;

	skb = gre_handle_offloads(skb, !!(tun_key->tun_flags & TUNNEL_CSUM));
	if (IS_ERR(skb))
		return skb;

	tpi.flags = filter_tnl_flags(tun_key->tun_flags);
	tpi.proto = htons(ETH_P_TEB);
	tpi.key = be64_get_low32(tun_key->tun_id);
	tpi.seq = 0;
	gre_build_header(skb, &tpi, tunnel_hlen);

	return skb;
}

// 收包侧：把 GRE 头里的 32 位 key（和 seq）拼成 OVS 内部 64 位隧道 ID。
static __be64 key_to_tunnel_id(__be32 key, __be32 seq)
{
#ifdef __BIG_ENDIAN
	return (__force __be64)((__force u64)seq << 32 | (__force u32)key);
#else
	return (__force __be64)((__force u64)key << 32 | (__force u32)seq);
#endif
}

/* Called with rcu_read_lock and BH disabled. */
// GRE 收包回调：由 gre_cisco 协议框架在收到并解析出 GRE 头（tpi）后调用，
// 此时 skb 已剥掉外层 IP/GRE 头。作用：找到本 net 的 GRE vport，用 GRE
// key/seq 组装隧道 key，把内层帧送入 datapath。
// 返回 PACKET_RCVD（已消费）或 PACKET_REJECT（无对应 vport，交还框架）。
static int gre_rcv(struct sk_buff *skb,
		   const struct tnl_ptk_info *tpi)
{
	struct ovs_tunnel_info tun_info;
	struct ovs_net *ovs_net;
	struct vport *vport;
	__be64 key;

	// 每个 net namespace 仅有一个 GRE vport
	ovs_net = net_generic(dev_net(skb->dev), ovs_net_id);
	vport = rcu_dereference(ovs_net->vport_net.gre_vport);
	if (unlikely(!vport))
		return PACKET_REJECT;

	// 用 GRE key/seq 生成隧道 ID；GRE 无 UDP 端口，故源/目的端口传 0；无选项
	key = key_to_tunnel_id(tpi->key, tpi->seq);
	ovs_flow_tun_info_init(&tun_info, ip_hdr(skb), 0, 0, key,
			       filter_tnl_flags(tpi->flags), NULL, 0);

	ovs_vport_receive(vport, skb, &tun_info);
	return PACKET_RCVD;
}

/* Called with rcu_read_lock and BH disabled. */
// GRE ICMP 差错回调：收到与本 GRE 隧道相关的 ICMP 差错时被调用。
// 这里不做实际处理，仅根据是否存在 GRE vport 返回是否已认领该报文。
static int gre_err(struct sk_buff *skb, u32 info,
		   const struct tnl_ptk_info *tpi)
{
	struct ovs_net *ovs_net;
	struct vport *vport;

	ovs_net = net_generic(dev_net(skb->dev), ovs_net_id);
	vport = rcu_dereference(ovs_net->vport_net.gre_vport);

	if (unlikely(!vport))
		return PACKET_REJECT;
	else
		return PACKET_RCVD;
}

// send 回调：把内层帧封装成 "外层 IP + GRE + 内层帧" 发出。
// 流程：取出口隧道信息 -> 查路由 -> 计算 GRE 头长并确保 headroom 足够 ->
// 内联可能的硬件 VLAN tag -> __build_header 压 GRE 头 -> iptunnel_xmit 压外层
// IP 头并发送。出错走对应 goto 清理路由/skb。
static int gre_tnl_send(struct vport *vport, struct sk_buff *skb)
{
	struct net *net = ovs_dp_get_net(vport->dp);
	const struct ovs_key_ipv4_tunnel *tun_key;
	struct flowi4 fl;
	struct rtable *rt;
	int min_headroom;
	int tunnel_hlen;
	__be16 df;
	int err;

	// 出口隧道信息（目的 IP、tun_id、tos/ttl、标志）应由流水线填好
	if (unlikely(!OVS_CB(skb)->egress_tun_info)) {
		err = -EINVAL;
		goto err_free_skb;
	}

	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;
	// 按隧道目的地址查外层路由（协议 GRE），得出口设备与源地址
	rt = ovs_tunnel_route_lookup(net, tun_key, skb->mark, &fl, IPPROTO_GRE);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto err_free_skb;
	}

	// GRE 头长度随标志位（是否带 key/csum/seq）而变
	tunnel_hlen = ip_gre_calc_hlen(tun_key->tun_flags);

	// 估算封装所需的最小头部空间：链路层 + 路由头 + GRE 头 + 外层 IP 头
	// (+ 可能的 VLAN)。不足或 skb 头被共享时扩展 headroom，避免后续压头越界。
	min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
			+ tunnel_hlen + sizeof(struct iphdr)
			+ (skb_vlan_tag_present(skb) ? VLAN_HLEN : 0);
	if (skb_headroom(skb) < min_headroom || skb_header_cloned(skb)) {
		int head_delta = SKB_DATA_ALIGN(min_headroom -
						skb_headroom(skb) +
						16);
		err = pskb_expand_head(skb, max_t(int, head_delta, 0),
					0, GFP_ATOMIC);
		if (unlikely(err))
			goto err_free_rt;
	}

	// 把硬件卸载的 VLAN tag 真正插回帧内，使内层帧完整后再封装
	skb = vlan_hwaccel_push_inside(skb);
	if (unlikely(!skb)) {
		err = -ENOMEM;
		goto err_free_rt;
	}

	/* Push Tunnel header. */
	// 压入 GRE 头（skb 可能被重新分配）
	skb = __build_header(skb, tunnel_hlen);
	if (IS_ERR(skb)) {
		err = PTR_ERR(skb);
		skb = NULL;
		goto err_free_rt;
	}

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ?
		htons(IP_DF) : 0;

	skb->ignore_df = 1;

	// 压入外层 IP 头（协议 GRE）并交给 IP 层发送
	return iptunnel_xmit(skb->sk, rt, skb, fl.saddr,
			     tun_key->ipv4_dst, IPPROTO_GRE,
			     tun_key->ipv4_tos, tun_key->ipv4_ttl, df, false);
err_free_rt:
	ip_rt_put(rt);
err_free_skb:
	kfree_skb(skb);
	return err;
}

// GRE 收包在 gre_cisco 框架中的注册项：handler 处理数据、err_handler 处理
// ICMP 差错，priority 决定多个 handler 的匹配顺序。
static struct gre_cisco_protocol gre_protocol = {
	.handler        = gre_rcv,
	.err_handler    = gre_err,
	.priority       = 1,
};

// gre_ports 记录当前存活的 GRE vport 数（引用计数）。GRE 协议 handler
// 在整台机器上只需注册一次，因此用计数控制注册/注销时机。
static int gre_ports;
// 首个 GRE vport 创建时把 gre_protocol 注册进 gre_cisco 框架
static int gre_init(void)
{
	int err;

	gre_ports++;
	if (gre_ports > 1)
		return 0;

	err = gre_cisco_register(&gre_protocol);
	if (err)
		pr_warn("cannot register gre protocol handler\n");

	return err;
}

// 最后一个 GRE vport 销毁时注销协议 handler
static void gre_exit(void)
{
	gre_ports--;
	if (gre_ports > 0)
		return;

	gre_cisco_unregister(&gre_protocol);
}

// get_name 回调：GRE vport 的私有区直接存放接口名字符串
static const char *gre_get_name(const struct vport *vport)
{
	return vport_priv(vport);
}

// create 回调：创建 GRE vport。每个 net namespace 只允许一个 GRE vport
// （因为 GRE 无端口区分，靠单一 handler 收全部 GRE 报文）。
// 首次创建会注册协议 handler，并把新 vport 记入 ovs_net->vport_net.gre_vport。
static struct vport *gre_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct ovs_net *ovs_net;
	struct vport *vport;
	int err;

	err = gre_init();
	if (err)
		return ERR_PTR(err);

	ovs_net = net_generic(net, ovs_net_id);
	// 已存在 GRE vport 则拒绝（每个 net 只能有一个）
	if (ovsl_dereference(ovs_net->vport_net.gre_vport)) {
		vport = ERR_PTR(-EEXIST);
		goto error;
	}

	// GRE vport 私有区只需容纳接口名（IFNAMSIZ 字节）
	vport = ovs_vport_alloc(IFNAMSIZ, &ovs_gre_vport_ops, parms);
	if (IS_ERR(vport))
		goto error;

	strncpy(vport_priv(vport), parms->name, IFNAMSIZ);
	// 以 RCU 方式发布到 ovs_net，使 gre_rcv 能查到它
	rcu_assign_pointer(ovs_net->vport_net.gre_vport, vport);
	return vport;

error:
	gre_exit();
	return vport;
}

// destroy 回调：清空 net 中的 GRE vport 指针，延迟释放 vport，
// 并递减 GRE 引用计数（可能触发协议 handler 注销）。
static void gre_tnl_destroy(struct vport *vport)
{
	struct net *net = ovs_dp_get_net(vport->dp);
	struct ovs_net *ovs_net;

	ovs_net = net_generic(net, ovs_net_id);

	RCU_INIT_POINTER(ovs_net->vport_net.gre_vport, NULL);
	ovs_vport_deferred_free(vport);
	gre_exit();
}

// get_egress_tun_info 回调：算出该 GRE 隧道出口报文的元信息（含源 IP）。
// GRE 无 UDP 端口，故源/目的端口传 0。
static int gre_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				   struct ovs_tunnel_info *egress_tun_info)
{
	return ovs_tunnel_get_egress_info(egress_tun_info,
					  ovs_dp_get_net(vport->dp),
					  OVS_CB(skb)->egress_tun_info,
					  IPPROTO_GRE, skb->mark, 0, 0);
}

// GRE vport 操作集：type 为 OVS_VPORT_TYPE_GRE。注意 GRE 无 get_options
// 回调（除接口名外无可序列化配置）。
static struct vport_ops ovs_gre_vport_ops = {
	.type		= OVS_VPORT_TYPE_GRE,
	.create		= gre_create,
	.destroy	= gre_tnl_destroy,
	.get_name	= gre_get_name,
	.send		= gre_tnl_send,
	.get_egress_tun_info	= gre_get_egress_tun_info,
	.owner		= THIS_MODULE,
};

// 模块初始化：注册 GRE vport 类型到 OVS
static int __init ovs_gre_tnl_init(void)
{
	return ovs_vport_ops_register(&ovs_gre_vport_ops);
}

// 模块卸载：注销 GRE vport 类型
static void __exit ovs_gre_tnl_exit(void)
{
	ovs_vport_ops_unregister(&ovs_gre_vport_ops);
}

module_init(ovs_gre_tnl_init);
module_exit(ovs_gre_tnl_exit);

MODULE_DESCRIPTION("OVS: GRE switching port");
MODULE_LICENSE("GPL");
MODULE_ALIAS("vport-type-3");
