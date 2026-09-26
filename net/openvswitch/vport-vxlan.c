/*
 * Copyright (c) 2014 Nicira, Inc.
 * Copyright (c) 2013 Cisco Systems, Inc.
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
 * OVS VXLAN 隧道端口（vport-type-4）
 *
 * VXLAN（Virtual eXtensible LAN）把二层以太帧封装进 UDP 报文，用 24 位 VNI
 * （VXLAN Network Identifier）区分多达 1600 万个虚拟二层网络，是最常用的
 * overlay 隧道之一。可选的 GBP（Group Based Policy）扩展可在头部携带组策略标记。
 *
 * 本文件把 VXLAN 实现成一种 OVS vport：
 *   收包路径：底层 vxlan socket 收到 UDP 报文 -> vxlan_rcv 解出 VNI（作为
 *             tun_id）与 GBP -> ovs_flow_tun_info_init 组装隧道 key ->
 *             ovs_vport_receive 送入 datapath。
 *   发包路径：vxlan_tnl_send -> 查路由 -> 由 tun_id 生成 VNI/GBP ->
 *             vxlan_xmit_skb 封装 VXLAN+UDP+IP 头并发送。
 * 通过 struct vport_ops（ovs_vxlan_vport_ops）注册这些回调。
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/udp.h>
#include <linux/module.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/vxlan.h>

#include "datapath.h"
#include "vport.h"
#include "vport-vxlan.h"

/**
 * struct vxlan_port - Keeps track of open UDP ports
 * @vs: vxlan_sock created for the port.
 * @name: vport name.
 *
 * VXLAN vport 的私有数据。vs 是底层收发 UDP 的 vxlan socket；name 为接口名；
 * exts 记录启用的 VXLAN 扩展标志（如 VXLAN_F_GBP，定义于 <net/vxlan.h>）。
 */
struct vxlan_port {
	struct vxlan_sock *vs;
	char name[IFNAMSIZ];
	u32 exts; /* VXLAN_F_* in <net/vxlan.h> */
};

static struct vport_ops ovs_vxlan_vport_ops;

// 从 vport 私有区取出 vxlan_port
static inline struct vxlan_port *vxlan_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

/* Called with rcu_read_lock and BH disabled. */
// VXLAN 收包回调：底层 vxlan socket 校验完 UDP 报文后调用，md 携带解析出的
// VNI 及 GBP。作用：把 VNI 转成 64 位 tun_id，连同外层 IP/端口、GBP 选项
// 组装成隧道 key，把内层帧送入 datapath。vs->data 是对应的 vport。
static void vxlan_rcv(struct vxlan_sock *vs, struct sk_buff *skb,
		      struct vxlan_metadata *md)
{
	struct ovs_tunnel_info tun_info;
	struct vxlan_port *vxlan_port;
	struct vport *vport = vs->data;
	struct iphdr *iph;
	struct ovs_vxlan_opts opts = {
		.gbp = md->gbp,
	};
	__be64 key;
	__be16 flags;

	// 一定带 KEY；UDP 校验和非 0 则带 CSUM
	flags = TUNNEL_KEY | (udp_hdr(skb)->check != 0 ? TUNNEL_CSUM : 0);
	vxlan_port = vxlan_vport(vport);
	// 仅当本端口启用了 GBP 扩展且报文确实带 GBP 时，才标记 VXLAN 选项
	if (vxlan_port->exts & VXLAN_F_GBP && md->gbp)
		flags |= TUNNEL_VXLAN_OPT;

	/* Save outer tunnel values */
	// 保存外层隧道信息：VNI 在 md->vni 中占高 24 位，右移 8 位取出后作 tun_id
	iph = ip_hdr(skb);
	key = cpu_to_be64(ntohl(md->vni) >> 8);
	ovs_flow_tun_info_init(&tun_info, iph,
			       udp_hdr(skb)->source, udp_hdr(skb)->dest,
			       key, flags, &opts, sizeof(opts));

	ovs_vport_receive(vport, skb, &tun_info);
}

// get_options 回调：把 UDP 目的端口写回 netlink；若启用了扩展（如 GBP），
// 再以嵌套属性写出各扩展标记，供用户态读取端口配置。
static int vxlan_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	__be16 dst_port = inet_sk(vxlan_port->vs->sock->sk)->inet_sport;

	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(dst_port)))
		return -EMSGSIZE;

	// 有扩展则以嵌套属性输出
	if (vxlan_port->exts) {
		struct nlattr *exts;

		exts = nla_nest_start(skb, OVS_TUNNEL_ATTR_EXTENSION);
		if (!exts)
			return -EMSGSIZE;

		if (vxlan_port->exts & VXLAN_F_GBP &&
		    nla_put_flag(skb, OVS_VXLAN_EXT_GBP))
			return -EMSGSIZE;

		nla_nest_end(skb, exts);
	}

	return 0;
}

// destroy 回调：释放底层 vxlan socket，延迟释放 vport 内存
static void vxlan_tnl_destroy(struct vport *vport)
{
	struct vxlan_port *vxlan_port = vxlan_vport(vport);

	vxlan_sock_release(vxlan_port->vs);

	ovs_vport_deferred_free(vport);
}

// VXLAN 扩展属性的解析策略：目前仅支持 GBP（标志型属性）
static const struct nla_policy exts_policy[OVS_VXLAN_EXT_MAX+1] = {
	[OVS_VXLAN_EXT_GBP]	= { .type = NLA_FLAG, },
};

// 解析用户态传入的扩展属性，据此在 vxlan_port->exts 中置位相应扩展标志。
// 返回 0 成功，负值表示属性非法。
static int vxlan_configure_exts(struct vport *vport, struct nlattr *attr)
{
	struct nlattr *exts[OVS_VXLAN_EXT_MAX+1];
	struct vxlan_port *vxlan_port;
	int err;

	if (nla_len(attr) < sizeof(struct nlattr))
		return -EINVAL;

	err = nla_parse_nested(exts, OVS_VXLAN_EXT_MAX, attr, exts_policy);
	if (err < 0)
		return err;

	vxlan_port = vxlan_vport(vport);

	if (exts[OVS_VXLAN_EXT_GBP])
		vxlan_port->exts |= VXLAN_F_GBP;

	return 0;
}

// create 回调：创建 VXLAN vport。
// 解析必填的 UDP 目的端口和可选的扩展属性，分配 vport，然后创建监听该端口的
// vxlan socket 并注册 vxlan_rcv 为收包回调。返回新 vport；出错返回 ERR_PTR。
static struct vport *vxlan_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct vxlan_port *vxlan_port;
	struct vxlan_sock *vs;
	struct vport *vport;
	struct nlattr *a;
	u16 dst_port;
	int err;

	if (!options) {
		err = -EINVAL;
		goto error;
	}
	// 从嵌套属性中要求用户态提供 UDP 目的端口
	a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
	if (a && nla_len(a) == sizeof(u16)) {
		dst_port = nla_get_u16(a);
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto error;
	}

	// 分配 vport，尾部预留 vxlan_port 私有区
	vport = ovs_vport_alloc(sizeof(struct vxlan_port),
				&ovs_vxlan_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	vxlan_port = vxlan_vport(vport);
	strncpy(vxlan_port->name, parms->name, IFNAMSIZ);

	// 可选：解析扩展属性（如启用 GBP），失败则回收 vport
	a = nla_find_nested(options, OVS_TUNNEL_ATTR_EXTENSION);
	if (a) {
		err = vxlan_configure_exts(vport, a);
		if (err) {
			ovs_vport_free(vport);
			goto error;
		}
	}

	// 创建监听 dst_port 的 vxlan socket，注册 vxlan_rcv 收包回调，
	// 并带上启用的扩展标志。失败时回收 vport。
	vs = vxlan_sock_add(net, htons(dst_port), vxlan_rcv, vport, true,
			    vxlan_port->exts);
	if (IS_ERR(vs)) {
		ovs_vport_free(vport);
		return (void *)vs;
	}
	vxlan_port->vs = vs;

	return vport;

error:
	return ERR_PTR(err);
}

// 从出口隧道选项中取出 GBP 标记（若启用了 VXLAN_OPT 且选项长度足够），
// 否则返回 0。发包时用于填 VXLAN 头的 GBP 字段。
static int vxlan_ext_gbp(struct sk_buff *skb)
{
	const struct ovs_tunnel_info *tun_info;
	const struct ovs_vxlan_opts *opts;

	tun_info = OVS_CB(skb)->egress_tun_info;
	opts = tun_info->options;

	if (tun_info->tunnel.tun_flags & TUNNEL_VXLAN_OPT &&
	    tun_info->options_len >= sizeof(*opts))
		return opts->gbp;
	else
		return 0;
}

// send 回调：把内层帧封装成 VXLAN 报文发出。
// 流程：取出口隧道信息 -> 查路由 -> 由 tun_id 生成 VNI、取 GBP、组装扩展标志 ->
// vxlan_xmit_skb 追加 VXLAN+UDP+IP 头并发送。出错释放 skb。
static int vxlan_tnl_send(struct vport *vport, struct sk_buff *skb)
{
	struct net *net = ovs_dp_get_net(vport->dp);
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	__be16 dst_port = inet_sk(vxlan_port->vs->sock->sk)->inet_sport;
	const struct ovs_key_ipv4_tunnel *tun_key;
	struct vxlan_metadata md = {0};
	struct rtable *rt;
	struct flowi4 fl;
	__be16 src_port;
	__be16 df;
	int err;
	u32 vxflags;

	// 出口隧道信息应由流水线填好
	if (unlikely(!OVS_CB(skb)->egress_tun_info)) {
		err = -EINVAL;
		goto error;
	}

	tun_key = &OVS_CB(skb)->egress_tun_info->tunnel;
	// 按隧道目的地址查外层路由（协议 UDP）
	rt = ovs_tunnel_route_lookup(net, tun_key, skb->mark, &fl, IPPROTO_UDP);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto error;
	}

	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ?
		htons(IP_DF) : 0;

	skb->ignore_df = 1;

	// 依内层流哈希生成 UDP 源端口（利于底层负载分担）
	src_port = udp_flow_src_port(net, skb, 0, 0, true);
	// tun_id 左移 8 位放到 VNI 字段（高 24 位）
	md.vni = htonl(be64_to_cpu(tun_key->tun_id) << 8);
	// 取 GBP 标记填入元数据
	md.gbp = vxlan_ext_gbp(skb);
	// 组合发送标志：端口启用的扩展 + 是否算 UDP 校验和
	vxflags = vxlan_port->exts |
		      (tun_key->tun_flags & TUNNEL_CSUM ? VXLAN_F_UDP_CSUM : 0);

	// 封装并发送：追加 VXLAN 头（VNI/GBP）、UDP 头（src/dst 端口）、
	// 外层 IP 头（saddr/dst/tos/ttl/df）
	err = vxlan_xmit_skb(rt, skb, fl.saddr, tun_key->ipv4_dst,
			     tun_key->ipv4_tos, tun_key->ipv4_ttl, df,
			     src_port, dst_port,
			     &md, false, vxflags);
	if (err < 0)
		ip_rt_put(rt);
	return err;
error:
	kfree_skb(skb);
	return err;
}

// get_egress_tun_info 回调：预先算出该 VXLAN 隧道出口报文元信息（含源 IP、
// UDP 源/目的端口），供上层动作/统计使用。
static int vxlan_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				     struct ovs_tunnel_info *egress_tun_info)
{
	struct net *net = ovs_dp_get_net(vport->dp);
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	__be16 dst_port = inet_sk(vxlan_port->vs->sock->sk)->inet_sport;
	__be16 src_port;
	int port_min;
	int port_max;

	inet_get_local_port_range(net, &port_min, &port_max);
	// 与发包一致地计算 UDP 源端口
	src_port = udp_flow_src_port(net, skb, 0, 0, true);

	return ovs_tunnel_get_egress_info(egress_tun_info, net,
					  OVS_CB(skb)->egress_tun_info,
					  IPPROTO_UDP, skb->mark,
					  src_port, dst_port);
}

// get_name 回调：返回 vport 接口名
static const char *vxlan_get_name(const struct vport *vport)
{
	struct vxlan_port *vxlan_port = vxlan_vport(vport);
	return vxlan_port->name;
}

// VXLAN vport 操作集：type 为 OVS_VPORT_TYPE_VXLAN，向框架登记全部回调。
static struct vport_ops ovs_vxlan_vport_ops = {
	.type		= OVS_VPORT_TYPE_VXLAN,
	.create		= vxlan_tnl_create,
	.destroy	= vxlan_tnl_destroy,
	.get_name	= vxlan_get_name,
	.get_options	= vxlan_get_options,
	.send		= vxlan_tnl_send,
	.get_egress_tun_info	= vxlan_get_egress_tun_info,
	.owner		= THIS_MODULE,
};

// 模块初始化：注册 VXLAN vport 类型到 OVS
static int __init ovs_vxlan_tnl_init(void)
{
	return ovs_vport_ops_register(&ovs_vxlan_vport_ops);
}

// 模块卸载：注销 VXLAN vport 类型
static void __exit ovs_vxlan_tnl_exit(void)
{
	ovs_vport_ops_unregister(&ovs_vxlan_vport_ops);
}

module_init(ovs_vxlan_tnl_init);
module_exit(ovs_vxlan_tnl_exit);

MODULE_DESCRIPTION("OVS: VXLAN switching port");
MODULE_LICENSE("GPL");
MODULE_ALIAS("vport-type-4");
