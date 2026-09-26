/*
 * Copyright (c) 2014 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

/*
 * OVS Geneve 隧道端口（vport-type-5）
 *
 * Geneve（Generic Network Virtualization Encapsulation，通用网络虚拟化封装）
 * 是一种把二层以太帧封装进 UDP 报文的 overlay 隧道协议，用于在三层网络之上
 * 构建虚拟二层网络。相比 VXLAN，Geneve 头部除了 24 位 VNI 之外还带有一段
 * 可变长的 TLV 选项（Type-Length-Value），扩展性更强。
 *
 * 本文件把 Geneve 隧道实现成一种 OVS vport（虚拟端口）：
 *   收包路径：底层 geneve socket 收到 UDP 报文 -> geneve_rcv 解封装 ->
 *             提取 VNI/选项等隧道 key -> ovs_vport_receive 送入 datapath。
 *   发包路径：geneve_tnl_send -> 查路由 -> geneve_xmit_skb 封装 Geneve+UDP+IP
 *             头 -> 发送。
 * 通过 struct vport_ops（ovs_geneve_vport_ops）向 OVS vport 框架注册这些回调。
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/rculist.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/module.h>

#include <net/geneve.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/udp.h>
#include <net/xfrm.h>

#include "datapath.h"
#include "vport.h"

static struct vport_ops ovs_geneve_vport_ops;

/**
 * struct geneve_port - Keeps track of open UDP ports
 * @gs: The socket created for this port number.
 * @name: vport name.
 *
 * 每个 Geneve vport 的私有数据，保存在 vport 尾部（vport_priv）。
 * gs 是底层实际收发 UDP 报文的 geneve socket；name 是该 vport 的接口名。
 */
struct geneve_port {
	struct geneve_sock *gs;
	char name[IFNAMSIZ];
};

static LIST_HEAD(geneve_ports);

// 从 vport 私有区取出 geneve_port（vport 分配时预留了这块空间）
static inline struct geneve_port *geneve_vport(const struct vport *vport)
{
	return vport_priv(vport);
}

// 定位 skb 中的 Geneve 头：紧跟在 UDP 头之后
static inline struct genevehdr *geneve_hdr(const struct sk_buff *skb)
{
	return (struct genevehdr *)(udp_hdr(skb) + 1);
}

/* Convert 64 bit tunnel ID to 24 bit VNI. */
// 把 OVS 内部使用的 64 位隧道 ID 压缩成 Geneve 头里的 24 位 VNI。
// VNI 取隧道 ID 的低 24 位；大小端下 __be64 在内存里的字节排布不同，
// 因此需要分别取字节以保证网络字节序正确。
static void tunnel_id_to_vni(__be64 tun_id, __u8 *vni)
{
#ifdef __BIG_ENDIAN
	vni[0] = (__force __u8)(tun_id >> 16);
	vni[1] = (__force __u8)(tun_id >> 8);
	vni[2] = (__force __u8)tun_id;
#else
	vni[0] = (__force __u8)((__force u64)tun_id >> 40);
	vni[1] = (__force __u8)((__force u64)tun_id >> 48);
	vni[2] = (__force __u8)((__force u64)tun_id >> 56);
#endif
}

/* Convert 24 bit VNI to 64 bit tunnel ID. */
// 收包时的反向转换：把 Geneve 头里的 24 位 VNI 扩展回 64 位隧道 ID，
// 供 datapath 内部统一以 __be64 tun_id 处理。
static __be64 vni_to_tunnel_id(const __u8 *vni)
{
#ifdef __BIG_ENDIAN
	return (vni[0] << 16) | (vni[1] << 8) | vni[2];
#else
	return (__force __be64)(((__force u64)vni[0] << 40) |
				((__force u64)vni[1] << 48) |
				((__force u64)vni[2] << 56));
#endif
}

// Geneve 收包回调：底层 geneve socket 收到并校验完 UDP 报文后调用（此时
// skb 已剥掉外层 IP/UDP/Geneve 头，data 指向内层以太帧）。
// 作用：从 Geneve 头提取 VNI、标志位和 TLV 选项，组装成 ovs_tunnel_info
// 隧道 key，再把内层帧连同隧道 key 一起送入 OVS datapath。
// gs->rcv_data 在 geneve_sock_add 时被设为对应的 vport。
static void geneve_rcv(struct geneve_sock *gs, struct sk_buff *skb)
{
	struct vport *vport = gs->rcv_data;
	struct genevehdr *geneveh = geneve_hdr(skb);
	int opts_len;
	struct ovs_tunnel_info tun_info;
	__be64 key;
	__be16 flags;

	// Geneve 头的 opt_len 字段以 4 字节为单位，乘 4 得到 TLV 选项总字节数
	opts_len = geneveh->opt_len * 4;

	// 根据 Geneve 头/UDP 头的各个位设置 OVS 隧道标志：
	// 一定带 KEY 和 GENEVE_OPT；UDP 校验和非 0 则带 CSUM；
	// oam/critical 位分别映射为 TUNNEL_OAM / TUNNEL_CRIT_OPT。
	flags = TUNNEL_KEY | TUNNEL_GENEVE_OPT |
		(udp_hdr(skb)->check != 0 ? TUNNEL_CSUM : 0) |
		(geneveh->oam ? TUNNEL_OAM : 0) |
		(geneveh->critical ? TUNNEL_CRIT_OPT : 0);

	// 24 位 VNI -> 64 位隧道 ID
	key = vni_to_tunnel_id(geneveh->vni);

	// 用外层 IP 头（源/目的地址、tos、ttl）、UDP 源/目的端口、隧道 key、
	// 标志位以及 Geneve TLV 选项（geneveh->options，opts_len 字节）初始化
	// 隧道元信息。TLV 选项原样拷入 tun_opts 供流表匹配。
	ovs_flow_tun_info_init(&tun_info, ip_hdr(skb),
			       udp_hdr(skb)->source, udp_hdr(skb)->dest,
			       key, flags,
			       geneveh->options, opts_len);

	// 把解封装后的内层帧和隧道元信息交给 datapath 继续查流表/转发
	ovs_vport_receive(vport, skb, &tun_info);
}

// get_options 回调：把该 vport 的可序列化配置写回 netlink 消息，
// 供用户态（ovs-vswitchd）读取端口配置。这里只有 UDP 目的端口一项。
// 返回 0 成功；skb 空间不足返回 -EMSGSIZE。
static int geneve_get_options(const struct vport *vport,
			      struct sk_buff *skb)
{
	struct geneve_port *geneve_port = geneve_vport(vport);
	struct inet_sock *sk = inet_sk(geneve_port->gs->sock->sk);

	// 把 socket 绑定的本地端口作为隧道目的端口写回属性
	if (nla_put_u16(skb, OVS_TUNNEL_ATTR_DST_PORT, ntohs(sk->inet_sport)))
		return -EMSGSIZE;
	return 0;
}

// destroy 回调：销毁 vport 时释放底层 geneve socket，并延迟释放 vport 内存
// （延迟到 RCU 宽限期后，确保没有并发的收包路径还在引用它）。
static void geneve_tnl_destroy(struct vport *vport)
{
	struct geneve_port *geneve_port = geneve_vport(vport);

	geneve_sock_release(geneve_port->gs);

	ovs_vport_deferred_free(vport);
}

// create 回调：创建一个 Geneve vport。
// 从用户态传入的 options 中解析出必须指定的 UDP 目的端口，分配 vport，
// 然后创建监听该端口的底层 geneve socket 并把 geneve_rcv 注册为收包回调。
// 返回新 vport；出错返回 ERR_PTR。
static struct vport *geneve_tnl_create(const struct vport_parms *parms)
{
	struct net *net = ovs_dp_get_net(parms->dp);
	struct nlattr *options = parms->options;
	struct geneve_port *geneve_port;
	struct geneve_sock *gs;
	struct vport *vport;
	struct nlattr *a;
	int err;
	u16 dst_port;

	if (!options) {
		err = -EINVAL;
		goto error;
	}

	// 从嵌套属性中查找并要求用户态提供 UDP 目的端口
	a = nla_find_nested(options, OVS_TUNNEL_ATTR_DST_PORT);
	if (a && nla_len(a) == sizeof(u16)) {
		dst_port = nla_get_u16(a);
	} else {
		/* Require destination port from userspace. */
		err = -EINVAL;
		goto error;
	}

	// 分配 vport，尾部预留 geneve_port 大小的私有区
	vport = ovs_vport_alloc(sizeof(struct geneve_port),
				&ovs_geneve_vport_ops, parms);
	if (IS_ERR(vport))
		return vport;

	geneve_port = geneve_vport(vport);
	strncpy(geneve_port->name, parms->name, IFNAMSIZ);

	// 创建/复用监听 dst_port 的 geneve socket，注册 geneve_rcv 为收包回调，
	// 并把本 vport 作为回调私有数据。失败时回收已分配的 vport。
	gs = geneve_sock_add(net, htons(dst_port), geneve_rcv, vport, true, 0);
	if (IS_ERR(gs)) {
		ovs_vport_free(vport);
		return (void *)gs;
	}
	geneve_port->gs = gs;

	return vport;
error:
	return ERR_PTR(err);
}

// send 回调：把一条内层帧封装成 Geneve 报文发出。
// 流程：取出出口隧道元信息 -> 按目的地址查路由 -> 计算源端口/DF/VNI/选项 ->
// geneve_xmit_skb 追加 Geneve+UDP+IP 头并交给 IP 层发送。
// 成功返回 geneve_xmit_skb 的结果；出错释放 skb 并返回负错误码。
static int geneve_tnl_send(struct vport *vport, struct sk_buff *skb)
{
	const struct ovs_key_ipv4_tunnel *tun_key;
	struct ovs_tunnel_info *tun_info;
	struct net *net = ovs_dp_get_net(vport->dp);
	struct geneve_port *geneve_port = geneve_vport(vport);
	__be16 dport = inet_sk(geneve_port->gs->sock->sk)->inet_sport;
	__be16 sport;
	struct rtable *rt;
	struct flowi4 fl;
	u8 vni[3], opts_len, *opts;
	__be16 df;
	int err;

	// 出口隧道元信息由前面的流水线（如 set_tunnel 动作）填好，携带目的
	// IP、tun_id、tos/ttl、标志位及 Geneve 选项。缺失说明配置错误。
	tun_info = OVS_CB(skb)->egress_tun_info;
	if (unlikely(!tun_info)) {
		err = -EINVAL;
		goto error;
	}

	tun_key = &tun_info->tunnel;
	// 按隧道目的地址查外层路由（协议 UDP），得到出口设备和源地址（fl.saddr）
	rt = ovs_tunnel_route_lookup(net, tun_key, skb->mark, &fl, IPPROTO_UDP);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		goto error;
	}

	// 是否在外层 IP 头设置 DF（不分片）位
	df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
	// 依据内层流哈希生成 UDP 源端口（熵值利于底层多路径/RSS 负载分担）
	sport = udp_flow_src_port(net, skb, 1, USHRT_MAX, true);
	// 64 位隧道 ID -> 24 位 VNI 填入 Geneve 头
	tunnel_id_to_vni(tun_key->tun_id, vni);
	skb->ignore_df = 1;

	// 若隧道 key 带 Geneve TLV 选项，则把它们透传到发出的 Geneve 头
	if (tun_key->tun_flags & TUNNEL_GENEVE_OPT) {
		opts = (u8 *)tun_info->options;
		opts_len = tun_info->options_len;
	} else {
		opts = NULL;
		opts_len = 0;
	}

	// 封装并发送：追加 Geneve 头（VNI/选项/标志）、UDP 头（sport/dport）、
	// 外层 IP 头（saddr/dst/tos/ttl/df），是否算 UDP 校验和取决于 TUNNEL_CSUM。
	err = geneve_xmit_skb(geneve_port->gs, rt, skb, fl.saddr,
			      tun_key->ipv4_dst, tun_key->ipv4_tos,
			      tun_key->ipv4_ttl, df, sport, dport,
			      tun_key->tun_flags, vni, opts_len, opts,
			      !!(tun_key->tun_flags & TUNNEL_CSUM), false);
	if (err < 0)
		ip_rt_put(rt);
	return err;

error:
	kfree_skb(skb);
	return err;
}

// get_name 回调：返回该 vport 的接口名
static const char *geneve_get_name(const struct vport *vport)
{
	struct geneve_port *geneve_port = geneve_vport(vport);

	return geneve_port->name;
}

// get_egress_tun_info 回调：在真正发包前，预先算出这条隧道出口报文的
// 元信息（尤其是 UDP 源/目的端口和经路由确定的源 IP），供上层动作/统计使用。
static int geneve_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				      struct ovs_tunnel_info *egress_tun_info)
{
	struct geneve_port *geneve_port = geneve_vport(vport);
	struct net *net = ovs_dp_get_net(vport->dp);
	__be16 dport = inet_sk(geneve_port->gs->sock->sk)->inet_sport;
	__be16 sport = udp_flow_src_port(net, skb, 1, USHRT_MAX, true);

	/* Get tp_src and tp_dst, refert to geneve_build_header().
	 */
	// 与 geneve_tnl_send 保持一致地计算源/目的端口，并查出源 IP
	return ovs_tunnel_get_egress_info(egress_tun_info,
					  ovs_dp_get_net(vport->dp),
					  OVS_CB(skb)->egress_tun_info,
					  IPPROTO_UDP, skb->mark, sport, dport);
}

// Geneve vport 操作集：向 OVS vport 框架登记本类型端口的全部回调。
// type 为 OVS_VPORT_TYPE_GENEVE，用户态据此创建该类型端口。
static struct vport_ops ovs_geneve_vport_ops = {
	.type		= OVS_VPORT_TYPE_GENEVE,
	.create		= geneve_tnl_create,
	.destroy	= geneve_tnl_destroy,
	.get_name	= geneve_get_name,
	.get_options	= geneve_get_options,
	.send		= geneve_tnl_send,
	.owner          = THIS_MODULE,
	.get_egress_tun_info	= geneve_get_egress_tun_info,
};

// 模块初始化：注册 Geneve vport 类型到 OVS
static int __init ovs_geneve_tnl_init(void)
{
	return ovs_vport_ops_register(&ovs_geneve_vport_ops);
}

// 模块卸载：注销 Geneve vport 类型
static void __exit ovs_geneve_tnl_exit(void)
{
	ovs_vport_ops_unregister(&ovs_geneve_vport_ops);
}

module_init(ovs_geneve_tnl_init);
module_exit(ovs_geneve_tnl_exit);

MODULE_DESCRIPTION("OVS: Geneve swiching port");
MODULE_LICENSE("GPL");
MODULE_ALIAS("vport-type-5");
