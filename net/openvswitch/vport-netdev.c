/*
 * Copyright (c) 2007-2012 Nicira, Inc.
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

#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/llc.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/openvswitch.h>

#include <net/llc.h>

#include "datapath.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

// netdev 类型 vport 的操作表(定义见文件末尾)，此处前置声明。
static struct vport_ops ovs_netdev_vport_ops;

// 真正把从底层网卡截获到的报文送入 OVS datapath。
// 调用者：netdev_frame_hook(rx_handler 回调)。必须在 rcu_read_lock 下调用。
/* Must be called with rcu_read_lock. */
static void netdev_port_receive(struct vport *vport, struct sk_buff *skb)
{
	// 该设备未挂到 datapath(vport 为空)，直接丢弃
	if (unlikely(!vport))
		goto error;

	// OVS 不支持 LRO(大接收卸载)聚合后的报文，命中则丢弃并告警
	if (unlikely(skb_warn_if_lro(skb)))
		goto error;

	/* Make our own copy of the packet.  Otherwise we will mangle the
	 * packet for anyone who came before us (e.g. tcpdump via AF_PACKET).
	 */
	// 若 skb 被其它路径(如 tcpdump 经 AF_PACKET)共享，则复制一份，
	// 避免后续对报文的修改破坏别人看到的内容
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return;

	// 收包时 skb->data 已指向 L3 头，这里把指针回退到以太头，
	// 因为 datapath 需要从完整的二层帧开始处理
	skb_push(skb, ETH_HLEN);
	// 重新把刚 push 进来的以太头计入校验和
	ovs_skb_postpush_rcsum(skb, skb->data, ETH_HLEN);

	// 交给通用 vport 接收入口，进入 datapath 流表匹配与动作执行
	ovs_vport_receive(vport, skb, NULL);
	return;

error:
	kfree_skb(skb);
}

// rx_handler 回调：在 netdev_create 中通过 netdev_rx_handler_register 注册
// 到底层网卡上。凡是进入该网卡的报文都会先经过此钩子被 OVS 截获。
// 由内核收包路径(__netif_receive_skb_core)在 rcu_read_lock 且关闭下半部时调用。
/* Called with rcu_read_lock and bottom-halves disabled. */
static rx_handler_result_t netdev_frame_hook(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct vport *vport;

	// 回环类型的报文不拦截，交还给协议栈正常处理
	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	// 由收包设备反查对应的 OVS 端口
	vport = ovs_netdev_get_vport(skb->dev);

	// 把报文送入 datapath
	netdev_port_receive(vport, skb);

	// 返回 CONSUMED 表示报文已被 OVS 接管，协议栈不再继续处理
	return RX_HANDLER_CONSUMED;
}

// 取得 datapath 的本地设备(OVSP_LOCAL 端口对应的内部设备)。
// netdev vport 会把底层网卡挂到这个本地设备之下作为其 upper master，
// 从而在网络设备拓扑中体现"网卡属于某个网桥"的从属关系。
static struct net_device *get_dpdev(const struct datapath *dp)
{
	struct vport *local;

	local = ovs_vport_ovsl(dp, OVSP_LOCAL);
	BUG_ON(!local);
	return netdev_vport_priv(local)->dev;
}

// 创建一个 netdev 类型的 vport：把一个已存在的内核网卡挂到 OVS 作为端口。
// 调用者：ovs_vport_add(经 vport_ops.create)。成功返回 vport，失败返回 ERR_PTR。
// 核心动作是给底层网卡注册 rx_handler，使其收到的报文被 OVS 截获。
static struct vport *netdev_create(const struct vport_parms *parms)
{
	struct vport *vport;
	struct netdev_vport *netdev_vport;
	int err;

	// 分配 vport 并预留 netdev_vport 私有区
	vport = ovs_vport_alloc(sizeof(struct netdev_vport),
				&ovs_netdev_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	netdev_vport = netdev_vport_priv(vport);

	// 按名字(如 "eth0")在本 netns 中查找目标网络设备，并递增其引用计数
	netdev_vport->dev = dev_get_by_name(ovs_dp_get_net(vport->dp), parms->name);
	if (!netdev_vport->dev) {
		err = -ENODEV;
		goto error_free_vport;
	}

	// 拒绝回环设备、非以太网设备以及 OVS 内部设备(它们不能作为 netdev 端口)
	if (netdev_vport->dev->flags & IFF_LOOPBACK ||
	    netdev_vport->dev->type != ARPHRD_ETHER ||
	    ovs_is_internal_dev(netdev_vport->dev)) {
		err = -EINVAL;
		goto error_put;
	}

	// 修改网络设备状态需持 rtnl 锁
	rtnl_lock();
	// 把底层网卡设为 datapath 本地设备的从设备(建立 master/upper 关系)
	err = netdev_master_upper_dev_link(netdev_vport->dev,
					   get_dpdev(vport->dp));
	if (err)
		goto error_unlock;

	// 注册收包钩子 netdev_frame_hook，并把 vport 作为 rx_handler_data 保存。
	// 此后进入该网卡的报文都会先经过 netdev_frame_hook 被 OVS 拦截
	err = netdev_rx_handler_register(netdev_vport->dev, netdev_frame_hook,
					 vport);
	if (err)
		goto error_master_upper_dev_unlink;

	// 开启混杂模式，确保收下所有目的 MAC 的报文交由 OVS 转发决策
	dev_set_promiscuity(netdev_vport->dev, 1);
	// 打标记表明该设备已被 OVS datapath 接管(供 ovs_netdev_get_vport 等判断)
	netdev_vport->dev->priv_flags |= IFF_OVS_DATAPATH;
	rtnl_unlock();

	return vport;

	// 以下为出错回滚路径，按加锁/注册的逆序撤销
error_master_upper_dev_unlink:
	netdev_upper_dev_unlink(netdev_vport->dev, get_dpdev(vport->dp));
error_unlock:
	rtnl_unlock();
error_put:
	dev_put(netdev_vport->dev);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

// RCU 宽限期结束后的真正释放回调：释放对底层设备的引用并释放 vport。
static void free_port_rcu(struct rcu_head *rcu)
{
	struct netdev_vport *netdev_vport = container_of(rcu,
					struct netdev_vport, rcu);

	// 释放 netdev_create 中 dev_get_by_name 获得的设备引用
	dev_put(netdev_vport->dev);
	ovs_vport_free(vport_from_priv(netdev_vport));
}

// 把底层网卡从 OVS 上摘除(与 netdev_create 中的挂接动作相对应)。
// 调用者：netdev_destroy(正常删除端口)、dp_device_event(设备被注销时)。
// 必须持有 rtnl 锁。
void ovs_netdev_detach_dev(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	ASSERT_RTNL();
	// 清除 OVS 接管标记
	netdev_vport->dev->priv_flags &= ~IFF_OVS_DATAPATH;
	// 注销收包钩子，报文重新回到协议栈正常路径
	netdev_rx_handler_unregister(netdev_vport->dev);
	// 解除与本地设备的 master/upper 从属关系
	netdev_upper_dev_unlink(netdev_vport->dev,
				netdev_master_upper_dev_get(netdev_vport->dev));
	// 撤销之前开启的混杂模式(计数减一)
	dev_set_promiscuity(netdev_vport->dev, -1);
}

// 销毁 netdev vport：正常删除端口时经 vport_ops.destroy 调用。
static void netdev_destroy(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	rtnl_lock();
	// 若设备仍被 OVS 接管(未被 dp_device_event 提前摘除)，先摘除
	if (netdev_vport->dev->priv_flags & IFF_OVS_DATAPATH)
		ovs_netdev_detach_dev(vport);
	rtnl_unlock();

	// 延迟到 RCU 宽限期后再释放设备引用和 vport，避免与并发收包路径冲突
	call_rcu(&netdev_vport->rcu, free_port_rcu);
}

// 返回底层网络设备的名字，作为该 vport 的名字。
const char *ovs_netdev_get_name(const struct vport *vport)
{
	const struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	return netdev_vport->dev->name;
}

// 计算报文的有效载荷长度(不含以太头，若带 VLAN 标签则再扣掉 VLAN 头)，
// 用于发送前与 MTU 比较。
static unsigned int packet_length(const struct sk_buff *skb)
{
	unsigned int length = skb->len - ETH_HLEN;

	if (skb->protocol == htons(ETH_P_8021Q))
		length -= VLAN_HLEN;

	return length;
}

// 发送函数：datapath 决定把报文从该 netdev 端口发出时经 vport_ops.send 调用。
// 通过 dev_queue_xmit 把报文从真实网卡发出。返回发送的字节数，丢弃返回 0。
static int netdev_send(struct vport *vport, struct sk_buff *skb)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);
	int mtu = netdev_vport->dev->mtu;
	int len;

	// 非 GSO 报文若超过 MTU 则丢弃(GSO 报文由网卡/软件分段后再受 MTU 约束)
	if (unlikely(packet_length(skb) > mtu && !skb_is_gso(skb))) {
		net_warn_ratelimited("%s: dropped over-mtu packet: %d > %d\n",
				     netdev_vport->dev->name,
				     packet_length(skb), mtu);
		goto drop;
	}

	// 指定出口设备并交给内核发送队列，真正把帧发出去
	skb->dev = netdev_vport->dev;
	len = skb->len;
	dev_queue_xmit(skb);

	return len;

drop:
	kfree_skb(skb);
	return 0;
}

// 由内核设备反查其对应的 OVS vport；未挂到 datapath 则返回 NULL。
// vport 指针即注册 rx_handler 时保存的 rx_handler_data。
/* Returns null if this device is not attached to a datapath. */
struct vport *ovs_netdev_get_vport(struct net_device *dev)
{
	// 通过 IFF_OVS_DATAPATH 标记快速判断该设备是否被 OVS 接管
	if (likely(dev->priv_flags & IFF_OVS_DATAPATH))
		return (struct vport *)
			rcu_dereference_rtnl(dev->rx_handler_data);
	else
		return NULL;
}

// netdev 类型 vport 的操作表：把上面各回调登记到 OVS vport 框架。
static struct vport_ops ovs_netdev_vport_ops = {
	.type		= OVS_VPORT_TYPE_NETDEV,
	.create		= netdev_create,
	.destroy	= netdev_destroy,
	.get_name	= ovs_netdev_get_name,
	.send		= netdev_send,
};

// 模块初始化：向 vport 框架注册 netdev 类型。
int __init ovs_netdev_init(void)
{
	return ovs_vport_ops_register(&ovs_netdev_vport_ops);
}

// 模块退出：注销 netdev 类型。
void ovs_netdev_exit(void)
{
	ovs_vport_ops_unregister(&ovs_netdev_vport_ops);
}
