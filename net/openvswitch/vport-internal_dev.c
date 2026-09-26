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

#include <linux/hardirq.h>
#include <linux/if_vlan.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>

#include <net/dst.h>
#include <net/xfrm.h>
#include <net/rtnetlink.h>

#include "datapath.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

// 内部设备的私有数据：一个纯软件 net_device 反向指回它所属的 OVS vport。
struct internal_dev {
	struct vport *vport;
};

// 内部设备 vport 的操作表(定义见文件末尾)，此处前置声明。
static struct vport_ops ovs_internal_vport_ops;

// 从 net_device 取出 internal_dev 私有数据。
static struct internal_dev *internal_dev_priv(struct net_device *netdev)
{
	return netdev_priv(netdev);
}

// 提供设备统计信息给内核网络层(如 ifconfig/ip 读取)。
// 注意：内部设备是协议栈与 datapath 的注入/抽取点，二者视角相反，
// 因此这里要把 OVS 统计的收发方向对调后再上报给主机 OS。
/* This function is only called by the kernel network layer.*/
static struct rtnl_link_stats64 *internal_dev_get_stats(struct net_device *netdev,
							struct rtnl_link_stats64 *stats)
{
	struct vport *vport = ovs_internal_dev_get_vport(netdev);
	struct ovs_vport_stats vport_stats;

	ovs_vport_get_stats(vport, &vport_stats);

	/* The tx and rx stats need to be swapped because the
	 * switch and host OS have opposite perspectives. */
	// 交换收发方向：交换机口的"发"就是主机的"收"，反之亦然
	stats->rx_packets	= vport_stats.tx_packets;
	stats->tx_packets	= vport_stats.rx_packets;
	stats->rx_bytes		= vport_stats.tx_bytes;
	stats->tx_bytes		= vport_stats.rx_bytes;
	stats->rx_errors	= vport_stats.tx_errors;
	stats->tx_errors	= vport_stats.rx_errors;
	stats->rx_dropped	= vport_stats.tx_dropped;
	stats->tx_dropped	= vport_stats.rx_dropped;

	return stats;
}

// 发送函数(ndo_start_xmit)：本机协议栈从该内部设备发出的报文，
// 在这里被直接抽取并送进 OVS datapath 进行流表处理。
// 这就是"协议栈 -> datapath"的注入方向。
/* Called with rcu_read_lock_bh. */
static int internal_dev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	rcu_read_lock();
	// 把报文交给通用 vport 接收入口，进入 datapath
	ovs_vport_receive(internal_dev_priv(netdev)->vport, skb, NULL);
	rcu_read_unlock();
	return 0;
}

// 设备被 up 时启动发送队列。
static int internal_dev_open(struct net_device *netdev)
{
	netif_start_queue(netdev);
	return 0;
}

// 设备被 down 时停止发送队列。
static int internal_dev_stop(struct net_device *netdev)
{
	netif_stop_queue(netdev);
	return 0;
}

// ethtool 查询驱动信息时上报驱动名为 "openvswitch"。
static void internal_dev_getinfo(struct net_device *netdev,
				 struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, "openvswitch", sizeof(info->driver));
}

// 内部设备的 ethtool 操作表。
static const struct ethtool_ops internal_dev_ethtool_ops = {
	.get_drvinfo	= internal_dev_getinfo,
	.get_link	= ethtool_op_get_link,
};

// 修改 MTU：下限 68 字节(IP 最小重组缓冲)，其余直接接受。
static int internal_dev_change_mtu(struct net_device *netdev, int new_mtu)
{
	if (new_mtu < 68)
		return -EINVAL;

	netdev->mtu = new_mtu;
	return 0;
}

// 设备销毁析构器(在 free_netdev 时被调用)：释放关联的 vport 并释放 net_device。
static void internal_dev_destructor(struct net_device *dev)
{
	struct vport *vport = ovs_internal_dev_get_vport(dev);

	ovs_vport_free(vport);
	free_netdev(dev);
}

// 内部设备的 net_device_ops：把上面各回调登记给内核网络设备框架。
static const struct net_device_ops internal_dev_netdev_ops = {
	.ndo_open = internal_dev_open,
	.ndo_stop = internal_dev_stop,
	.ndo_start_xmit = internal_dev_xmit,
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_change_mtu = internal_dev_change_mtu,
	.ndo_get_stats64 = internal_dev_get_stats,
};

// rtnetlink link 类型描述：内部设备对外以 "openvswitch" 类型出现。
static struct rtnl_link_ops internal_dev_link_ops __read_mostly = {
	.kind = "openvswitch",
};

// net_device 的初始化回调(传给 alloc_netdev)：配置内部设备的各项属性。
static void do_setup(struct net_device *netdev)
{
	// 先按以太网设备做默认初始化(设置 MTU、头长度、广播地址等)
	ether_setup(netdev);

	netdev->netdev_ops = &internal_dev_netdev_ops;

	// 该设备可能把 skb 送入 datapath 被修改，故不能共享 skb
	netdev->priv_flags &= ~IFF_TX_SKB_SHARING;
	// 允许设备处于 up 状态时更改 MAC 地址
	netdev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	netdev->destructor = internal_dev_destructor;
	netdev->ethtool_ops = &internal_dev_ethtool_ops;
	netdev->rtnl_link_ops = &internal_dev_link_ops;
	// 内部设备无需硬件发送队列(直接软件转发到 datapath)
	netdev->tx_queue_len = 0;

	// 声明本地无锁发送、支持分散聚合、GSO/校验和卸载等软件特性
	netdev->features = NETIF_F_LLTX | NETIF_F_SG | NETIF_F_FRAGLIST |
			   NETIF_F_HIGHDMA | NETIF_F_HW_CSUM |
			   NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ENCAP_ALL;

	netdev->vlan_features = netdev->features;
	netdev->hw_enc_features = netdev->features;
	netdev->features |= NETIF_F_HW_VLAN_CTAG_TX;
	netdev->hw_features = netdev->features & ~NETIF_F_LLTX;

	// 随机分配一个 MAC 地址
	eth_hw_addr_random(netdev);
}

// 创建内部设备 vport：经 vport_ops.create 调用，通过 alloc_netdev 新建一个
// 纯软件 net_device 并注册到内核。常用于网桥自身接口(OVSP_LOCAL 端口)。
// 成功返回 vport，失败返回 ERR_PTR。
static struct vport *internal_dev_create(const struct vport_parms *parms)
{
	struct vport *vport;
	struct netdev_vport *netdev_vport;
	struct internal_dev *internal_dev;
	int err;

	// 分配 vport(私有区复用 netdev_vport，用来保存 dev 指针)
	vport = ovs_vport_alloc(sizeof(struct netdev_vport),
				&ovs_internal_vport_ops, parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		goto error;
	}

	netdev_vport = netdev_vport_priv(vport);

	// 新建带 internal_dev 私有区、以 do_setup 初始化的 net_device
	netdev_vport->dev = alloc_netdev(sizeof(struct internal_dev),
					 parms->name, NET_NAME_UNKNOWN,
					 do_setup);
	if (!netdev_vport->dev) {
		err = -ENOMEM;
		goto error_free_vport;
	}

	// 把设备放入 datapath 所在的网络命名空间，并让其私有区反指回 vport
	dev_net_set(netdev_vport->dev, ovs_dp_get_net(vport->dp));
	internal_dev = internal_dev_priv(netdev_vport->dev);
	internal_dev->vport = vport;

	/* Restrict bridge port to current netns. */
	// 网桥本地口(OVSP_LOCAL)不允许被移动到其它 netns
	if (vport->port_no == OVSP_LOCAL)
		netdev_vport->dev->features |= NETIF_F_NETNS_LOCAL;

	rtnl_lock();
	// 向内核注册该网络设备，注册后它就是一块可见的网卡
	err = register_netdevice(netdev_vport->dev);
	if (err)
		goto error_free_netdev;

	// 开启混杂模式并启动发送队列
	dev_set_promiscuity(netdev_vport->dev, 1);
	rtnl_unlock();
	netif_start_queue(netdev_vport->dev);

	return vport;

	// 出错回滚路径
error_free_netdev:
	rtnl_unlock();
	free_netdev(netdev_vport->dev);
error_free_vport:
	ovs_vport_free(vport);
error:
	return ERR_PTR(err);
}

// 销毁内部设备 vport：停止队列、关闭混杂模式并注销 net_device。
// vport 本身的释放由设备析构器 internal_dev_destructor 完成。
static void internal_dev_destroy(struct vport *vport)
{
	struct netdev_vport *netdev_vport = netdev_vport_priv(vport);

	netif_stop_queue(netdev_vport->dev);
	rtnl_lock();
	dev_set_promiscuity(netdev_vport->dev, -1);

	/* unregister_netdevice() waits for an RCU grace period. */
	// 注销设备，内部会等待一个 RCU 宽限期后触发析构器
	unregister_netdevice(netdev_vport->dev);

	rtnl_unlock();
}

// 接收函数(vport_ops.send)：datapath 决定把报文送到该内部设备时调用，
// 即把报文注入本机协议栈(netif_rx)。这是"datapath -> 协议栈"的注入方向。
static int internal_dev_recv(struct vport *vport, struct sk_buff *skb)
{
	struct net_device *netdev = netdev_vport_priv(vport)->dev;
	int len;

	// 设备未 up 则丢弃
	if (unlikely(!(netdev->flags & IFF_UP))) {
		kfree_skb(skb);
		return 0;
	}

	len = skb->len;

	// 清理来自 datapath 侧的路由/netfilter/IPsec 等残留状态，
	// 以免影响该报文重新进入本机协议栈
	skb_dst_drop(skb);
	nf_reset(skb);
	secpath_reset(skb);

	// 设定入口设备、报文类型和二层协议，并把以太头从 L3 校验和中扣除
	skb->dev = netdev;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);
	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);

	// 交给协议栈接收路径，如同该设备真的收到了这个报文
	netif_rx(skb);

	return len;
}

// 内部设备 vport 的操作表。注意 send 指向 internal_dev_recv：
// datapath 的"发送到该端口"等于把报文注入本机协议栈接收。
static struct vport_ops ovs_internal_vport_ops = {
	.type		= OVS_VPORT_TYPE_INTERNAL,
	.create		= internal_dev_create,
	.destroy	= internal_dev_destroy,
	.get_name	= ovs_netdev_get_name,
	.send		= internal_dev_recv,
};

// 通过比较 netdev_ops 判断该设备是否为 OVS 内部设备。
int ovs_is_internal_dev(const struct net_device *netdev)
{
	return netdev->netdev_ops == &internal_dev_netdev_ops;
}

// 由内部设备的 net_device 反查其 vport；非内部设备返回 NULL。
struct vport *ovs_internal_dev_get_vport(struct net_device *netdev)
{
	if (!ovs_is_internal_dev(netdev))
		return NULL;

	return internal_dev_priv(netdev)->vport;
}

// 注册内部设备：先注册 rtnetlink link 类型，再向 vport 框架注册内部设备类型。
int ovs_internal_dev_rtnl_link_register(void)
{
	int err;

	err = rtnl_link_register(&internal_dev_link_ops);
	if (err < 0)
		return err;

	err = ovs_vport_ops_register(&ovs_internal_vport_ops);
	// vport 类型注册失败则回滚 link 类型注册
	if (err < 0)
		rtnl_link_unregister(&internal_dev_link_ops);

	return err;
}

// 注销内部设备(与注册相反的顺序)。
void ovs_internal_dev_rtnl_link_unregister(void)
{
	ovs_vport_ops_unregister(&ovs_internal_vport_ops);
	rtnl_link_unregister(&internal_dev_link_ops);
}
