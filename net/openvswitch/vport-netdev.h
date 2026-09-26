/*
 * Copyright (c) 2007-2011 Nicira, Inc.
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

#ifndef VPORT_NETDEV_H
#define VPORT_NETDEV_H 1

#include <linux/netdevice.h>
#include <linux/rcupdate.h>

#include "vport.h"

// 根据一个内核网络设备(net_device)反查它所对应的 OVS vport。
// 只有真正挂到 datapath 上的设备才会返回非空，否则返回 NULL。
struct vport *ovs_netdev_get_vport(struct net_device *dev);

// netdev 类型 vport 的私有数据结构，保存在 vport 结构体尾部的私有区。
// 它把一个 OVS 端口和其底层的真实内核网络设备关联起来。
struct netdev_vport {
	// 用于 RCU 延迟释放：设备摘除后不能立即 free，需等待宽限期
	struct rcu_head rcu;

	// 该 vport 所绑定的底层内核网络设备(如 eth0)
	struct net_device *dev;
};

// 从 vport 取出其 netdev_vport 私有数据(位于 vport 私有区)。
static inline struct netdev_vport *
netdev_vport_priv(const struct vport *vport)
{
	return vport_priv(vport);
}

// 返回该 vport 底层网络设备的名字(如 "eth0")。
const char *ovs_netdev_get_name(const struct vport *);
// 把底层设备从 OVS 上摘除：注销收包钩子、解除主从关系、恢复混杂模式计数。
void ovs_netdev_detach_dev(struct vport *);

int __init ovs_netdev_init(void);
void ovs_netdev_exit(void);

#endif /* vport_netdev.h */
