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

#ifndef VPORT_INTERNAL_DEV_H
#define VPORT_INTERNAL_DEV_H 1

#include "datapath.h"
#include "vport.h"

// 判断一个网络设备是否为 OVS 内部设备(通过其 netdev_ops 是否等于内部设备的 ops)。
int ovs_is_internal_dev(const struct net_device *);
// 由内部设备的 net_device 反查其对应的 vport；非内部设备返回 NULL。
struct vport *ovs_internal_dev_get_vport(struct net_device *);
// 向 rtnetlink 注册/注销 "openvswitch" 这类内部设备的 link 类型。
int ovs_internal_dev_rtnl_link_register(void);
void ovs_internal_dev_rtnl_link_unregister(void);

#endif /* vport-internal_dev.h */
