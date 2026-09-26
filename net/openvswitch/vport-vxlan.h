/*
 * OVS VXLAN 隧道端口的辅助定义头文件。
 * 目前仅定义 VXLAN 可选选项（GBP）在 OVS 内部的表示，供 vport-vxlan.c 使用。
 */
#ifndef VPORT_VXLAN_H
#define VPORT_VXLAN_H 1

#include <linux/kernel.h>
#include <linux/types.h>

// OVS 保存在隧道元信息 options 中的 VXLAN 选项。
// gbp 即 VXLAN 头 GBP 扩展里的 Group Based Policy 标记，收包时从
// vxlan_metadata->gbp 存入，发包时经 vxlan_ext_gbp() 取出填回 VXLAN 头。
struct ovs_vxlan_opts {
	__u32 gbp;
};

#endif
