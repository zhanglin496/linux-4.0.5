/*
 * Copyright (c) 2007-2013 Nicira, Inc.
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


#ifndef FLOW_NETLINK_H
#define FLOW_NETLINK_H 1

/*
 * flow_netlink.h - OVS 流表编解码层的对外接口声明。
 *
 * 这里声明的函数在 flow_netlink.c 中实现，供 datapath.c（netlink 命令处理）
 * 调用，完成两类工作：
 *  - 解析 (get)：把用户态下发的 OVS_KEY_ATTR_* / OVS_ACTION_ATTR_* 属性
 *    转换成内核的 sw_flow_key / sw_flow_mask / sw_flow_actions，并做校验。
 *  - 序列化 (put)：把内核流表结构 dump 回 netlink 属性返回给用户态。
 * 大多数函数带 bool log 参数：正常为 true 打印错误日志；在“探测特性兼容性”
 * 时传 false 以抑制无谓的错误日志。
 */

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
#include <net/ip_tunnels.h>

#include "flow.h"

/* 计算序列化隧道 key / 完整 flow key 的最大字节数，用于预留 skb 空间 */
size_t ovs_tun_key_attr_size(void);
size_t ovs_key_attr_size(void);

/* 初始化 sw_flow_match：清零并绑定 key/mask 指针 */
void ovs_match_init(struct sw_flow_match *match,
		    struct sw_flow_key *key, struct sw_flow_mask *mask);

/* 序列化：把一个 key（或掩码值）写入指定属性 attr 的嵌套里 */
int ovs_nla_put_key(const struct sw_flow_key *, const struct sw_flow_key *,
		    int attr, bool is_mask, struct sk_buff *);
/* 解析：仅提取流的元数据字段（in_port/priority/tun_key/skb_mark） */
int ovs_nla_get_flow_metadata(const struct nlattr *, struct sw_flow_key *,
			      bool log);

/* dump 流标识 / 已掩码 key / 掩码，分别对应 UFID-or-key / KEY / MASK 属性 */
int ovs_nla_put_identifier(const struct sw_flow *flow, struct sk_buff *skb);
int ovs_nla_put_masked_key(const struct sw_flow *flow, struct sk_buff *skb);
int ovs_nla_put_mask(const struct sw_flow *flow, struct sk_buff *skb);

/* 把 key + 可选 mask 属性解析成 sw_flow_match（含掩码合法性校验） */
int ovs_nla_get_match(struct sw_flow_match *, const struct nlattr *key,
		      const struct nlattr *mask, bool log);
/* 序列化出口隧道 key（供 userspace 动作携带 egress tunnel 信息） */
int ovs_nla_put_egress_tunnel_key(struct sk_buff *,
				  const struct ovs_tunnel_info *);

/* UFID（用户态流唯一标识）解析：读取/校验 UFID，或据 key 生成标识 */
bool ovs_nla_get_ufid(struct sw_flow_id *, const struct nlattr *, bool log);
int ovs_nla_get_identifier(struct sw_flow_id *sfid, const struct nlattr *ufid,
			   const struct sw_flow_key *key, bool log);
u32 ovs_nla_get_ufid_flags(const struct nlattr *attr);

/* 动作链的解析（校验+拷贝进 sw_flow_actions）与序列化（dump 回 netlink） */
int ovs_nla_copy_actions(const struct nlattr *attr,
			 const struct sw_flow_key *key,
			 struct sw_flow_actions **sfa, bool log);
int ovs_nla_put_actions(const struct nlattr *attr,
			int len, struct sk_buff *skb);

/* 经 RCU 宽限期后释放动作缓冲 */
void ovs_nla_free_flow_actions(struct sw_flow_actions *);

#endif /* flow_netlink.h */
