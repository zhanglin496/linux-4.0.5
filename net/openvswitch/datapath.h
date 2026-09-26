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

#ifndef DATAPATH_H
#define DATAPATH_H 1

#include <asm/page.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/u64_stats_sync.h>

#include "flow.h"
#include "flow_table.h"
#include "vport.h"

// 一个 datapath（虚拟交换机）最多可容纳的端口数：端口号用 u16 表示，上限即 65535
#define DP_MAX_PORTS           USHRT_MAX
// datapath 中 ports 端口哈希表的桶数（必须是 2 的幂，用于 port_no & (BUCKETS-1) 取模）
#define DP_VPORT_HASH_BUCKETS  1024

// sample 动作允许的最大嵌套深度，防止动作递归无限展开
#define SAMPLE_ACTION_DEPTH 3

/**
 * struct dp_stats_percpu - per-cpu packet processing statistics for a given
 * datapath.
 * @n_hit: Number of received packets for which a matching flow was found in
 * the flow table.
 * @n_miss: Number of received packets that had no matching flow in the flow
 * table.  The sum of @n_hit and @n_miss is the number of packets that have
 * been received by the datapath.
 * @n_lost: Number of received packets that had no matching flow in the flow
 * table that could not be sent to userspace (normally due to an overflow in
 * one of the datapath's queues).
 * @n_mask_hit: Number of masks looked up for flow match.
 *   @n_mask_hit / (@n_hit + @n_missed)  will be the average masks looked
 *   up per packet.
 */
struct dp_stats_percpu {
	u64 n_hit;		// 命中流表的报文数
	u64 n_missed;		// 未命中流表的报文数（会触发 upcall 上送用户态）
	u64 n_lost;		// 未命中且无法上送用户态而丢弃的报文数（通常因队列溢出）
	u64 n_mask_hit;		// 累计查询过的掩码次数，用于评估 megaflow 查表开销
	struct u64_stats_sync syncp;	// 保护上面 64 位计数在 32 位平台上的读写一致性
};

/**
 * struct datapath - datapath for flow-based packet switching
 * @rcu: RCU callback head for deferred destruction.
 * @list_node: Element in global 'dps' list.
 * @table: flow table.
 * @ports: Hash table for ports.  %OVSP_LOCAL port always exists.  Protected by
 * ovs_mutex and RCU.
 * @stats_percpu: Per-CPU datapath statistics.
 * @net: Reference to net namespace.
 *
 * Context: See the comment on locking at the top of datapath.c for additional
 * locking information.
 */
// struct datapath：一个基于流的虚拟交换机实例（一个 OVS bridge 对应一个 datapath）
struct datapath {
	struct rcu_head rcu;		// 供 call_rcu 延迟释放整个 datapath 用
	struct list_head list_node;	// 挂入 per-netns 的 ovs_net->dps 全局链表

	/* Flow table. */
	// 流表：报文查表匹配的核心数据结构
	struct flow_table table;

	/* Switch ports. */
	// 端口哈希表数组，共 DP_VPORT_HASH_BUCKETS 个桶；OVSP_LOCAL 端口始终存在
	// 写操作受 ovs_mutex 保护，读操作受 RCU 保护
	struct hlist_head *ports;

	/* Stats. */
	// per-CPU 统计计数（命中/未命中/丢弃/掩码命中），避免多核竞争
	struct dp_stats_percpu __percpu *stats_percpu;

#ifdef CONFIG_NET_NS
	/* Network namespace ref. */
	// 所属网络命名空间的引用（编译开启 netns 时才有）
	struct net *net;
#endif

	// 用户态协商的特性位（如 OVS_DP_F_UNALIGNED），影响 upcall 消息布局
	u32 user_features;
};

/**
 * struct ovs_skb_cb - OVS data in skb CB
 * @egress_tun_key: Tunnel information about this packet on egress path.
 * NULL if the packet is not being tunneled.
 * @input_vport: The original vport packet came in on. This value is cached
 * when a packet is received by OVS.
 */
// struct ovs_skb_cb：OVS 借用 skb->cb 存放的每报文私有数据
struct ovs_skb_cb {
	struct ovs_tunnel_info  *egress_tun_info;	// 出方向隧道封装信息，非隧道报文为 NULL
	struct vport		*input_vport;		// 报文进入 OVS 的原始 vport（收包时缓存）
};
// 从任意 skb 取出 OVS 私有控制块的便捷宏
#define OVS_CB(skb) ((struct ovs_skb_cb *)(skb)->cb)

/**
 * struct dp_upcall - metadata to include with a packet to send to userspace
 * @cmd: One of %OVS_PACKET_CMD_*.
 * @userdata: If nonnull, its variable-length value is passed to userspace as
 * %OVS_PACKET_ATTR_USERDATA.
 * @portid: Netlink portid to which packet should be sent.  If @portid is 0
 * then no packet is sent and the packet is accounted in the datapath's @n_lost
 * counter.
 * @egress_tun_info: If nonnull, becomes %OVS_PACKET_ATTR_EGRESS_TUN_KEY.
 */
// struct dp_upcall_info：把报文上送用户态时随附的元数据
struct dp_upcall_info {
	const struct ovs_tunnel_info *egress_tun_info;	// 出隧道 key，非空则写入 OVS_PACKET_ATTR_EGRESS_TUN_KEY
	const struct nlattr *userdata;			// 用户态附带数据，非空则作为 OVS_PACKET_ATTR_USERDATA 回传
	u32 portid;					// 目标 netlink portid；为 0 表示无法上送，计入 n_lost
	u8 cmd;						// OVS_PACKET_CMD_* 之一（如 MISS/ACTION）
};

/**
 * struct ovs_net - Per net-namespace data for ovs.
 * @dps: List of datapaths to enable dumping them all out.
 * Protected by genl_mutex.
 */
// struct ovs_net：OVS 的每网络命名空间数据（通过 net_generic + ovs_net_id 取用）
struct ovs_net {
	struct list_head dps;			// 本 netns 内所有 datapath 的链表（供 dump 遍历）
	struct work_struct dp_notify_work;	// 设备变化通知的延迟工作项
	struct vport_net vport_net;		// vport 层的 per-netns 数据
};

// OVS 在 net_generic 框架里注册得到的 id，用于定位每个 netns 的 ovs_net
extern int ovs_net_id;
// 加/解 ovs_mutex（保护所有写操作），封装在 datapath.c 中
void ovs_lock(void);
void ovs_unlock(void);

#ifdef CONFIG_LOCKDEP
int lockdep_ovsl_is_held(void);
#else
#define lockdep_ovsl_is_held()	1
#endif

// 断言当前持有 ovs_mutex（仅在开启 lockdep 时真正检查）
#define ASSERT_OVSL()		WARN_ON(!lockdep_ovsl_is_held())
// 在“持有 ovs_mutex”前提下解引用 RCU 指针（写侧读取，无需 rcu_read_lock）
#define ovsl_dereference(p)					\
	rcu_dereference_protected(p, lockdep_ovsl_is_held())
// 允许在 rcu_read_lock 或 ovs_mutex 下解引用 RCU 指针
#define rcu_dereference_ovsl(p)					\
	rcu_dereference_check(p, lockdep_ovsl_is_held())

// 取得 datapath 所属的网络命名空间
static inline struct net *ovs_dp_get_net(const struct datapath *dp)
{
	return read_pnet(&dp->net);
}

// 设置 datapath 所属的网络命名空间
static inline void ovs_dp_set_net(struct datapath *dp, struct net *net)
{
	write_pnet(&dp->net, net);
}

// 按端口号查找 vport；调用者须持有 ovs_mutex 或 rcu_read_lock
struct vport *ovs_lookup_vport(const struct datapath *dp, u16 port_no);

// 在 RCU 读侧查找 vport 的封装：进入前会校验确实处于 rcu_read_lock 中
static inline struct vport *ovs_vport_rcu(const struct datapath *dp, int port_no)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return ovs_lookup_vport(dp, port_no);
}

// 查找 vport 的封装：允许持有 rcu_read_lock 或 ovs_mutex 任一
static inline struct vport *ovs_vport_ovsl_rcu(const struct datapath *dp, int port_no)
{
	WARN_ON_ONCE(!rcu_read_lock_held() && !lockdep_ovsl_is_held());
	return ovs_lookup_vport(dp, port_no);
}

// 查找 vport 的封装：要求必须持有 ovs_mutex（写侧路径使用）
static inline struct vport *ovs_vport_ovsl(const struct datapath *dp, int port_no)
{
	ASSERT_OVSL();
	return ovs_lookup_vport(dp, port_no);
}

extern struct notifier_block ovs_dp_device_notifier;
extern struct genl_family dp_vport_genl_family;

// 数据面收包主入口：用 key 查流表，命中执行 actions，未命中 upcall 上送；须在 rcu_read_lock 下调用
void ovs_dp_process_packet(struct sk_buff *skb, struct sw_flow_key *key);
// 从 datapath 摘除并销毁一个端口；须持有 ovs_mutex
void ovs_dp_detach_port(struct vport *);
// 将报文连同元数据上送用户态（处理 GSO 分段），失败时累加 n_lost
int ovs_dp_upcall(struct datapath *, struct sk_buff *,
		  const struct sw_flow_key *, const struct dp_upcall_info *);

// 返回 datapath 的名字（即其 OVSP_LOCAL 内部口名）；须在 rcu_read_lock 或 ovs_mutex 下调用
const char *ovs_dp_name(const struct datapath *dp);
// 为一个 vport 构造 netlink 通告消息（供设备变化通知使用）
struct sk_buff *ovs_vport_cmd_build_info(struct vport *, u32 pid, u32 seq,
					 u8 cmd);

// 对 skb 执行给定的动作列表（实现在 actions.c），是流命中后的动作引擎入口
int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct sw_flow_actions *, struct sw_flow_key *);

// 处理端口设备变化通知的工作队列回调
void ovs_dp_notify_wq(struct work_struct *work);

int action_fifos_init(void);
void action_fifos_exit(void);

// 受限速控制的 netlink 错误日志宏：仅当允许打印且未被限速时输出
#define OVS_NLERR(logging_allowed, fmt, ...)			\
do {								\
	if (logging_allowed && net_ratelimit())			\
		pr_info("netlink: " fmt "\n", ##__VA_ARGS__);	\
} while (0)
#endif /* datapath.h */
