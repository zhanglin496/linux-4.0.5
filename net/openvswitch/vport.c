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

#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <net/net_namespace.h>
#include <linux/module.h>

#include "datapath.h"
#include "vport.h"
#include "vport-internal_dev.h"

static void ovs_vport_record_error(struct vport *,
				   enum vport_err_type err_type);

// 已注册的各类型端口 ops 链表(netdev/internal/gre/vxlan/geneve...)。
static LIST_HEAD(vport_ops_list);

/* Protected by RCU read lock for reading, ovs_mutex for writing. */
// 全局端口哈希表：按 (net, name) 索引所有 vport，供 ovs_vport_locate 查找。
// 读侧用 RCU，写侧(增删)须持 ovs_mutex。
static struct hlist_head *dev_table;
#define VPORT_HASH_BUCKETS 1024		// 哈希桶数量，取 2 的幂便于用位与取模

/**
 *	ovs_vport_init - initialize vport subsystem
 *
 * Called at module load time to initialize the vport subsystem.
 */
// 模块加载时分配全局 dev_table 哈希表。返回 0 成功，-ENOMEM 失败。
int ovs_vport_init(void)
{
	dev_table = kzalloc(VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dev_table)
		return -ENOMEM;

	return 0;
}

/**
 *	ovs_vport_exit - shutdown vport subsystem
 *
 * Called at module exit time to shutdown the vport subsystem.
 */
// 模块卸载时释放 dev_table。
void ovs_vport_exit(void)
{
	kfree(dev_table);
}

// 计算某 (net, name) 端口应落入的哈希桶。
// 用 net 指针作为 jhash 初值，使不同 namespace 的同名端口散列到不同桶。
static struct hlist_head *hash_bucket(const struct net *net, const char *name)
{
	unsigned int hash = jhash(name, strlen(name), (unsigned long) net);
	// 位与代替取模(桶数是 2 的幂)
	return &dev_table[hash & (VPORT_HASH_BUCKETS - 1)];
}

// 注册一种端口类型的 ops(由各端口实现模块在加载时调用)。
// 同一 type 只能注册一次，重复返回 -EEXIST。持 ovs_mutex 操作链表。
int ovs_vport_ops_register(struct vport_ops *ops)
{
	int err = -EEXIST;
	struct vport_ops *o;

	ovs_lock();
	// 遍历检查该 type 是否已注册
	list_for_each_entry(o, &vport_ops_list, list)
		if (ops->type == o->type)
			goto errout;

	list_add_tail(&ops->list, &vport_ops_list);
	err = 0;
errout:
	ovs_unlock();
	return err;
}
EXPORT_SYMBOL_GPL(ovs_vport_ops_register);

// 注销某端口类型的 ops(实现模块卸载时调用)。
void ovs_vport_ops_unregister(struct vport_ops *ops)
{
	ovs_lock();
	list_del(&ops->list);
	ovs_unlock();
}
EXPORT_SYMBOL_GPL(ovs_vport_ops_unregister);

/**
 *	ovs_vport_locate - find a port that has already been created
 *
 * @name: name of port to find
 *
 * Must be called with ovs or RCU read lock.
 */
// 按名字在 dev_table 中查找已存在的端口。须持 ovs_mutex 或 RCU 读锁。
struct vport *ovs_vport_locate(const struct net *net, const char *name)
{
	struct hlist_head *bucket = hash_bucket(net, name);
	struct vport *vport;

	// 同一桶内可能有哈希冲突的其它端口，故名字与 net 都要匹配
	hlist_for_each_entry_rcu(vport, bucket, hash_node)
		if (!strcmp(name, vport->ops->get_name(vport)) &&
		    net_eq(ovs_dp_get_net(vport->dp), net))
			return vport;

	return NULL;
}

/**
 *	ovs_vport_alloc - allocate and initialize new vport
 *
 * @priv_size: Size of private data area to allocate.
 * @ops: vport device ops
 *
 * Allocate and initialize a new vport defined by @ops.  The vport will contain
 * a private data area of size @priv_size that can be accessed using
 * vport_priv().  vports that are no longer needed should be released with
 * vport_free().
 */
// 分配并初始化一个新 vport。私有数据区大小 priv_size，紧跟 vport 结构之后，
// 通过 vport_priv() 访问。由各类型 ops->create 调用。失败返回 ERR_PTR。
struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
			  const struct vport_parms *parms)
{
	struct vport *vport;
	size_t alloc_size;

	// vport 结构 + (对齐后)私有区，连成一整块内存一次分配
	alloc_size = sizeof(struct vport);
	if (priv_size) {
		alloc_size = ALIGN(alloc_size, VPORT_ALIGN);
		alloc_size += priv_size;
	}

	vport = kzalloc(alloc_size, GFP_KERNEL);
	if (!vport)
		return ERR_PTR(-ENOMEM);

	// 从创建参数填入归属 dp、端口号、ops
	vport->dp = parms->dp;
	vport->port_no = parms->port_no;
	vport->ops = ops;
	INIT_HLIST_NODE(&vport->dp_hash_node);

	// 初始化 upcall portid 数组；参数非法则回滚
	if (ovs_vport_set_upcall_portids(vport, parms->upcall_portids)) {
		kfree(vport);
		return ERR_PTR(-EINVAL);
	}

	// 分配 per-CPU 收发统计
	vport->percpu_stats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!vport->percpu_stats) {
		kfree(vport);
		return ERR_PTR(-ENOMEM);
	}

	return vport;
}
EXPORT_SYMBOL_GPL(ovs_vport_alloc);

/**
 *	ovs_vport_free - uninitialize and free vport
 *
 * @vport: vport to free
 *
 * Frees a vport allocated with vport_alloc() when it is no longer needed.
 *
 * The caller must ensure that an RCU grace period has passed since the last
 * time @vport was in a datapath.
 */
// 释放 ovs_vport_alloc 分配的 vport(含 portid 数组与 per-CPU 统计)。
// 调用者须保证该 vport 离开 datapath 后已过一个 RCU 宽限期。
void ovs_vport_free(struct vport *vport)
{
	/* vport is freed from RCU callback or error path, Therefore
	 * it is safe to use raw dereference.
	 */
	// 此处已在 RCU 回调或错误路径中，无并发读者，故用 raw 解引用
	kfree(rcu_dereference_raw(vport->upcall_portids));
	free_percpu(vport->percpu_stats);
	kfree(vport);
}
EXPORT_SYMBOL_GPL(ovs_vport_free);

// 按 parms->type 在 vport_ops_list 中查找对应的端口 ops。
static struct vport_ops *ovs_vport_lookup(const struct vport_parms *parms)
{
	struct vport_ops *ops;

	list_for_each_entry(ops, &vport_ops_list, list)
		if (ops->type == parms->type)
			return ops;

	return NULL;
}

/**
 *	ovs_vport_add - add vport device (for kernel callers)
 *
 * @parms: Information about new vport.
 *
 * Creates a new vport with the specified configuration (which is dependent on
 * device type).  ovs_mutex must be held.
 */
// 按 type 找到对应 ops，调用其 create 创建端口，并挂入全局 dev_table。
// 须持 ovs_mutex。若该 type 的模块尚未加载，则尝试按需加载后返回 -EAGAIN
// 让上层重试整个添加流程。
struct vport *ovs_vport_add(const struct vport_parms *parms)
{
	struct vport_ops *ops;
	struct vport *vport;

	ops = ovs_vport_lookup(parms);
	if (ops) {
		struct hlist_head *bucket;

		// 增加实现模块的引用计数，防止创建期间被卸载
		if (!try_module_get(ops->owner))
			return ERR_PTR(-EAFNOSUPPORT);

		// 调用具体类型的创建函数
		vport = ops->create(parms);
		if (IS_ERR(vport)) {
			module_put(ops->owner);
			return vport;
		}

		// 创建成功，按 (net, name) 挂入全局哈希表(供 locate 查找)
		bucket = hash_bucket(ovs_dp_get_net(vport->dp),
				     vport->ops->get_name(vport));
		hlist_add_head_rcu(&vport->hash_node, bucket);
		return vport;
	}

	/* Unlock to attempt module load and return -EAGAIN if load
	 * was successful as we need to restart the port addition
	 * workflow.
	 */
	// 未找到该 type：释放锁去按需加载模块(request_module 可能睡眠)
	ovs_unlock();
	request_module("vport-type-%d", parms->type);
	ovs_lock();

	// 加载后仍无该 type 则真正不支持；否则返回 -EAGAIN 让上层重试
	if (!ovs_vport_lookup(parms))
		return ERR_PTR(-EAFNOSUPPORT);
	else
		return ERR_PTR(-EAGAIN);
}

/**
 *	ovs_vport_set_options - modify existing vport device (for kernel callers)
 *
 * @vport: vport to modify.
 * @options: New configuration.
 *
 * Modifies an existing device with the specified configuration (which is
 * dependent on device type).  ovs_mutex must be held.
 */
// 修改端口配置：转发给具体类型的 ops->set_options。未实现返回 -EOPNOTSUPP。
int ovs_vport_set_options(struct vport *vport, struct nlattr *options)
{
	if (!vport->ops->set_options)
		return -EOPNOTSUPP;
	return vport->ops->set_options(vport, options);
}

/**
 *	ovs_vport_del - delete existing vport device
 *
 * @vport: vport to delete.
 *
 * Detaches @vport from its datapath and destroys it.  It is possible to fail
 * for reasons such as lack of memory.  ovs_mutex must be held.
 */
// 从全局 dev_table 摘除端口并调用 ops->destroy 销毁。须持 ovs_mutex。
void ovs_vport_del(struct vport *vport)
{
	ASSERT_OVSL();

	// 先从哈希表摘除(RCU 方式)，减少模块引用，再销毁
	hlist_del_rcu(&vport->hash_node);
	module_put(vport->ops->owner);
	vport->ops->destroy(vport);
}

/**
 *	ovs_vport_get_stats - retrieve device stats
 *
 * @vport: vport from which to retrieve the stats
 * @stats: location to store stats
 *
 * Retrieves transmit, receive, and error stats for the given device.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
// 汇总统计填入 stats：错误统计来自 err_stats(原子量)，
// 正常收发统计来自各 CPU 的 percpu_stats(需累加)。须持 ovs_mutex 或 rcu。
void ovs_vport_get_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	int i;

	memset(stats, 0, sizeof(*stats));

	/* We potentially have 2 sources of stats that need to be combined:
	 * those we have collected (split into err_stats and percpu_stats) from
	 * set_stats() and device error stats from netdev->get_stats() (for
	 * errors that happen  downstream and therefore aren't reported through
	 * our vport_record_error() function).
	 * Stats from first source are reported by ovs (OVS_VPORT_ATTR_STATS).
	 * netdev-stats can be directly read over netlink-ioctl.
	 */

	// 第一部分：错误/丢包统计，直接读原子量
	stats->rx_errors  = atomic_long_read(&vport->err_stats.rx_errors);
	stats->tx_errors  = atomic_long_read(&vport->err_stats.tx_errors);
	stats->tx_dropped = atomic_long_read(&vport->err_stats.tx_dropped);
	stats->rx_dropped = atomic_long_read(&vport->err_stats.rx_dropped);

	// 第二部分：遍历所有可能的 CPU，累加各自的正常收发统计
	for_each_possible_cpu(i) {
		const struct pcpu_sw_netstats *percpu_stats;
		struct pcpu_sw_netstats local_stats;
		unsigned int start;

		percpu_stats = per_cpu_ptr(vport->percpu_stats, i);

		// 用 u64_stats 序号锁读取一致快照(应对 32 位上 64 位计数撕裂)
		do {
			start = u64_stats_fetch_begin_irq(&percpu_stats->syncp);
			local_stats = *percpu_stats;
		} while (u64_stats_fetch_retry_irq(&percpu_stats->syncp, start));

		stats->rx_bytes		+= local_stats.rx_bytes;
		stats->rx_packets	+= local_stats.rx_packets;
		stats->tx_bytes		+= local_stats.tx_bytes;
		stats->tx_packets	+= local_stats.tx_packets;
	}
}

/**
 *	ovs_vport_get_options - retrieve device options
 *
 * @vport: vport from which to retrieve the options.
 * @skb: sk_buff where options should be appended.
 *
 * Retrieves the configuration of the given device, appending an
 * %OVS_VPORT_ATTR_OPTIONS attribute that in turn contains nested
 * vport-specific attributes to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room, or another
 * negative error code if a real error occurred.  If an error occurs, @skb is
 * left unmodified.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
// 读取端口配置：以嵌套的 OVS_VPORT_ATTR_OPTIONS 属性追加到 skb，
// 内部转发给 ops->get_options。空间不足返回 -EMSGSIZE，出错时 skb 不改动。
int ovs_vport_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct nlattr *nla;
	int err;

	// 该类型无配置则无需追加，直接成功
	if (!vport->ops->get_options)
		return 0;

	// 开启一个嵌套属性容器
	nla = nla_nest_start(skb, OVS_VPORT_ATTR_OPTIONS);
	if (!nla)
		return -EMSGSIZE;

	err = vport->ops->get_options(vport, skb);
	if (err) {
		// 出错则回滚这段嵌套，保持 skb 原样
		nla_nest_cancel(skb, nla);
		return err;
	}

	nla_nest_end(skb, nla);
	return 0;
}

/**
 *	ovs_vport_set_upcall_portids - set upcall portids of @vport.
 *
 * @vport: vport to modify.
 * @ids: new configuration, an array of port ids.
 *
 * Sets the vport's upcall_portids to @ids.
 *
 * Returns 0 if successful, -EINVAL if @ids is zero length or cannot be parsed
 * as an array of U32.
 *
 * Must be called with ovs_mutex.
 */
// 设置端口的 upcall portid 数组(以 RCU 方式替换旧数组)。须持 ovs_mutex。
// ids 为空或长度非 u32 整数倍则返回 -EINVAL。
int ovs_vport_set_upcall_portids(struct vport *vport, const struct nlattr *ids)
{
	struct vport_portids *old, *vport_portids;

	// 至少要有一个 portid，且总长必须是 u32 的整数倍
	if (!nla_len(ids) || nla_len(ids) % sizeof(u32))
		return -EINVAL;

	old = ovsl_dereference(vport->upcall_portids);

	// 分配新结构：头部 + 变长 ids 数组
	vport_portids = kmalloc(sizeof(*vport_portids) + nla_len(ids),
				GFP_KERNEL);
	if (!vport_portids)
		return -ENOMEM;

	vport_portids->n_ids = nla_len(ids) / sizeof(u32);
	// 预计算 n_ids 的倒数，供 find_upcall_portid 快速取模
	vport_portids->rn_ids = reciprocal_value(vport_portids->n_ids);
	nla_memcpy(vport_portids->ids, ids, nla_len(ids));

	// 发布新数组，旧数组延迟到 RCU 宽限期后释放
	rcu_assign_pointer(vport->upcall_portids, vport_portids);

	if (old)
		kfree_rcu(old, rcu);
	return 0;
}

/**
 *	ovs_vport_get_upcall_portids - get the upcall_portids of @vport.
 *
 * @vport: vport from which to retrieve the portids.
 * @skb: sk_buff where portids should be appended.
 *
 * Retrieves the configuration of the given vport, appending the
 * %OVS_VPORT_ATTR_UPCALL_PID attribute which is the array of upcall
 * portids to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room.
 * If an error occurs, @skb is left unmodified.  Must be called with
 * ovs_mutex or rcu_read_lock.
 */
// 把端口的 upcall portid 追加到 skb 的 OVS_VPORT_ATTR_UPCALL_PID 属性。
// 新特性(每端口多 pid)下上报整个数组，否则只上报首个 pid(兼容旧接口)。
int ovs_vport_get_upcall_portids(const struct vport *vport,
				 struct sk_buff *skb)
{
	struct vport_portids *ids;

	ids = rcu_dereference_ovsl(vport->upcall_portids);

	if (vport->dp->user_features & OVS_DP_F_VPORT_PIDS)
		return nla_put(skb, OVS_VPORT_ATTR_UPCALL_PID,
			       ids->n_ids * sizeof(u32), (void *)ids->ids);
	else
		return nla_put_u32(skb, OVS_VPORT_ATTR_UPCALL_PID, ids->ids[0]);
}

/**
 *	ovs_vport_find_upcall_portid - find the upcall portid to send upcall.
 *
 * @vport: vport from which the missed packet is received.
 * @skb: skb that the missed packet was received.
 *
 * Uses the skb_get_hash() to select the upcall portid to send the
 * upcall.
 *
 * Returns the portid of the target socket.  Must be called with rcu_read_lock.
 */
// 为一个流表 miss 的报文选择目标 upcall portid，实现负载分担：
// 用报文的 skb hash 对 n_ids 取模选中数组里的某个 pid，
// 使同一条流稳定落到同一用户态 socket，不同流分散到多个 socket。
// 取模用 reciprocal_divide(预计算倒数)避免热路径整数除法。须持 rcu。
u32 ovs_vport_find_upcall_portid(const struct vport *vport, struct sk_buff *skb)
{
	struct vport_portids *ids;
	u32 ids_index;
	u32 hash;

	ids = rcu_dereference(vport->upcall_portids);

	// 只配了一个且为 0 的 pid：表示不指定目标(交由默认处理)
	if (ids->n_ids == 1 && ids->ids[0] == 0)
		return 0;

	hash = skb_get_hash(skb);
	// 等价于 ids_index = hash % n_ids，但用乘法实现的快速取模
	ids_index = hash - ids->n_ids * reciprocal_divide(hash, ids->rn_ids);
	return ids->ids[ids_index];
}

/**
 *	ovs_vport_receive - pass up received packet to the datapath for processing
 *
 * @vport: vport that received the packet
 * @skb: skb that was received
 * @tun_key: tunnel (if any) that carried packet
 *
 * Must be called with rcu_read_lock.  The packet cannot be shared and
 * skb->data should point to the Ethernet header.
 */
// 底层端口收到报文后的入口：更新收统计，提取 flow key(含隧道信息)，
// 然后交给 ovs_dp_process_packet 进入 datapath 查流表/执行动作。
// 须持 rcu；报文不可共享，skb->data 应指向以太头。
void ovs_vport_receive(struct vport *vport, struct sk_buff *skb,
		       const struct ovs_tunnel_info *tun_info)
{
	struct pcpu_sw_netstats *stats;
	struct sw_flow_key key;
	int error;

	// 更新本 CPU 收方向统计(带 VLAN 时补上 VLAN 头长度)
	stats = this_cpu_ptr(vport->percpu_stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len +
			   (skb_vlan_tag_present(skb) ? VLAN_HLEN : 0);
	u64_stats_update_end(&stats->syncp);

	// 记录入端口，清空出向隧道信息
	OVS_CB(skb)->input_vport = vport;
	OVS_CB(skb)->egress_tun_info = NULL;
	/* Extract flow from 'skb' into 'key'. */
	// 从报文(及隧道信息)解析出 flow key，用于流表匹配
	error = ovs_flow_key_extract(tun_info, skb, &key);
	if (unlikely(error)) {
		kfree_skb(skb);
		return;
	}
	// 进入 datapath 主处理流程
	ovs_dp_process_packet(skb, &key);
}
EXPORT_SYMBOL_GPL(ovs_vport_receive);

/**
 *	ovs_vport_send - send a packet on a device
 *
 * @vport: vport on which to send the packet
 * @skb: skb to send
 *
 * Sends the given packet and returns the length of data sent.  Either ovs
 * lock or rcu_read_lock must be held.
 */
// 从端口发出报文：调用 ops->send。返回>0 为已发长度并累加发统计，
// <0 记发送错误，==0 记发送丢弃。须持 ovs_mutex 或 rcu。
int ovs_vport_send(struct vport *vport, struct sk_buff *skb)
{
	int sent = vport->ops->send(vport, skb);

	if (likely(sent > 0)) {
		// 发送成功，更新本 CPU 发方向统计
		struct pcpu_sw_netstats *stats;

		stats = this_cpu_ptr(vport->percpu_stats);

		u64_stats_update_begin(&stats->syncp);
		stats->tx_packets++;
		stats->tx_bytes += sent;
		u64_stats_update_end(&stats->syncp);
	} else if (sent < 0) {
		// 负值：发送出错
		ovs_vport_record_error(vport, VPORT_E_TX_ERROR);
	} else {
		// 0：报文被丢弃
		ovs_vport_record_error(vport, VPORT_E_TX_DROPPED);
	}
	return sent;
}

/**
 *	ovs_vport_record_error - indicate device error to generic stats layer
 *
 * @vport: vport that encountered the error
 * @err_type: one of enum vport_err_type types to indicate the error type
 *
 * If using the vport generic stats layer indicate that an error of the given
 * type has occurred.
 */
// 按错误类型累加对应的错误统计(原子量，无需加锁)。
static void ovs_vport_record_error(struct vport *vport,
				   enum vport_err_type err_type)
{
	switch (err_type) {
	case VPORT_E_RX_DROPPED:
		atomic_long_inc(&vport->err_stats.rx_dropped);
		break;

	case VPORT_E_RX_ERROR:
		atomic_long_inc(&vport->err_stats.rx_errors);
		break;

	case VPORT_E_TX_DROPPED:
		atomic_long_inc(&vport->err_stats.tx_dropped);
		break;

	case VPORT_E_TX_ERROR:
		atomic_long_inc(&vport->err_stats.tx_errors);
		break;
	}

}

// RCU 回调：宽限期后真正释放 vport。
static void free_vport_rcu(struct rcu_head *rcu)
{
	struct vport *vport = container_of(rcu, struct vport, rcu);

	ovs_vport_free(vport);
}

// 延迟释放 vport：经 RCU 宽限期后再释放，确保无并发读者仍在访问。
void ovs_vport_deferred_free(struct vport *vport)
{
	if (!vport)
		return;

	call_rcu(&vport->rcu, free_vport_rcu);
}
EXPORT_SYMBOL_GPL(ovs_vport_deferred_free);

// 计算隧道出向封装信息：先按隧道 key 查路由拿到源 IP，
// 再结合 tun_info、源/目的端口等生成 egress_tun_info(供后续封装)。
int ovs_tunnel_get_egress_info(struct ovs_tunnel_info *egress_tun_info,
			       struct net *net,
			       const struct ovs_tunnel_info *tun_info,
			       u8 ipproto,
			       u32 skb_mark,
			       __be16 tp_src,
			       __be16 tp_dst)
{
	const struct ovs_key_ipv4_tunnel *tun_key;
	struct rtable *rt;
	struct flowi4 fl;

	if (unlikely(!tun_info))
		return -EINVAL;

	tun_key = &tun_info->tunnel;

	/* Route lookup to get srouce IP address.
	 * The process may need to be changed if the corresponding process
	 * in vports ops changed.
	 */
	// 查路由以确定外层源 IP(fl.saddr)；这里只需路由结果，随即释放 rt
	rt = ovs_tunnel_route_lookup(net, tun_key, skb_mark, &fl, ipproto);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	ip_rt_put(rt);

	/* Generate egress_tun_info based on tun_info,
	 * saddr, tp_src and tp_dst
	 */
	// 用查得的源 IP 与隧道 key 各字段填出出向隧道信息
	__ovs_flow_tun_info_init(egress_tun_info,
				 fl.saddr, tun_key->ipv4_dst,
				 tun_key->ipv4_tos,
				 tun_key->ipv4_ttl,
				 tp_src, tp_dst,
				 tun_key->tun_id,
				 tun_key->tun_flags,
				 tun_info->options,
				 tun_info->options_len);

	return 0;
}
EXPORT_SYMBOL_GPL(ovs_tunnel_get_egress_info);

// 取端口的出向隧道信息：仅隧道端口实现 get_egress_tun_info，
// 非隧道端口返回 -EINVAL。
int ovs_vport_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				  struct ovs_tunnel_info *info)
{
	/* get_egress_tun_info() is only implemented on tunnel ports. */
	if (unlikely(!vport->ops->get_egress_tun_info))
		return -EINVAL;

	return vport->ops->get_egress_tun_info(vport, skb, info);
}
