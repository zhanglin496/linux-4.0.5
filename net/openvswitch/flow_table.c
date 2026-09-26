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

#include "flow.h"
#include "datapath.h"
#include <linux/uaccess.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/llc_pdu.h>
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/llc.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/rcupdate.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/rculist.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ndisc.h>

/*
 * OVS 流表核心：掩码链表 + 哈希表实现的通配（megaflow）匹配
 * -----------------------------------------------------------------
 * OpenFlow 规则往往带通配符（例如“只看目的 IP，忽略源端口”），无法直接用一次
 * 精确哈希查找命中。OVS 的做法是：
 *   1) 每条流(sw_flow)关联一个掩码(sw_flow_mask)，掩码标出“这条流关心哪些位”。
 *   2) 流表在哈希表里存的是“报文 key 与掩码做与运算后的结果(masked key)”。
 *   3) 表里出现过的所有不同掩码，去重后串在 mask_list 上（多条流可共享同一掩码，
 *      靠 ref_count 计数）。
 * 查表时：对来包的 key，遍历 mask_list，逐个掩码做 masked key 再去哈希表精确查找；
 * 任一掩码命中即返回。这就是所谓 megaflow：一次内核查表可覆盖大量具体五元组。
 * n_mask_hit 统计本次查了几个掩码，反映查表代价。
 *
 * 并发模型：读路径（报文查表）在 RCU 读侧临界区内进行，无锁；写路径（增删流、
 * 增删掩码、rehash）在 OVS 全局 mutex（ovs-lock）保护下进行，表实例替换用
 * rcu_assign_pointer + call_rcu 延迟释放，保证读者始终看到一致的哈希表。
 */

// 哈希表初始桶数（2 的幂）。
#define TBL_MIN_BUCKETS		1024
// 周期性 rehash 的时间间隔：10 分钟。即使表大小没变，也定期换 hash_seed 重排，
// 抵御刻意构造碰撞的攻击，并让分布重新均匀。
#define REHASH_INTERVAL		(10 * 60 * HZ)

// sw_flow 对象的 slab 缓存（含随节点数变长的 stats 指针数组，见 ovs_flow_init）。
static struct kmem_cache *flow_cache;
// per-flow 的统计结构 flow_stats 的 slab 缓存，按 NUMA 节点分配。
struct kmem_cache *flow_stats_cache __read_mostly;

// 返回掩码/key 有效范围的字节数（end - start），供按 range 遍历时用作长度。
static u16 range_n_bytes(const struct sw_flow_key_range *range)
{
	return range->end - range->start;
}

// 把 src(未掩码 key) 按 mask 做与运算，结果写入 dst。
// 关键点：只处理 mask->range[start,end) 这一段（以 long 为步长），范围外不动，
// 因为后续对 dst 的哈希/比较也只看这一段（见 flow_hash/cmp_key）。
void ovs_flow_mask_key(struct sw_flow_key *dst, const struct sw_flow_key *src,
		       const struct sw_flow_mask *mask)
{
	// m/s/d 分别指向 mask->key、src、dst 中 range.start 处，按 long 对齐遍历。
	const long *m = (const long *)((const u8 *)&mask->key +
				mask->range.start);
	const long *s = (const long *)((const u8 *)src +
				mask->range.start);
	long *d = (long *)((u8 *)dst + mask->range.start);
	int i;

	/* The memory outside of the 'mask->range' are not set since
	 * further operations on 'dst' only uses contents within
	 * 'mask->range'.
	 */
	// 逐个 long 做按位与：masked_key = src & mask。以 long 为单位是为了效率。
	for (i = 0; i < range_n_bytes(&mask->range); i += sizeof(long))
		*d++ = *s++ & *m++;
}

// 分配并初始化一条流(sw_flow)。返回流指针，失败返回 ERR_PTR。
// 同时分配默认(node 0)的统计节点；其余 NUMA 节点的 stats 首次写入时才惰性分配。
struct sw_flow *ovs_flow_alloc(void)
{
	struct sw_flow *flow;
	struct flow_stats *stats;
	int node;

	flow = kmem_cache_alloc(flow_cache, GFP_KERNEL);
	if (!flow)
		return ERR_PTR(-ENOMEM);

	// 清零/初始化各成员：动作、掩码、UFID/未掩码 key 均先置空。
	flow->sf_acts = NULL;
	flow->mask = NULL;
	flow->id.unmasked_key = NULL;
	flow->id.ufid_len = 0;
	// 记录“上次写统计的节点”，用于减少跨 NUMA 竞争；初值无节点。
	flow->stats_last_writer = NUMA_NO_NODE;

	/* Initialize the default stat node. */
	// 默认统计节点固定分配在 node 0，清零。
	stats = kmem_cache_alloc_node(flow_stats_cache,
				      GFP_KERNEL | __GFP_ZERO, 0);
	if (!stats)
		goto err;

	spin_lock_init(&stats->lock);

	RCU_INIT_POINTER(flow->stats[0], stats);

	// 其余节点的统计槽先置空，待实际有该节点报文命中时再分配。
	for_each_node(node)
		if (node != 0)
			RCU_INIT_POINTER(flow->stats[node], NULL);

	return flow;
err:
	kmem_cache_free(flow_cache, flow);
	return ERR_PTR(-ENOMEM);
}

// 返回主表当前流数量。
int ovs_flow_tbl_count(const struct flow_table *table)
{
	return table->count;
}

// 用 flex_array 分配 n_buckets 个 hlist_head 组成的桶数组，并逐个初始化为空链表。
// flex_array 预分配(prealloc)保证后续 flex_array_get 不会再触发分配、可在原子上下文安全访问。
static struct flex_array *alloc_buckets(unsigned int n_buckets)
{
	struct flex_array *buckets;
	int i, err;

	buckets = flex_array_alloc(sizeof(struct hlist_head),
				   n_buckets, GFP_KERNEL);
	if (!buckets)
		return NULL;

	err = flex_array_prealloc(buckets, 0, n_buckets, GFP_KERNEL);
	if (err) {
		flex_array_free(buckets);
		return NULL;
	}

	for (i = 0; i < n_buckets; i++)
		INIT_HLIST_HEAD((struct hlist_head *)
					flex_array_get(buckets, i));

	return buckets;
}

// 真正释放一条流：释放未掩码 key、动作、各节点统计，最后归还 sw_flow 本体。
// 注意：不在此处减掩码引用计数（掩码由 ovs_flow_tbl_remove 处理）。
static void flow_free(struct sw_flow *flow)
{
	int node;

	// 仅当流以“完整 key”作为标识时才有 unmasked_key 需要释放（UFID 标识则不用）。
	if (ovs_identifier_is_key(&flow->id))
		kfree(flow->id.unmasked_key);
	kfree((struct sw_flow_actions __force *)flow->sf_acts);
	// 释放所有已分配的 per-node 统计节点。
	for_each_node(node)
		if (flow->stats[node])
			kmem_cache_free(flow_stats_cache,
					(struct flow_stats __force *)flow->stats[node]);
	kmem_cache_free(flow_cache, flow);
}

// RCU 回调：宽限期结束后真正释放流，确保并发读者不再引用它。
static void rcu_free_flow_callback(struct rcu_head *rcu)
{
	struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);

	flow_free(flow);
}

// 释放一条流。deferred=true 走 RCU 延迟释放（流可能仍被读者引用时用）；
// false 表示确认无人引用，可立即释放（如分配失败的错误路径）。
void ovs_flow_free(struct sw_flow *flow, bool deferred)
{
	if (!flow)
		return;

	if (deferred)
		call_rcu(&flow->rcu, rcu_free_flow_callback);
	else
		flow_free(flow);
}

// 释放桶数组本身（不含其中的流）。
static void free_buckets(struct flex_array *buckets)
{
	flex_array_free(buckets);
}


// 释放一个 table_instance 的骨架：桶数组 + 实例结构体（不负责其中的流）。
static void __table_instance_destroy(struct table_instance *ti)
{
	free_buckets(ti->buckets);
	kfree(ti);
}

// 分配一个新的哈希表实例：new_size 个桶，node_ver 从 0 起，随机 hash_seed。
static struct table_instance *table_instance_alloc(int new_size)
{
	struct table_instance *ti = kmalloc(sizeof(*ti), GFP_KERNEL);

	if (!ti)
		return NULL;

	ti->buckets = alloc_buckets(new_size);

	if (!ti->buckets) {
		kfree(ti);
		return NULL;
	}
	ti->n_buckets = new_size;
	ti->node_ver = 0;
	// 新表默认在销毁时会释放其中的流；rehash 搬迁后才会把旧表置为 keep_flows。
	ti->keep_flows = false;
	// 每个实例独立的随机哈希种子。
	get_random_bytes(&ti->hash_seed, sizeof(u32));

	return ti;
}

// 初始化整张流表：分配主表实例与 UFID 表实例，初始化掩码链表与计数。
// 成功返回 0，失败返回 -ENOMEM。
int ovs_flow_tbl_init(struct flow_table *table)
{
	struct table_instance *ti, *ufid_ti;

	ti = table_instance_alloc(TBL_MIN_BUCKETS);

	if (!ti)
		return -ENOMEM;

	ufid_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!ufid_ti)
		goto free_ti;

	rcu_assign_pointer(table->ti, ti);
	rcu_assign_pointer(table->ufid_ti, ufid_ti);
	INIT_LIST_HEAD(&table->mask_list);
	table->last_rehash = jiffies;
	table->count = 0;
	table->ufid_count = 0;
	return 0;

free_ti:
	__table_instance_destroy(ti);
	return -ENOMEM;
}

// RCU 回调：延迟销毁哈希表实例骨架。
static void flow_tbl_destroy_rcu_cb(struct rcu_head *rcu)
{
	struct table_instance *ti = container_of(rcu, struct table_instance, rcu);

	__table_instance_destroy(ti);
}

// 销毁主表实例 ti 及其配套的 UFID 表实例 ufid_ti。
// 若 ti->keep_flows 为真（rehash 后的旧实例），跳过释放流，只拆表结构。
// deferred 决定表实例本身是立即释放还是走 RCU 延迟。
static void table_instance_destroy(struct table_instance *ti,
				   struct table_instance *ufid_ti,
				   bool deferred)
{
	int i;

	if (!ti)
		return;

	BUG_ON(!ufid_ti);
	// rehash 旧实例：流已被新实例接管，只需拆表，不能释放流。
	if (ti->keep_flows)
		goto skip_flows;

	// 遍历每个桶，摘下并释放桶内所有流。
	for (i = 0; i < ti->n_buckets; i++) {
		struct sw_flow *flow;
		struct hlist_head *head = flex_array_get(ti->buckets, i);
		struct hlist_node *n;
		// 用当前实例的 node_ver 选中正确的一套 hlist_node。
		int ver = ti->node_ver;
		int ufid_ver = ufid_ti->node_ver;

		hlist_for_each_entry_safe(flow, n, head, flow_table.node[ver]) {
			// 先从主表摘链。
			hlist_del_rcu(&flow->flow_table.node[ver]);
			// 若流也在 UFID 表中，一并摘除，避免悬挂。
			if (ovs_identifier_is_ufid(&flow->id))
				hlist_del_rcu(&flow->ufid_table.node[ufid_ver]);
			ovs_flow_free(flow, deferred);
		}
	}

skip_flows:
	if (deferred) {
		// 表实例骨架经 RCU 延迟释放，避免正在遍历的读者踩空。
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		call_rcu(&ufid_ti->rcu, flow_tbl_destroy_rcu_cb);
	} else {
		__table_instance_destroy(ti);
		__table_instance_destroy(ufid_ti);
	}
}

/* No need for locking this function is called from RCU callback or
 * error path.
 */
// 销毁整张流表（连同其中的流）。仅在 RCU 回调或错误路径调用，故无需加锁、
// 直接同步释放(deferred=false)。
void ovs_flow_tbl_destroy(struct flow_table *table)
{
	struct table_instance *ti = rcu_dereference_raw(table->ti);
	struct table_instance *ufid_ti = rcu_dereference_raw(table->ufid_ti);

	table_instance_destroy(ti, ufid_ti, false);
}

// dump 迭代器：从 (*bucket, *last) 位置返回下一条流，供 netlink 遍历导出流表。
// *bucket 是当前桶下标，*last 是桶内已返回过的条数；返回 NULL 表示遍历结束。
struct sw_flow *ovs_flow_tbl_dump_next(struct table_instance *ti,
				       u32 *bucket, u32 *last)
{
	struct sw_flow *flow;
	struct hlist_head *head;
	int ver;
	int i;

	ver = ti->node_ver;
	while (*bucket < ti->n_buckets) {
		i = 0;
		head = flex_array_get(ti->buckets, *bucket);
		hlist_for_each_entry_rcu(flow, head, flow_table.node[ver]) {
			// 跳过本桶里已经返回过的前 *last 条。
			if (i < *last) {
				i++;
				continue;
			}
			// 记住下次从本桶第 i+1 条继续。
			*last = i + 1;
			return flow;
		}
		// 本桶遍历完，前进到下一桶并把桶内计数清零。
		(*bucket)++;
		*last = 0;
	}

	return NULL;
}

// 由预计算的 hash 值定位桶：再用 hash_seed 做一次 jhash 扰动，
// 然后对 n_buckets 取模（n_buckets 是 2 的幂，故用 & 掩码）。
static struct hlist_head *find_bucket(struct table_instance *ti, u32 hash)
{
	hash = jhash_1word(hash, ti->hash_seed);
	return flex_array_get(ti->buckets,
				(hash & (ti->n_buckets - 1)));
}

// 把流按其主表 hash 插入对应桶（用当前实例的 node_ver 那套节点）。
static void table_instance_insert(struct table_instance *ti,
				  struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->flow_table.hash);
	hlist_add_head_rcu(&flow->flow_table.node[ti->node_ver], head);
}

// 把流按其 UFID hash 插入 UFID 表对应桶。
static void ufid_table_instance_insert(struct table_instance *ti,
				       struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->ufid_table.hash);
	hlist_add_head_rcu(&flow->ufid_table.node[ti->node_ver], head);
}

// rehash 的搬迁核心：把 old 实例中的所有流重新哈希插入 new 实例。
// 关键：new 用与 old 相反的 node_ver（双缓冲）——同一条流的另一套 hlist_node，
// 因此搬迁期间旧表仍完整可查，直到指针切换完成。ufid 选择搬主表链还是 UFID 表链。
static void flow_table_copy_flows(struct table_instance *old,
				  struct table_instance *new, bool ufid)
{
	int old_ver;
	int i;

	old_ver = old->node_ver;
	new->node_ver = !old_ver;

	/* Insert in new table. */
	for (i = 0; i < old->n_buckets; i++) {
		struct sw_flow *flow;
		struct hlist_head *head;

		head = flex_array_get(old->buckets, i);

		if (ufid)
			hlist_for_each_entry(flow, head,
					     ufid_table.node[old_ver])
				ufid_table_instance_insert(new, flow);
		else
			hlist_for_each_entry(flow, head,
					     flow_table.node[old_ver])
				table_instance_insert(new, flow);
	}

	// 流已同时挂在新实例上；标记旧实例销毁时不要释放这些流。
	old->keep_flows = true;
}

// 新建一个 n_buckets 桶的实例，把 ti 的流全部搬进去后返回新实例。失败返回 NULL。
static struct table_instance *table_instance_rehash(struct table_instance *ti,
						    int n_buckets, bool ufid)
{
	struct table_instance *new_ti;

	new_ti = table_instance_alloc(n_buckets);
	if (!new_ti)
		return NULL;

	flow_table_copy_flows(ti, new_ti, ufid);

	return new_ti;
}

// 清空流表：新建空的主表与 UFID 表实例并原子替换旧实例、计数归零，
// 旧实例（连同其中的流）走 RCU 延迟销毁。成功返回 0。
int ovs_flow_tbl_flush(struct flow_table *flow_table)
{
	struct table_instance *old_ti, *new_ti;
	struct table_instance *old_ufid_ti, *new_ufid_ti;

	new_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!new_ti)
		return -ENOMEM;
	new_ufid_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!new_ufid_ti)
		goto err_free_ti;

	old_ti = ovsl_dereference(flow_table->ti);
	old_ufid_ti = ovsl_dereference(flow_table->ufid_ti);

	rcu_assign_pointer(flow_table->ti, new_ti);
	rcu_assign_pointer(flow_table->ufid_ti, new_ufid_ti);
	flow_table->last_rehash = jiffies;
	flow_table->count = 0;
	flow_table->ufid_count = 0;

	// deferred=true：等读者退出后再销毁旧表及其流。
	table_instance_destroy(old_ti, old_ufid_ti, true);
	return 0;

err_free_ti:
	__table_instance_destroy(new_ti);
	return -ENOMEM;
}

// 对 key 的 [range.start, range.end) 区间做 jhash2，得到用于哈希表的 32 位散列。
// 只哈希 range 内容而非整个 key：不同掩码关心的字段范围不同，且掩码外的字段在
// masked key 里为 0/无意义，按 range 计算既正确又省去无关字段的开销。
static u32 flow_hash(const struct sw_flow_key *key,
		     const struct sw_flow_key_range *range)
{
	int key_start = range->start;
	int key_end = range->end;
	const u32 *hash_key = (const u32 *)((const u8 *)key + key_start);
	// 以 u32 为单位的字数（range 长度保证是 4 的倍数）。
	int hash_u32s = (key_end - key_start) >> 2;

	/* Make sure number of hash bytes are multiple of u32. */
	BUILD_BUG_ON(sizeof(long) % sizeof(u32));

	return jhash2(hash_key, hash_u32s, 0);
}

// 返回比较/哈希应从 key 的哪个偏移开始：
// 若带隧道目的 IP(tun_key.ipv4_dst) 则从 0（含隧道字段）起；否则跳过隧道元数据，
// 从 phy 字段处（向下对齐到 long）起，以省去无关的隧道部分。
static int flow_key_start(const struct sw_flow_key *key)
{
	if (key->tun_key.ipv4_dst)
		return 0;
	else
		return rounddown(offsetof(struct sw_flow_key, phy),
					  sizeof(long));
}

// 比较两个 key 在 [key_start, key_end) 区间是否完全相等。
// 用异或累积到 diffs、最后判 0，是无分支的常数时间比较（避免逐字段短路，利于流水线）。
static bool cmp_key(const struct sw_flow_key *key1,
		    const struct sw_flow_key *key2,
		    int key_start, int key_end)
{
	const long *cp1 = (const long *)((const u8 *)key1 + key_start);
	const long *cp2 = (const long *)((const u8 *)key2 + key_start);
	long diffs = 0;
	int i;

	for (i = key_start; i < key_end;  i += sizeof(long))
		diffs |= *cp1++ ^ *cp2++;

	return diffs == 0;
}

// 比较流的“已掩码 key”与给定 masked key 在 range 内是否相等（哈希命中后的精确确认）。
static bool flow_cmp_masked_key(const struct sw_flow *flow,
				const struct sw_flow_key *key,
				const struct sw_flow_key_range *range)
{
	return cmp_key(&flow->key, key, range->start, range->end);
}

// 比较流保存的“未掩码原始 key”与 match 中的 key 是否精确相等。
// 用于精确查找(lookup_exact)：确保命中的不仅是同一掩码类，而是完全一样的规则。
static bool ovs_flow_cmp_unmasked_key(const struct sw_flow *flow,
				      const struct sw_flow_match *match)
{
	struct sw_flow_key *key = match->key;
	int key_start = flow_key_start(key);
	int key_end = match->range.end;

	BUG_ON(ovs_identifier_is_ufid(&flow->id));
	return cmp_key(flow->id.unmasked_key, key, key_start, key_end);
}

// 单个掩码的查找：把 unmasked key 用 mask 掩码，算 hash，定位桶后遍历冲突链，
// 逐个用“掩码指针 + hash + masked key”三重条件确认命中。命中返回流，否则 NULL。
static struct sw_flow *masked_flow_lookup(struct table_instance *ti,
					  const struct sw_flow_key *unmasked,
					  const struct sw_flow_mask *mask)
{
	struct sw_flow *flow;
	struct hlist_head *head;
	u32 hash;
	struct sw_flow_key masked_key;

	// 先按此掩码得到 masked key，再据其在本掩码 range 上哈希。
	ovs_flow_mask_key(&masked_key, unmasked, mask);
	hash = flow_hash(&masked_key, &mask->range);
	head = find_bucket(ti, hash);
	hlist_for_each_entry_rcu(flow, head, flow_table.node[ti->node_ver]) {
		// 先比指针/hash（廉价）再做全 key 比较（较贵），降低比较成本。
		if (flow->mask == mask && flow->flow_table.hash == hash &&
		    flow_cmp_masked_key(flow, &masked_key, &mask->range))
			return flow;
	}
	return NULL;
}

// 数据路径主查表：遍历掩码链表，对每个掩码各查一次，命中即返回。
// n_mask_hit 返回本次一共查了多少个掩码（性能/统计用）。在 RCU 读侧调用。
struct sw_flow *ovs_flow_tbl_lookup_stats(struct flow_table *tbl,
				    const struct sw_flow_key *key,
				    u32 *n_mask_hit)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ti);
	struct sw_flow_mask *mask;
	struct sw_flow *flow;

	*n_mask_hit = 0;
	list_for_each_entry_rcu(mask, &tbl->mask_list, list) {
		(*n_mask_hit)++;
		flow = masked_flow_lookup(ti, key, mask);
		if (flow)  /* Found */
			return flow;
	}
	return NULL;
}

// 不关心掩码命中数的查表封装。
struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *tbl,
				    const struct sw_flow_key *key)
{
	u32 __always_unused n_mask_hit;

	return ovs_flow_tbl_lookup_stats(tbl, key, &n_mask_hit);
}

// 精确查找：不仅要掩码类命中，还要原始未掩码 key 完全一致。
// 供控制面按规则精确定位一条流（增/改流时判重）。须在 ovs-mutex 下调用。
struct sw_flow *ovs_flow_tbl_lookup_exact(struct flow_table *tbl,
					  const struct sw_flow_match *match)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ti);
	struct sw_flow_mask *mask;
	struct sw_flow *flow;

	/* Always called under ovs-mutex. */
	list_for_each_entry(mask, &tbl->mask_list, list) {
		flow = masked_flow_lookup(ti, match->key, mask);
		// 掩码命中后，还要求它以完整 key 为标识且未掩码 key 完全匹配。
		if (flow && ovs_identifier_is_key(&flow->id) &&
		    ovs_flow_cmp_unmasked_key(flow, match))
			return flow;
	}
	return NULL;
}

// 对 UFID 字节串做 jhash，得到 UFID 表的散列值。
static u32 ufid_hash(const struct sw_flow_id *sfid)
{
	return jhash(sfid->ufid, sfid->ufid_len, 0);
}

// 比较流的 UFID 与给定 UFID 是否一致（长度 + 内容）。
static bool ovs_flow_cmp_ufid(const struct sw_flow *flow,
			      const struct sw_flow_id *sfid)
{
	if (flow->id.ufid_len != sfid->ufid_len)
		return false;

	return !memcmp(flow->id.ufid, sfid->ufid, sfid->ufid_len);
}

// 通用比较：流用 UFID 标识则比 masked key，否则比未掩码 key。
bool ovs_flow_cmp(const struct sw_flow *flow, const struct sw_flow_match *match)
{
	if (ovs_identifier_is_ufid(&flow->id))
		return flow_cmp_masked_key(flow, match->key, &match->range);

	return ovs_flow_cmp_unmasked_key(flow, match);
}

// 在 UFID 哈希表中按 UFID 查流（不走掩码链表，UFID 本身即精确键）。
struct sw_flow *ovs_flow_tbl_lookup_ufid(struct flow_table *tbl,
					 const struct sw_flow_id *ufid)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ufid_ti);
	struct sw_flow *flow;
	struct hlist_head *head;
	u32 hash;

	hash = ufid_hash(ufid);
	head = find_bucket(ti, hash);
	hlist_for_each_entry_rcu(flow, head, ufid_table.node[ti->node_ver]) {
		if (flow->ufid_table.hash == hash &&
		    ovs_flow_cmp_ufid(flow, ufid))
			return flow;
	}
	return NULL;
}

// 返回掩码链表中掩码的个数（即每次查表最多要遍历几个掩码）。
int ovs_flow_tbl_num_masks(const struct flow_table *table)
{
	struct sw_flow_mask *mask;
	int num = 0;

	list_for_each_entry(mask, &table->mask_list, list)
		num++;

	return num;
}

// 扩容：桶数翻倍并把流搬到新实例。
static struct table_instance *table_instance_expand(struct table_instance *ti,
						    bool ufid)
{
	return table_instance_rehash(ti, ti->n_buckets * 2, ufid);
}

/* Remove 'mask' from the mask list, if it is not needed any more. */
// 掩码解引用：ref_count 减 1，减到 0 说明再无流使用它，从链表摘除并 RCU 释放。
// 多条流共享同一掩码，故用引用计数管理其生命周期。须持 ovs-lock。
static void flow_mask_remove(struct flow_table *tbl, struct sw_flow_mask *mask)
{
	if (mask) {
		/* ovs-lock is required to protect mask-refcount and
		 * mask list.
		 */
		ASSERT_OVSL();
		BUG_ON(!mask->ref_count);
		mask->ref_count--;

		if (!mask->ref_count) {
			list_del_rcu(&mask->list);
			kfree_rcu(mask, rcu);
		}
	}
}

/* Must be called with OVS mutex held. */
// 从流表移除一条流：从主表（及 UFID 表）摘链、更新计数、并给其掩码解引用。
// 注意 flow->mask 不置 NULL——RCU 读者在宽限期内仍可能访问它。须持 ovs-mutex。
void ovs_flow_tbl_remove(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ti = ovsl_dereference(table->ti);
	struct table_instance *ufid_ti = ovsl_dereference(table->ufid_ti);

	BUG_ON(table->count == 0);
	hlist_del_rcu(&flow->flow_table.node[ti->node_ver]);
	table->count--;
	if (ovs_identifier_is_ufid(&flow->id)) {
		hlist_del_rcu(&flow->ufid_table.node[ufid_ti->node_ver]);
		table->ufid_count--;
	}

	/* RCU delete the mask. 'flow->mask' is not NULLed, as it should be
	 * accessible as long as the RCU read lock is held.
	 */
	flow_mask_remove(table, flow->mask);
}

// 分配一个新掩码，初始引用计数为 1。
static struct sw_flow_mask *mask_alloc(void)
{
	struct sw_flow_mask *mask;

	mask = kmalloc(sizeof(*mask), GFP_KERNEL);
	if (mask)
		mask->ref_count = 1;

	return mask;
}

// 判断两个掩码是否相同：range 起止一致且 range 内的掩码位完全相同。用于掩码去重。
static bool mask_equal(const struct sw_flow_mask *a,
		       const struct sw_flow_mask *b)
{
	const u8 *a_ = (const u8 *)&a->key + a->range.start;
	const u8 *b_ = (const u8 *)&b->key + b->range.start;

	return  (a->range.end == b->range.end)
		&& (a->range.start == b->range.start)
		&& (memcmp(a_, b_, range_n_bytes(&a->range)) == 0);
}

// 在掩码链表中查找与给定掩码相同的已有掩码，找到返回它（用于复用/去重）。
static struct sw_flow_mask *flow_mask_find(const struct flow_table *tbl,
					   const struct sw_flow_mask *mask)
{
	struct list_head *ml;

	list_for_each(ml, &tbl->mask_list) {
		struct sw_flow_mask *m;
		m = container_of(ml, struct sw_flow_mask, list);
		if (mask_equal(mask, m))
			return m;
	}

	return NULL;
}

/* Add 'mask' into the mask list, if it is not already there. */
// 为流关联掩码：链表中已有相同掩码则复用并 ref_count++；否则新建掩码加入链表。
// 结果写入 flow->mask。这样相同通配模式的众多流共享一份掩码对象。
static int flow_mask_insert(struct flow_table *tbl, struct sw_flow *flow,
			    const struct sw_flow_mask *new)
{
	struct sw_flow_mask *mask;
	mask = flow_mask_find(tbl, new);
	if (!mask) {
		/* Allocate a new mask if none exsits. */
		mask = mask_alloc();
		if (!mask)
			return -ENOMEM;
		mask->key = new->key;
		mask->range = new->range;
		list_add_rcu(&mask->list, &tbl->mask_list);
	} else {
		BUG_ON(!mask->ref_count);
		mask->ref_count++;
	}

	flow->mask = mask;
	return 0;
}

/* Must be called with OVS mutex held. */
// 把流插入主哈希表：按其掩码 range 算 hash 后入桶、count++，
// 并在必要时扩容或到点做周期性 rehash（新实例经 RCU 替换、旧实例延迟释放）。须持 ovs-mutex。
static void flow_key_insert(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *new_ti = NULL;
	struct table_instance *ti;

	flow->flow_table.hash = flow_hash(&flow->key, &flow->mask->range);
	ti = ovsl_dereference(table->ti);
	table_instance_insert(ti, flow);
	table->count++;

	/* Expand table, if necessary, to make room. */
	// 流数超过桶数则扩容；否则若超过 rehash 周期则原大小重排（换种子）。
	if (table->count > ti->n_buckets)
		new_ti = table_instance_expand(ti, false);
	else if (time_after(jiffies, table->last_rehash + REHASH_INTERVAL))
		new_ti = table_instance_rehash(ti, ti->n_buckets, false);

	if (new_ti) {
		rcu_assign_pointer(table->ti, new_ti);
		call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		table->last_rehash = jiffies;
	}
}

/* Must be called with OVS mutex held. */
// 把带 UFID 的流插入 UFID 哈希表：算 UFID hash 入桶、ufid_count++，
// 满则扩容。须持 ovs-mutex。
static void flow_ufid_insert(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ti;

	flow->ufid_table.hash = ufid_hash(&flow->id);
	ti = ovsl_dereference(table->ufid_ti);
	ufid_table_instance_insert(ti, flow);
	table->ufid_count++;

	/* Expand table, if necessary, to make room. */
	if (table->ufid_count > ti->n_buckets) {
		struct table_instance *new_ti;

		new_ti = table_instance_expand(ti, true);
		if (new_ti) {
			rcu_assign_pointer(table->ufid_ti, new_ti);
			call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
		}
	}
}

/* Must be called with OVS mutex held. */
// 对外的插入入口：先关联/去重掩码，再插入主表，若带 UFID 再插入 UFID 表。
// 顺序保证掩码就位后才计算 hash。须持 ovs-mutex。
int ovs_flow_tbl_insert(struct flow_table *table, struct sw_flow *flow,
			const struct sw_flow_mask *mask)
{
	int err;

	err = flow_mask_insert(table, flow, mask);
	if (err)
		return err;
	flow_key_insert(table, flow);
	if (ovs_identifier_is_ufid(&flow->id))
		flow_ufid_insert(table, flow);

	return 0;
}

/* Initializes the flow module.
 * Returns zero if successful or a negative error code. */
// 模块初始化：创建 sw_flow 与 flow_stats 两个 slab 缓存。
// sw_flow 缓存对象大小额外加上“每个可能 NUMA 节点一个 stats 指针”的柔性数组空间。
// 两处 BUILD_BUG_ON 强制 sw_flow_key 按 long 对齐且大小是 long 的整数倍，
// 以保证前述按 long 步长的掩码/比较/哈希操作不会越界或错位。
int ovs_flow_init(void)
{
	BUILD_BUG_ON(__alignof__(struct sw_flow_key) % __alignof__(long));
	BUILD_BUG_ON(sizeof(struct sw_flow_key) % sizeof(long));

	flow_cache = kmem_cache_create("sw_flow", sizeof(struct sw_flow)
				       + (num_possible_nodes()
					  * sizeof(struct flow_stats *)),
				       0, 0, NULL);
	if (flow_cache == NULL)
		return -ENOMEM;

	flow_stats_cache
		= kmem_cache_create("sw_flow_stats", sizeof(struct flow_stats),
				    0, SLAB_HWCACHE_ALIGN, NULL);
	if (flow_stats_cache == NULL) {
		kmem_cache_destroy(flow_cache);
		flow_cache = NULL;
		return -ENOMEM;
	}

	return 0;
}

/* Uninitializes the flow module. */
// 模块卸载：销毁两个 slab 缓存。
void ovs_flow_exit(void)
{
	kmem_cache_destroy(flow_stats_cache);
	kmem_cache_destroy(flow_cache);
}
