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

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H 1

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

// table_instance：一次具体的哈希表实例（bucket 数组 + 元数据）。
// flow_table 通过 RCU 指针指向当前的 table_instance；rehash（扩容/收缩/换种子）
// 时会新建一个 table_instance、把所有流搬过去，再原子替换指针，旧实例经 RCU 延迟释放。
// 这样查表侧（读者）在替换过程中始终能看到一份完整一致的哈希表，无需加锁。
struct table_instance {
	// 桶数组：用 flex_array 分配，每个元素是一个 hlist_head（哈希冲突链表头）。
	// flex_array 便于分配很大的连续逻辑数组而不要求物理连续。
	struct flex_array *buckets;
	// 桶数量，始终是 2 的幂，故取模可用 hash & (n_buckets - 1)。
	unsigned int n_buckets;
	// 用于 call_rcu 延迟释放本实例。
	struct rcu_head rcu;
	// 节点版本 0/1：sw_flow 内每条链的 hlist_node 有两套（node[0]/node[1]），
	// rehash 时新实例用另一套版本挂链，从而在搬迁期间新旧两个哈希表可同时挂着
	// 同一批流而互不干扰（双缓冲）。
	int node_ver;
	// 每个实例独立的哈希扰动种子，每次 rehash 重新随机，用于打散分布、抗碰撞攻击。
	u32 hash_seed;
	// 销毁本实例时是否跳过释放其中的流：rehash 后旧实例的流已被新实例接管，
	// 置 true 表示“只拆表、别把流也释放了”。
	bool keep_flows;
};

// flow_table：OVS 数据路径的整张流表对外结构。
// 采用“掩码链表 + 哈希表”实现通配（megaflow）匹配，见 flow_table.c 顶部说明。
struct flow_table {
	// 主哈希表实例：以“掩码后的 key”为索引，供报文快速路径查表。
	struct table_instance __rcu *ti;
	// UFID 哈希表实例：以用户空间下发的唯一流标识（UFID）为索引，供控制面按 UFID 查流。
	struct table_instance __rcu *ufid_ti;
	// 掩码链表：表中出现过的所有不同掩码（去重后）。查表时需对每个掩码各查一次。
	struct list_head mask_list;
	// 上次 rehash 的时间戳（jiffies），配合 REHASH_INTERVAL 做周期性重哈希。
	unsigned long last_rehash;
	// 主表中的流数量。
	unsigned int count;
	// UFID 表中的流数量（只有带 UFID 的流才计入）。
	unsigned int ufid_count;
};

extern struct kmem_cache *flow_stats_cache;

int ovs_flow_init(void);
void ovs_flow_exit(void);

struct sw_flow *ovs_flow_alloc(void);
void ovs_flow_free(struct sw_flow *, bool deferred);

int ovs_flow_tbl_init(struct flow_table *);
int ovs_flow_tbl_count(const struct flow_table *table);
void ovs_flow_tbl_destroy(struct flow_table *table);
int ovs_flow_tbl_flush(struct flow_table *flow_table);

int ovs_flow_tbl_insert(struct flow_table *table, struct sw_flow *flow,
			const struct sw_flow_mask *mask);
void ovs_flow_tbl_remove(struct flow_table *table, struct sw_flow *flow);
int  ovs_flow_tbl_num_masks(const struct flow_table *table);
struct sw_flow *ovs_flow_tbl_dump_next(struct table_instance *table,
				       u32 *bucket, u32 *idx);
struct sw_flow *ovs_flow_tbl_lookup_stats(struct flow_table *,
				    const struct sw_flow_key *,
				    u32 *n_mask_hit);
struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *,
				    const struct sw_flow_key *);
struct sw_flow *ovs_flow_tbl_lookup_exact(struct flow_table *tbl,
					  const struct sw_flow_match *match);
struct sw_flow *ovs_flow_tbl_lookup_ufid(struct flow_table *,
					 const struct sw_flow_id *);

bool ovs_flow_cmp(const struct sw_flow *, const struct sw_flow_match *);

void ovs_flow_mask_key(struct sw_flow_key *dst, const struct sw_flow_key *src,
		       const struct sw_flow_mask *mask);
#endif /* flow_table.h */
