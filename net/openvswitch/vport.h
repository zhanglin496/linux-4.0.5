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

#ifndef VPORT_H
#define VPORT_H 1

#include <linux/if_tunnel.h>
#include <linux/list.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/reciprocal_div.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/u64_stats_sync.h>

#include "datapath.h"

struct vport;
struct vport_parms;

/* The following definitions are for users of the vport subsytem: */
// 以下声明面向 vport 子系统的“使用者”（datapath 核心等），
// 隐藏了 netdev/internal/gre/vxlan/geneve 等各类端口的底层差异。

// 每个网络命名空间(net namespace)持有的 vport 相关状态。
struct vport_net {
	// 该 namespace 下的 GRE 隧道端口(全局只有一个)，RCU 保护。
	struct vport __rcu *gre_vport;
};

int ovs_vport_init(void);
void ovs_vport_exit(void);

struct vport *ovs_vport_add(const struct vport_parms *);
void ovs_vport_del(struct vport *);

struct vport *ovs_vport_locate(const struct net *net, const char *name);

void ovs_vport_get_stats(struct vport *, struct ovs_vport_stats *);

int ovs_vport_set_options(struct vport *, struct nlattr *options);
int ovs_vport_get_options(const struct vport *, struct sk_buff *);

int ovs_vport_set_upcall_portids(struct vport *, const struct nlattr *pids);
int ovs_vport_get_upcall_portids(const struct vport *, struct sk_buff *);
u32 ovs_vport_find_upcall_portid(const struct vport *, struct sk_buff *);

int ovs_vport_send(struct vport *, struct sk_buff *);

int ovs_tunnel_get_egress_info(struct ovs_tunnel_info *egress_tun_info,
			       struct net *net,
			       const struct ovs_tunnel_info *tun_info,
			       u8 ipproto,
			       u32 skb_mark,
			       __be16 tp_src,
			       __be16 tp_dst);
int ovs_vport_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				  struct ovs_tunnel_info *info);

/* The following definitions are for implementers of vport devices: */
// 以下声明面向 vport 各类端口的“实现者”（netdev/internal/tunnel 等具体 ops）。

// vport 的错误统计。与 percpu_stats(正常收发统计)分开，
// 这些计数是丢包/出错等异常路径累加，用原子量避免加锁。
struct vport_err_stats {
	atomic_long_t rx_dropped;	// 收方向丢包数
	atomic_long_t rx_errors;	// 收方向错误数
	atomic_long_t tx_dropped;	// 发方向丢包数
	atomic_long_t tx_errors;	// 发方向错误数
};
/**
 * struct vport_portids - array of netlink portids of a vport.
 *                        must be protected by rcu.
 * @rn_ids: The reciprocal value of @n_ids.
 * @rcu: RCU callback head for deferred destruction.
 * @n_ids: Size of @ids array.
 * @ids: Array storing the Netlink socket pids to be used for packets received
 * on this port that miss the flow table.
 */
// 一个端口对应的“上送用户态”netlink portid 数组。
// 当报文在流表里 miss 时需要 upcall 给用户态(ovs-vswitchd)处理，
// 多个 portid(对应多个用户态 socket)可分担 upcall 负载。
// 用 skb hash 对 n_ids 取模来选一个 portid，取模用 reciprocal_div
// 把除法转成乘加，避免热路径上的整数除法开销。
struct vport_portids {
	// n_ids 的“倒数”预计算值，配合 reciprocal_divide 实现快速取模。
	struct reciprocal_value rn_ids;
	// RCU 回收头：portid 数组更新时用 kfree_rcu 延迟释放旧数组。
	struct rcu_head rcu;
	u32 n_ids;	// ids 数组元素个数
	u32 ids[];	// 变长数组，存放各 netlink portid
};

/**
 * struct vport - one port within a datapath
 * @rcu: RCU callback head for deferred destruction.
 * @dp: Datapath to which this port belongs.
 * @upcall_portids: RCU protected 'struct vport_portids'.
 * @port_no: Index into @dp's @ports array.
 * @hash_node: Element in @dev_table hash table in vport.c.
 * @dp_hash_node: Element in @datapath->ports hash table in datapath.c.
 * @ops: Class structure.
 * @percpu_stats: Points to per-CPU statistics used and maintained by vport
 * @err_stats: Points to error statistics used and maintained by vport
 * @detach_list: list used for detaching vport in net-exit call.
 */
// datapath 中的“一个端口”，是 OVS 对交换机端口的抽象。
// 具体类型的私有数据紧跟在本结构之后(见 vport_priv)。
struct vport {
	struct rcu_head rcu;			// 延迟释放用的 RCU 回收头
	struct datapath	*dp;			// 该端口所属的 datapath(交换机)
	// 上送用户态的 portid 数组，RCU 保护，可动态更新
	struct vport_portids __rcu *upcall_portids;
	u16 port_no;				// 在 dp->ports 中的端口号(索引)

	// 挂在 vport.c 全局 dev_table 哈希表上(按 net+name 索引，供 locate)
	struct hlist_node hash_node;
	// 挂在 datapath->ports 哈希表上(按 port_no 索引)
	struct hlist_node dp_hash_node;
	const struct vport_ops *ops;		// 本端口类型的操作集(“类”)

	// per-CPU 正常收发统计(包数/字节数)，无锁按 CPU 累加
	struct pcpu_sw_netstats __percpu *percpu_stats;

	struct vport_err_stats err_stats;	// 错误/丢包统计(原子量)
	struct list_head detach_list;		// net-exit 时批量摘除端口用的链表
};

/**
 * struct vport_parms - parameters for creating a new vport
 *
 * @name: New vport's name.
 * @type: New vport's type.
 * @options: %OVS_VPORT_ATTR_OPTIONS attribute from Netlink message, %NULL if
 * none was supplied.
 * @dp: New vport's datapath.
 * @port_no: New vport's port number.
 */
// 创建一个新 vport 时传入的参数集合。
struct vport_parms {
	const char *name;		// 新端口名字(如 "eth0"、"vxlan_sys_4789")
	enum ovs_vport_type type;	// 端口类型(决定用哪套 vport_ops)
	// 来自 netlink 的 OVS_VPORT_ATTR_OPTIONS 属性，无则为 NULL
	struct nlattr *options;

	/* For ovs_vport_alloc(). */
	// 以下字段供 ovs_vport_alloc() 填入 vport 结构
	struct datapath *dp;		// 新端口归属的 datapath
	u16 port_no;			// 分配给新端口的端口号
	struct nlattr *upcall_portids;	// 初始的 upcall portid 数组
};

/**
 * struct vport_ops - definition of a type of virtual port
 *
 * @type: %OVS_VPORT_TYPE_* value for this type of virtual port.
 * @create: Create a new vport configured as specified.  On success returns
 * a new vport allocated with ovs_vport_alloc(), otherwise an ERR_PTR() value.
 * @destroy: Destroys a vport.  Must call vport_free() on the vport but not
 * before an RCU grace period has elapsed.
 * @set_options: Modify the configuration of an existing vport.  May be %NULL
 * if modification is not supported.
 * @get_options: Appends vport-specific attributes for the configuration of an
 * existing vport to a &struct sk_buff.  May be %NULL for a vport that does not
 * have any configuration.
 * @get_name: Get the device's name.
 * @send: Send a packet on the device.  Returns the length of the packet sent,
 * zero for dropped packets or negative for error.
 * @get_egress_tun_info: Get the egress tunnel 5-tuple and other info for
 * a packet.
 */
// 某一“类型”虚拟端口的操作集(相当于该类端口的“类”/虚函数表)。
// netdev、internal、gre、vxlan、geneve 各自实现一份并注册到 vport_ops_list。
struct vport_ops {
	enum ovs_vport_type type;	// 该 ops 对应的端口类型

	/* Called with ovs_mutex. */
	// 以下 create/destroy 在持有 ovs_mutex 时调用
	// 创建一个新端口；成功返回 ovs_vport_alloc() 分配的 vport，失败返回 ERR_PTR
	struct vport *(*create)(const struct vport_parms *);
	// 销毁端口；须(在 RCU 宽限期后)调用 vport_free
	void (*destroy)(struct vport *);

	// 修改/读取端口配置，转发自 ovs_vport_set/get_options；不支持则可为 NULL
	int (*set_options)(struct vport *, struct nlattr *);
	int (*get_options)(const struct vport *, struct sk_buff *);

	/* Called with rcu_read_lock or ovs_mutex. */
	// 取端口设备名(在 rcu 或 ovs_mutex 下调用)
	const char *(*get_name)(const struct vport *);

	// 从端口发出报文；返回已发送长度，0 表示丢弃，负值表示出错
	int (*send)(struct vport *, struct sk_buff *);
	// 隧道端口专用：为报文计算出向隧道封装信息(5 元组等)
	int (*get_egress_tun_info)(struct vport *, struct sk_buff *,
				   struct ovs_tunnel_info *);

	struct module *owner;		// 实现该类端口的内核模块(引用计数用)
	struct list_head list;		// 挂入全局 vport_ops_list 的链表节点
};

enum vport_err_type {
	VPORT_E_RX_DROPPED,	// 收方向丢包
	VPORT_E_RX_ERROR,	// 收方向出错
	VPORT_E_TX_DROPPED,	// 发方向丢包
	VPORT_E_TX_ERROR,	// 发方向出错
};

struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *,
			      const struct vport_parms *);
void ovs_vport_free(struct vport *);
void ovs_vport_deferred_free(struct vport *vport);

#define VPORT_ALIGN 8

/**
 *	vport_priv - access private data area of vport
 *
 * @vport: vport to access
 *
 * If a nonzero size was passed in priv_size of vport_alloc() a private data
 * area was allocated on creation.  This allows that area to be accessed and
 * used for any purpose needed by the vport implementer.
 */
// 定位 vport 结构之后的“私有数据区”。
// 分配时 vport 结构与私有区连成一块内存，私有区起点按 VPORT_ALIGN 对齐，
// 因此私有区地址 = vport 地址 + 对齐后的 sizeof(struct vport)。
static inline void *vport_priv(const struct vport *vport)
{
	return (u8 *)(uintptr_t)vport + ALIGN(sizeof(struct vport), VPORT_ALIGN);
}

/**
 *	vport_from_priv - lookup vport from private data pointer
 *
 * @priv: Start of private data area.
 *
 * It is sometimes useful to translate from a pointer to the private data
 * area to the vport, such as in the case where the private data pointer is
 * the result of a hash table lookup.  @priv must point to the start of the
 * private data area.
 */
// vport_priv 的逆运算：由私有区指针反推出 vport 结构指针。
static inline struct vport *vport_from_priv(void *priv)
{
	return (struct vport *)((u8 *)priv - ALIGN(sizeof(struct vport), VPORT_ALIGN));
}

void ovs_vport_receive(struct vport *, struct sk_buff *,
		       const struct ovs_tunnel_info *);

// push 报文头(如隧道封装)后修正校验和：仅在 skb 采用
// CHECKSUM_COMPLETE 时，把新压入数据的部分校验和累加进 skb->csum。
static inline void ovs_skb_postpush_rcsum(struct sk_buff *skb,
				      const void *start, unsigned int len)
{
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_add(skb->csum, csum_partial(start, len, 0));
}

int ovs_vport_ops_register(struct vport_ops *ops);
void ovs_vport_ops_unregister(struct vport_ops *ops);

// 隧道封装前的路由查找内联函数：用隧道 key 中的源/目的 IP、tos、mark、
// 上层协议构造 flowi4，调用 ip_route_output_key 得到路由 rtable。
// 供隧道端口在封装外层 IP 头前确定出接口和源地址。
static inline struct rtable *ovs_tunnel_route_lookup(struct net *net,
						     const struct ovs_key_ipv4_tunnel *key,
						     u32 mark,
						     struct flowi4 *fl,
						     u8 protocol)
{
	struct rtable *rt;

	memset(fl, 0, sizeof(*fl));
	fl->daddr = key->ipv4_dst;		// 隧道外层目的 IP
	fl->saddr = key->ipv4_src;		// 隧道外层源 IP(可能为 0，由路由决定)
	fl->flowi4_tos = RT_TOS(key->ipv4_tos);	// 取 tos 高位参与路由
	fl->flowi4_mark = mark;			// 供策略路由使用的 fwmark
	fl->flowi4_proto = protocol;		// 外层 IP 的上层协议(如 UDP/GRE)

	rt = ip_route_output_key(net, fl);
	return rt;
}
#endif /* vport.h */
