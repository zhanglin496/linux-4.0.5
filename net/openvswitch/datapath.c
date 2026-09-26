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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/etherdevice.h>
#include <linux/genetlink.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ethtool.h>
#include <linux/wait.h>
#include <asm/div64.h>
#include <linux/highmem.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include <linux/openvswitch.h>
#include <linux/rculist.h>
#include <linux/dmi.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "datapath.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

int ovs_net_id __read_mostly;
EXPORT_SYMBOL_GPL(ovs_net_id);

// packet/flow/datapath 三个 Generic Netlink 命令族（vport 族定义在文件后半、并对外可见）
static struct genl_family dp_packet_genl_family;
static struct genl_family dp_flow_genl_family;
static struct genl_family dp_datapath_genl_family;

static const struct nla_policy flow_policy[];

// flow 族的组播组：新增/删除流表项时向订阅者广播
static const struct genl_multicast_group ovs_dp_flow_multicast_group = {
	.name = OVS_FLOW_MCGROUP,
};

// datapath 族的组播组
static const struct genl_multicast_group ovs_dp_datapath_multicast_group = {
	.name = OVS_DATAPATH_MCGROUP,
};

// vport 族的组播组
static const struct genl_multicast_group ovs_dp_vport_multicast_group = {
	.name = OVS_VPORT_MCGROUP,
};

/* Check if need to build a reply message.
 * OVS userspace sets the NLM_F_ECHO flag if it needs the reply. */
// 判断是否需要构造并发送回复：用户态设了 NLM_F_ECHO，或该组播组当前有监听者
static bool ovs_must_notify(struct genl_family *family, struct genl_info *info,
			    unsigned int group)
{
	return info->nlhdr->nlmsg_flags & NLM_F_ECHO ||
	       genl_has_listeners(family, genl_info_net(info), group);
}

// 向请求发起者以及订阅的组播组发送通告消息
static void ovs_notify(struct genl_family *family,
		       struct sk_buff *skb, struct genl_info *info)
{
	genl_notify(family, skb, genl_info_net(info), info->snd_portid,
		    0, info->nlhdr, GFP_KERNEL);
}

/**
 * DOC: Locking:
 *
 * All writes e.g. Writes to device state (add/remove datapath, port, set
 * operations on vports, etc.), Writes to other state (flow table
 * modifications, set miscellaneous datapath parameters, etc.) are protected
 * by ovs_lock.
 *
 * Reads are protected by RCU.
 *
 * There are a few special cases (mostly stats) that have their own
 * synchronization but they nest under all of above and don't interact with
 * each other.
 *
 * The RTNL lock nests inside ovs_mutex.
 */
// 加锁模型总结：
//   - 所有“写”（增删 datapath/端口、改流表、设置参数等）都由全局 ovs_mutex 串行保护；
//   - 所有“读”走 RCU（rcu_read_lock），与写侧并发但看到的是一致快照；
//   - 少数统计计数用各自的 u64_stats_sync 同步，嵌套在上述锁之下、彼此不交互；
//   - 锁的嵌套顺序：ovs_mutex 在外，RTNL 锁在内（先拿 ovs_mutex 再拿 rtnl）。

static DEFINE_MUTEX(ovs_mutex);

// 获取全局写锁 ovs_mutex
void ovs_lock(void)
{
	mutex_lock(&ovs_mutex);
}

// 释放全局写锁 ovs_mutex
void ovs_unlock(void)
{
	mutex_unlock(&ovs_mutex);
}

#ifdef CONFIG_LOCKDEP
// 供 lockdep 断言使用：返回当前是否持有 ovs_mutex
int lockdep_ovsl_is_held(void)
{
	if (debug_locks)
		return lockdep_is_held(&ovs_mutex);
	else
		return 1;
}
EXPORT_SYMBOL_GPL(lockdep_ovsl_is_held);
#endif

static struct vport *new_vport(const struct vport_parms *);
static int queue_gso_packets(struct datapath *dp, struct sk_buff *,
			     const struct sw_flow_key *,
			     const struct dp_upcall_info *);
static int queue_userspace_packet(struct datapath *dp, struct sk_buff *,
				  const struct sw_flow_key *,
				  const struct dp_upcall_info *);

/* Must be called with rcu_read_lock. */
// 根据 dp 网络设备的 ifindex 找到对应 datapath；须在 rcu_read_lock 下调用
static struct datapath *get_dp_rcu(struct net *net, int dp_ifindex)
{
	// 先按 ifindex 找到网络设备，再判断它是不是 OVS 内部设备并取回其 vport->dp
	struct net_device *dev = dev_get_by_index_rcu(net, dp_ifindex);

	if (dev) {
		struct vport *vport = ovs_internal_dev_get_vport(dev);
		if (vport)
			return vport->dp;
	}

	return NULL;
}

/* The caller must hold either ovs_mutex or rcu_read_lock to keep the
 * returned dp pointer valid.
 */
// get_dp_rcu 的封装：调用者须已持有 ovs_mutex 或 rcu_read_lock 以保证返回指针有效
static inline struct datapath *get_dp(struct net *net, int dp_ifindex)
{
	struct datapath *dp;

	WARN_ON_ONCE(!rcu_read_lock_held() && !lockdep_ovsl_is_held());
	rcu_read_lock();
	dp = get_dp_rcu(net, dp_ifindex);
	rcu_read_unlock();

	return dp;
}

/* Must be called with rcu_read_lock or ovs_mutex. */
// 返回 datapath 的名字：即其本地内部口 OVSP_LOCAL 的设备名
const char *ovs_dp_name(const struct datapath *dp)
{
	struct vport *vport = ovs_vport_ovsl_rcu(dp, OVSP_LOCAL);
	return vport->ops->get_name(vport);
}

// 返回 datapath 对应网络设备的 ifindex（本地口的底层 net_device），无本地口则返回 0
static int get_dpifindex(const struct datapath *dp)
{
	struct vport *local;
	int ifindex;

	rcu_read_lock();

	local = ovs_vport_rcu(dp, OVSP_LOCAL);
	if (local)
		ifindex = netdev_vport_priv(local)->dev->ifindex;
	else
		ifindex = 0;

	rcu_read_unlock();

	return ifindex;
}

// RCU 宽限期后真正释放 datapath 的回调：销毁流表、释放 per-CPU 统计、端口数组、netns 引用
static void destroy_dp_rcu(struct rcu_head *rcu)
{
	struct datapath *dp = container_of(rcu, struct datapath, rcu);

	ovs_flow_tbl_destroy(&dp->table);
	free_percpu(dp->stats_percpu);
	release_net(ovs_dp_get_net(dp));
	kfree(dp->ports);
	kfree(dp);
}

// 根据端口号定位其所在的哈希桶（低位与掩码取模，BUCKETS 为 2 的幂）
static struct hlist_head *vport_hash_bucket(const struct datapath *dp,
					    u16 port_no)
{
	return &dp->ports[port_no & (DP_VPORT_HASH_BUCKETS - 1)];
}

/* Called with ovs_mutex or RCU read lock. */
// 在 datapath 的端口哈希表中按端口号查找 vport；须持有 ovs_mutex 或 rcu_read_lock
struct vport *ovs_lookup_vport(const struct datapath *dp, u16 port_no)
{
	struct vport *vport;
	struct hlist_head *head;

	head = vport_hash_bucket(dp, port_no);
	hlist_for_each_entry_rcu(vport, head, dp_hash_node) {
		if (vport->port_no == port_no)
			return vport;
	}
	return NULL;
}

/* Called with ovs_mutex. */
// 创建并把新 vport 挂入 datapath 的端口哈希表；须持有 ovs_mutex
static struct vport *new_vport(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = ovs_vport_add(parms);
	if (!IS_ERR(vport)) {
		struct datapath *dp = parms->dp;
		struct hlist_head *head = vport_hash_bucket(dp, vport->port_no);

		// 用 RCU 方式插入，使并发读者要么看到旧表要么看到含新端口的表
		hlist_add_head_rcu(&vport->dp_hash_node, head);
	}
	return vport;
}

// 从 datapath 摘除并销毁一个端口；须持有 ovs_mutex
void ovs_dp_detach_port(struct vport *p)
{
	ASSERT_OVSL();

	/* First drop references to device. */
	// 先从哈希表中 RCU 摘链，使新读者不再看到它
	hlist_del_rcu(&p->dp_hash_node);

	/* Then destroy it. */
	// 再销毁 vport（内部会经 RCU 延迟释放）
	ovs_vport_del(p);
}

/* Must be called with rcu_read_lock. */
// 数据面收包核心：查流表，命中则执行动作并计 n_hit，未命中则 upcall 上送并计 n_missed
// 须在 rcu_read_lock 下调用（读流表与端口）
void ovs_dp_process_packet(struct sk_buff *skb, struct sw_flow_key *key)
{
	const struct vport *p = OVS_CB(skb)->input_vport;
	struct datapath *dp = p->dp;
	struct sw_flow *flow;
	struct sw_flow_actions *sf_acts;
	struct dp_stats_percpu *stats;
	u64 *stats_counter;
	u32 n_mask_hit;

	// 取本 CPU 的统计块，避免跨核竞争
	stats = this_cpu_ptr(dp->stats_percpu);

	/* Look up flow. */
	// 按 key 查流表，同时统计本次匹配查询了多少掩码（megaflow 开销）
	flow = ovs_flow_tbl_lookup_stats(&dp->table, key, &n_mask_hit);
	if (unlikely(!flow)) {
		// 未命中：构造一个 MISS upcall，把报文上送用户态由 ovs-vswitchd 决策
		struct dp_upcall_info upcall;
		int error;

		upcall.cmd = OVS_PACKET_CMD_MISS;
		upcall.userdata = NULL;
		// 由入口端口选出上送用的 netlink portid（支持按流哈希分摊到多个 handler）
		upcall.portid = ovs_vport_find_upcall_portid(p, skb);
		upcall.egress_tun_info = NULL;
		error = ovs_dp_upcall(dp, skb, key, &upcall);
		// upcall 成功由其内部消费 skb，失败则在此释放
		if (unlikely(error))
			kfree_skb(skb);
		else
			consume_skb(skb);
		stats_counter = &stats->n_missed;
		goto out;
	}

	// 命中：更新该流的报文/字节/TCP 标志统计，取出动作列表并执行
	ovs_flow_stats_update(flow, key->tp.flags, skb);
	sf_acts = rcu_dereference(flow->sf_acts);
	ovs_execute_actions(dp, skb, sf_acts, key);

	stats_counter = &stats->n_hit;

out:
	/* Update datapath statistics. */
	// 更新 datapath 级统计：命中/未命中计数与本次掩码查询次数
	u64_stats_update_begin(&stats->syncp);
	(*stats_counter)++;
	stats->n_mask_hit += n_mask_hit;
	u64_stats_update_end(&stats->syncp);
}

// 把报文上送用户态；GSO 报文先分段再逐段发送。发送失败累加 n_lost 并返回错误
int ovs_dp_upcall(struct datapath *dp, struct sk_buff *skb,
		  const struct sw_flow_key *key,
		  const struct dp_upcall_info *upcall_info)
{
	struct dp_stats_percpu *stats;
	int err;

	// portid 为 0 表示没有可送达的用户态 handler，直接按“未连接”丢弃
	if (upcall_info->portid == 0) {
		err = -ENOTCONN;
		goto err;
	}

	// 非 GSO 直接封包上送；GSO 需先软分段成多个小包再逐一上送
	if (!skb_is_gso(skb))
		err = queue_userspace_packet(dp, skb, key, upcall_info);
	else
		err = queue_gso_packets(dp, skb, key, upcall_info);
	if (err)
		goto err;

	return 0;

err:
	// 上送失败：本 CPU 的 n_lost 计数加一
	stats = this_cpu_ptr(dp->stats_percpu);

	u64_stats_update_begin(&stats->syncp);
	stats->n_lost++;
	u64_stats_update_end(&stats->syncp);

	return err;
}

// 将 GSO 大包软分段成一串小包，逐个封成 netlink 消息上送用户态
static int queue_gso_packets(struct datapath *dp, struct sk_buff *skb,
			     const struct sw_flow_key *key,
			     const struct dp_upcall_info *upcall_info)
{
	unsigned short gso_type = skb_shinfo(skb)->gso_type;
	struct sw_flow_key later_key;
	struct sk_buff *segs, *nskb;
	struct ovs_skb_cb ovs_cb;
	int err;

	// __skb_gso_segment 会覆盖 skb->cb，故先备份 OVS_CB 再恢复
	ovs_cb = *OVS_CB(skb);
	segs = __skb_gso_segment(skb, NETIF_F_SG, false);
	*OVS_CB(skb) = ovs_cb;
	if (IS_ERR(segs))
		return PTR_ERR(segs);
	if (segs == NULL)
		return -EINVAL;

	if (gso_type & SKB_GSO_UDP) {
		/* The initial flow key extracted by ovs_flow_key_extract()
		 * in this case is for a first fragment, so we need to
		 * properly mark later fragments.
		 */
		// UDP 分片：原 key 对应首片，后续分片要单独标记为 LATER 分片
		later_key = *key;
		later_key.ip.frag = OVS_FRAG_TYPE_LATER;
	}

	/* Queue all of the segments. */
	// 遍历分段链表，逐个上送；每个段都要重新写入备份的 OVS_CB
	skb = segs;
	do {
		*OVS_CB(skb) = ovs_cb;
		if (gso_type & SKB_GSO_UDP && skb != segs)
			key = &later_key;

		err = queue_userspace_packet(dp, skb, key, upcall_info);
		if (err)
			break;

	} while ((skb = skb->next));

	/* Free all of the segments. */
	// 无论成功与否都释放这条分段链：出错的用 kfree_skb，成功的用 consume_skb
	skb = segs;
	do {
		nskb = skb->next;
		if (err)
			kfree_skb(skb);
		else
			consume_skb(skb);
	} while ((skb = nskb));
	return err;
}

// 预估一条 upcall netlink 消息所需的字节数（含头部、报文、key 及可选属性）
static size_t upcall_msg_size(const struct dp_upcall_info *upcall_info,
			      unsigned int hdrlen)
{
	size_t size = NLMSG_ALIGN(sizeof(struct ovs_header))
		+ nla_total_size(hdrlen) /* OVS_PACKET_ATTR_PACKET */
		+ nla_total_size(ovs_key_attr_size()); /* OVS_PACKET_ATTR_KEY */

	/* OVS_PACKET_ATTR_USERDATA */
	// 若带用户数据，计入其对齐后长度
	if (upcall_info->userdata)
		size += NLA_ALIGN(upcall_info->userdata->nla_len);

	/* OVS_PACKET_ATTR_EGRESS_TUN_KEY */
	// 若带出隧道 key，计入隧道属性长度
	if (upcall_info->egress_tun_info)
		size += nla_total_size(ovs_tun_key_attr_size());

	return size;
}

// 把单个（非 GSO）报文连同 key、元数据封成 netlink 消息，单播给用户态 handler
static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
				  const struct sw_flow_key *key,
				  const struct dp_upcall_info *upcall_info)
{
	struct ovs_header *upcall;
	struct sk_buff *nskb = NULL;
	struct sk_buff *user_skb = NULL; /* to be queued to userspace */
	struct nlattr *nla;
	struct genl_info info = {
		.dst_sk = ovs_dp_get_net(dp)->genl_sock,
		.snd_portid = upcall_info->portid,
	};
	size_t len;
	unsigned int hlen;
	int err, dp_ifindex;

	// 取 datapath 的 ifindex 写入 upcall 头部；取不到说明本地设备已消失
	dp_ifindex = get_dpifindex(dp);
	if (!dp_ifindex)
		return -ENODEV;

	// 若报文带硬件卸载的 VLAN 标签，先克隆并把标签压回报文内，便于用户态看到完整帧
	if (skb_vlan_tag_present(skb)) {
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (!nskb)
			return -ENOMEM;

		nskb = __vlan_hwaccel_push_inside(nskb);
		if (!nskb)
			return -ENOMEM;

		skb = nskb;
	}

	// netlink 属性长度用 u16 表示，报文过大无法承载则拒绝
	if (nla_attr_size(skb->len) > USHRT_MAX) {
		err = -EFBIG;
		goto out;
	}

	/* Complete checksum if needed */
	// 校验和尚未计算（CHECKSUM_PARTIAL）则在此补齐，避免用户态拿到不完整校验和
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_checksum_help(skb)))
		goto out;

	/* Older versions of OVS user space enforce alignment of the last
	 * Netlink attribute to NLA_ALIGNTO which would require extensive
	 * padding logic. Only perform zerocopy if padding is not required.
	 */
	// 协商了 UNALIGNED 特性才能零拷贝（只放头部，数据段由 skb_zerocopy 引用）；
	// 否则线性拷贝整包，避免旧用户态因末属性对齐要求出错
	if (dp->user_features & OVS_DP_F_UNALIGNED)
		hlen = skb_zerocopy_headlen(skb);
	else
		hlen = skb->len;

	// 按预估大小分配用户态 skb
	len = upcall_msg_size(upcall_info, hlen);
	user_skb = genlmsg_new_unicast(len, &info, GFP_ATOMIC);
	if (!user_skb) {
		err = -ENOMEM;
		goto out;
	}

	// 填 Generic Netlink 头与 OVS 头（命令、dp_ifindex）
	upcall = genlmsg_put(user_skb, 0, 0, &dp_packet_genl_family,
			     0, upcall_info->cmd);
	upcall->dp_ifindex = dp_ifindex;

	// 写入流 key 属性
	err = ovs_nla_put_key(key, key, OVS_PACKET_ATTR_KEY, false, user_skb);
	BUG_ON(err);

	// 可选：透传用户数据
	if (upcall_info->userdata)
		__nla_put(user_skb, OVS_PACKET_ATTR_USERDATA,
			  nla_len(upcall_info->userdata),
			  nla_data(upcall_info->userdata));

	// 可选：写入出隧道 key（嵌套属性）
	if (upcall_info->egress_tun_info) {
		nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_EGRESS_TUN_KEY);
		err = ovs_nla_put_egress_tunnel_key(user_skb,
						    upcall_info->egress_tun_info);
		BUG_ON(err);
		nla_nest_end(user_skb, nla);
	}

	/* Only reserve room for attribute header, packet data is added
	 * in skb_zerocopy() */
	// 先只占位 PACKET 属性头，真正的报文数据随后由 skb_zerocopy 填入
	if (!(nla = nla_reserve(user_skb, OVS_PACKET_ATTR_PACKET, 0))) {
		err = -ENOBUFS;
		goto out;
	}
	nla->nla_len = nla_attr_size(skb->len);

	// 把报文数据拷贝/引用进用户态 skb（hlen 之内线性拷贝，其余可零拷贝引用）
	err = skb_zerocopy(user_skb, skb, skb->len, hlen);
	if (err)
		goto out;

	/* Pad OVS_PACKET_ATTR_PACKET if linear copy was performed */
	// 若走了线性拷贝，需按 netlink 对齐补零字节
	if (!(dp->user_features & OVS_DP_F_UNALIGNED)) {
		size_t plen = NLA_ALIGN(user_skb->len) - user_skb->len;

		if (plen > 0)
			memset(skb_put(user_skb, plen), 0, plen);
	}

	// 回填 netlink 消息总长度，然后单播给目标 portid
	((struct nlmsghdr *) user_skb->data)->nlmsg_len = user_skb->len;

	err = genlmsg_unicast(ovs_dp_get_net(dp), user_skb, upcall_info->portid);
	user_skb = NULL;
out:
	// 出错时标记发送错误；释放可能残留的用户态 skb 与 VLAN 克隆
	if (err)
		skb_tx_error(skb);
	kfree_skb(user_skb);
	kfree_skb(nskb);
	return err;
}

// OVS_PACKET_CMD_EXECUTE 处理函数：用户态下发一个报文和一组动作，让内核直接执行动作
// （如注入报文、按动作转发/修改）。用户态需持 CAP_NET_ADMIN
static int ovs_packet_cmd_execute(struct sk_buff *skb, struct genl_info *info)
{
	struct ovs_header *ovs_header = info->userhdr;
	struct nlattr **a = info->attrs;
	struct sw_flow_actions *acts;
	struct sk_buff *packet;
	struct sw_flow *flow;
	struct sw_flow_actions *sf_acts;
	struct datapath *dp;
	struct ethhdr *eth;
	struct vport *input_vport;
	int len;
	int err;
	bool log = !a[OVS_PACKET_ATTR_PROBE];

	// 校验必需属性：原始报文、流 key、动作三者缺一不可
	err = -EINVAL;
	if (!a[OVS_PACKET_ATTR_PACKET] || !a[OVS_PACKET_ATTR_KEY] ||
	    !a[OVS_PACKET_ATTR_ACTIONS])
		goto err;

	// 按报文长度分配 skb（预留 NET_IP_ALIGN 对齐），并拷入用户态传来的报文内容
	len = nla_len(a[OVS_PACKET_ATTR_PACKET]);
	packet = __dev_alloc_skb(NET_IP_ALIGN + len, GFP_KERNEL);
	err = -ENOMEM;
	if (!packet)
		goto err;
	skb_reserve(packet, NET_IP_ALIGN);

	nla_memcpy(__skb_put(packet, len), a[OVS_PACKET_ATTR_PACKET], len);

	skb_reset_mac_header(packet);
	eth = eth_hdr(packet);

	/* Normally, setting the skb 'protocol' field would be handled by a
	 * call to eth_type_trans(), but it assumes there's a sending
	 * device, which we may not have. */
	// 手动设置 skb->protocol：以太类型字段 >= 0x0600 为 Ethernet II，否则视为 802.2/802.3
	if (ntohs(eth->h_proto) >= ETH_P_802_3_MIN)
		packet->protocol = eth->h_proto;
	else
		packet->protocol = htons(ETH_P_802_2);

	/* Build an sw_flow for sending this packet. */
	// 构造一个临时 sw_flow，仅用于承载本次执行所需的 key 和 actions
	flow = ovs_flow_alloc();
	err = PTR_ERR(flow);
	if (IS_ERR(flow))
		goto err_kfree_skb;

	// 从用户态给的 key 属性解析出流 key（写入 flow->key）
	err = ovs_flow_key_extract_userspace(a[OVS_PACKET_ATTR_KEY], packet,
					     &flow->key, log);
	if (err)
		goto err_flow_free;

	// 校验并拷贝用户态动作到内核 sw_flow_actions
	err = ovs_nla_copy_actions(a[OVS_PACKET_ATTR_ACTIONS],
				   &flow->key, &acts, log);
	if (err)
		goto err_flow_free;

	rcu_assign_pointer(flow->sf_acts, acts);
	// 从 key 里取出 priority/mark 设到报文上，无出隧道信息
	OVS_CB(packet)->egress_tun_info = NULL;
	packet->priority = flow->key.phy.priority;
	packet->mark = flow->key.phy.skb_mark;

	// 进入 RCU 读侧，定位 datapath
	rcu_read_lock();
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto err_unlock;

	// 以 key 指定的入口端口作为 input_vport，找不到则退回本地口 OVSP_LOCAL
	input_vport = ovs_vport_rcu(dp, flow->key.phy.in_port);
	if (!input_vport)
		input_vport = ovs_vport_rcu(dp, OVSP_LOCAL);

	if (!input_vport)
		goto err_unlock;

	OVS_CB(packet)->input_vport = input_vport;
	sf_acts = rcu_dereference(flow->sf_acts);

	// 执行动作。关软中断以保证动作执行期间的上下文与真实收包路径一致
	local_bh_disable();
	err = ovs_execute_actions(dp, packet, sf_acts, &flow->key);
	local_bh_enable();
	rcu_read_unlock();

	// 临时 flow 用完释放（deferred=false，同步释放）
	ovs_flow_free(flow, false);
	return err;

err_unlock:
	rcu_read_unlock();
err_flow_free:
	ovs_flow_free(flow, false);
err_kfree_skb:
	kfree_skb(packet);
err:
	return err;
}

// packet 族属性校验策略：报文至少含以太头，key/actions 为嵌套属性，PROBE 为标志位
static const struct nla_policy packet_policy[OVS_PACKET_ATTR_MAX + 1] = {
	[OVS_PACKET_ATTR_PACKET] = { .len = ETH_HLEN },
	[OVS_PACKET_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_PACKET_ATTR_PROBE] = { .type = NLA_FLAG },
};

// packet 族只有一个命令：EXECUTE，映射到 ovs_packet_cmd_execute，需要管理员权限
static const struct genl_ops dp_packet_genl_ops[] = {
	{ .cmd = OVS_PACKET_CMD_EXECUTE,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = packet_policy,
	  .doit = ovs_packet_cmd_execute
	}
};

// packet 命令族定义：动态分配 family id，支持多 netns 与并行处理
static struct genl_family dp_packet_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_PACKET_FAMILY,
	.version = OVS_PACKET_VERSION,
	.maxattr = OVS_PACKET_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_packet_genl_ops,
	.n_ops = ARRAY_SIZE(dp_packet_genl_ops),
};

// 汇总 datapath 的统计：流表规模、掩码数，以及跨所有 CPU 累加的命中/未命中/丢弃计数
static void get_dp_stats(const struct datapath *dp, struct ovs_dp_stats *stats,
			 struct ovs_dp_megaflow_stats *mega_stats)
{
	int i;

	memset(mega_stats, 0, sizeof(*mega_stats));

	stats->n_flows = ovs_flow_tbl_count(&dp->table);
	mega_stats->n_masks = ovs_flow_tbl_num_masks(&dp->table);

	stats->n_hit = stats->n_missed = stats->n_lost = 0;

	// 遍历所有可能的 CPU，用 seqcount 重试循环读取一致的 per-CPU 计数再累加
	for_each_possible_cpu(i) {
		const struct dp_stats_percpu *percpu_stats;
		struct dp_stats_percpu local_stats;
		unsigned int start;

		percpu_stats = per_cpu_ptr(dp->stats_percpu, i);

		do {
			start = u64_stats_fetch_begin_irq(&percpu_stats->syncp);
			local_stats = *percpu_stats;
		} while (u64_stats_fetch_retry_irq(&percpu_stats->syncp, start));

		stats->n_hit += local_stats.n_hit;
		stats->n_missed += local_stats.n_missed;
		stats->n_lost += local_stats.n_lost;
		mega_stats->n_mask_hit += local_stats.n_mask_hit;
	}
}

// 是否需要在回复里带完整 key：仅当流用 UFID 标识且用户未要求省略 key 时
static bool should_fill_key(const struct sw_flow_id *sfid, uint32_t ufid_flags)
{
	return ovs_identifier_is_ufid(sfid) &&
	       !(ufid_flags & OVS_UFID_F_OMIT_KEY);
}

// 是否需要在回复里带 mask（用户未要求省略即需要）
static bool should_fill_mask(uint32_t ufid_flags)
{
	return !(ufid_flags & OVS_UFID_F_OMIT_MASK);
}

// 是否需要在回复里带 actions（用户未要求省略即需要）
static bool should_fill_actions(uint32_t ufid_flags)
{
	return !(ufid_flags & OVS_UFID_F_OMIT_ACTIONS);
}

// 预估一条 flow 回复消息的字节数：按需计入 UFID/key/mask/actions 以及固定的统计属性
static size_t ovs_flow_cmd_msg_size(const struct sw_flow_actions *acts,
				    const struct sw_flow_id *sfid,
				    uint32_t ufid_flags)
{
	size_t len = NLMSG_ALIGN(sizeof(struct ovs_header));

	/* OVS_FLOW_ATTR_UFID */
	if (sfid && ovs_identifier_is_ufid(sfid))
		len += nla_total_size(sfid->ufid_len);

	/* OVS_FLOW_ATTR_KEY */
	if (!sfid || should_fill_key(sfid, ufid_flags))
		len += nla_total_size(ovs_key_attr_size());

	/* OVS_FLOW_ATTR_MASK */
	if (should_fill_mask(ufid_flags))
		len += nla_total_size(ovs_key_attr_size());

	/* OVS_FLOW_ATTR_ACTIONS */
	if (should_fill_actions(ufid_flags))
		len += nla_total_size(acts->actions_len);

	return len
		+ nla_total_size(sizeof(struct ovs_flow_stats)) /* OVS_FLOW_ATTR_STATS */
		+ nla_total_size(1) /* OVS_FLOW_ATTR_TCP_FLAGS */
		+ nla_total_size(8); /* OVS_FLOW_ATTR_USED */
}

/* Called with ovs_mutex or RCU read lock. */
// 把某条流的统计（使用时间、包/字节计数、TCP 标志）写入回复 skb；须持 ovs_mutex 或 RCU
static int ovs_flow_cmd_fill_stats(const struct sw_flow *flow,
				   struct sk_buff *skb)
{
	struct ovs_flow_stats stats;
	__be16 tcp_flags;
	unsigned long used;

	ovs_flow_stats_get(flow, &stats, &used, &tcp_flags);

	if (used &&
	    nla_put_u64(skb, OVS_FLOW_ATTR_USED, ovs_flow_used_time(used)))
		return -EMSGSIZE;

	if (stats.n_packets &&
	    nla_put(skb, OVS_FLOW_ATTR_STATS, sizeof(struct ovs_flow_stats), &stats))
		return -EMSGSIZE;

	if ((u8)ntohs(tcp_flags) &&
	     nla_put_u8(skb, OVS_FLOW_ATTR_TCP_FLAGS, (u8)ntohs(tcp_flags)))
		return -EMSGSIZE;

	return 0;
}

/* Called with ovs_mutex or RCU read lock. */
// 把某条流的动作列表写入回复 skb；须持 ovs_mutex 或 RCU
static int ovs_flow_cmd_fill_actions(const struct sw_flow *flow,
				     struct sk_buff *skb, int skb_orig_len)
{
	struct nlattr *start;
	int err;

	/* If OVS_FLOW_ATTR_ACTIONS doesn't fit, skip dumping the actions if
	 * this is the first flow to be dumped into 'skb'.  This is unusual for
	 * Netlink but individual action lists can be longer than
	 * NLMSG_GOODSIZE and thus entirely undumpable if we didn't do this.
	 * The userspace caller can always fetch the actions separately if it
	 * really wants them.  (Most userspace callers in fact don't care.)
	 *
	 * This can only fail for dump operations because the skb is always
	 * properly sized for single flows.
	 */
	start = nla_nest_start(skb, OVS_FLOW_ATTR_ACTIONS);
	if (start) {
		const struct sw_flow_actions *sf_acts;

		sf_acts = rcu_dereference_ovsl(flow->sf_acts);
		err = ovs_nla_put_actions(sf_acts->actions,
					  sf_acts->actions_len, skb);

		if (!err)
			nla_nest_end(skb, start);
		else {
			if (skb_orig_len)
				return err;

			nla_nest_cancel(skb, start);
		}
	} else if (skb_orig_len) {
		return -EMSGSIZE;
	}

	return 0;
}

/* Called with ovs_mutex or RCU read lock. */
// 把一条流的完整信息（标识/key/mask/统计/动作）填入 netlink 消息；须持 ovs_mutex 或 RCU
static int ovs_flow_cmd_fill_info(const struct sw_flow *flow, int dp_ifindex,
				  struct sk_buff *skb, u32 portid,
				  u32 seq, u32 flags, u8 cmd, u32 ufid_flags)
{
	const int skb_orig_len = skb->len;
	struct ovs_header *ovs_header;
	int err;

	// 写入 Generic Netlink 头与 OVS 头
	ovs_header = genlmsg_put(skb, portid, seq, &dp_flow_genl_family,
				 flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	ovs_header->dp_ifindex = dp_ifindex;

	// 写入流标识（UFID 或 key）
	err = ovs_nla_put_identifier(flow, skb);
	if (err)
		goto error;

	// 按需写入未掩码的完整 key
	if (should_fill_key(&flow->id, ufid_flags)) {
		err = ovs_nla_put_masked_key(flow, skb);
		if (err)
			goto error;
	}

	// 按需写入 mask
	if (should_fill_mask(ufid_flags)) {
		err = ovs_nla_put_mask(flow, skb);
		if (err)
			goto error;
	}

	// 写入统计信息
	err = ovs_flow_cmd_fill_stats(flow, skb);
	if (err)
		goto error;

	// 按需写入动作列表
	if (should_fill_actions(ufid_flags)) {
		err = ovs_flow_cmd_fill_actions(flow, skb, skb_orig_len);
		if (err)
			goto error;
	}

	genlmsg_end(skb, ovs_header);
	return 0;

error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

/* May not be called with RCU read lock. */
// 按需分配一条 flow 回复消息的 skb（GFP_KERNEL 可能睡眠，故不能在 RCU 读侧调用）；
// always=false 时仅当用户需要（ECHO 或有监听者）才分配
static struct sk_buff *ovs_flow_cmd_alloc_info(const struct sw_flow_actions *acts,
					       const struct sw_flow_id *sfid,
					       struct genl_info *info,
					       bool always,
					       uint32_t ufid_flags)
{
	struct sk_buff *skb;
	size_t len;

	if (!always && !ovs_must_notify(&dp_flow_genl_family, info, 0))
		return NULL;

	len = ovs_flow_cmd_msg_size(acts, sfid, ufid_flags);
	skb = genlmsg_new_unicast(len, info, GFP_KERNEL);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	return skb;
}

/* Called with ovs_mutex. */
// 分配并填好一条完整的 flow 信息回复消息；须持有 ovs_mutex
static struct sk_buff *ovs_flow_cmd_build_info(const struct sw_flow *flow,
					       int dp_ifindex,
					       struct genl_info *info, u8 cmd,
					       bool always, u32 ufid_flags)
{
	struct sk_buff *skb;
	int retval;

	skb = ovs_flow_cmd_alloc_info(ovsl_dereference(flow->sf_acts),
				      &flow->id, info, always, ufid_flags);
	if (IS_ERR_OR_NULL(skb))
		return skb;

	retval = ovs_flow_cmd_fill_info(flow, dp_ifindex, skb,
					info->snd_portid, info->snd_seq, 0,
					cmd, ufid_flags);
	BUG_ON(retval < 0);
	return skb;
}

// OVS_FLOW_CMD_NEW 处理：新增或更新一条流表项。需管理员权限
// 流程：解析 key/mask/actions -> 加 ovs_mutex -> 若不存在则插入，存在则更新 actions -> 回通告
static int ovs_flow_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow *flow = NULL, *new_flow;
	struct sw_flow_mask mask;
	struct sk_buff *reply;
	struct datapath *dp;
	struct sw_flow_key key;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int error;
	bool log = !a[OVS_FLOW_ATTR_PROBE];

	/* Must have key and actions. */
	error = -EINVAL;
	if (!a[OVS_FLOW_ATTR_KEY]) {
		OVS_NLERR(log, "Flow key attr not present in new flow.");
		goto error;
	}
	if (!a[OVS_FLOW_ATTR_ACTIONS]) {
		OVS_NLERR(log, "Flow actions attr not present in new flow.");
		goto error;
	}

	/* Most of the time we need to allocate a new flow, do it before
	 * locking.
	 */
	new_flow = ovs_flow_alloc();
	if (IS_ERR(new_flow)) {
		error = PTR_ERR(new_flow);
		goto error;
	}

	/* Extract key. */
	ovs_match_init(&match, &key, &mask);
	error = ovs_nla_get_match(&match, a[OVS_FLOW_ATTR_KEY],
				  a[OVS_FLOW_ATTR_MASK], log);
	if (error)
		goto err_kfree_flow;

	ovs_flow_mask_key(&new_flow->key, &key, &mask);

	/* Extract flow identifier. */
	error = ovs_nla_get_identifier(&new_flow->id, a[OVS_FLOW_ATTR_UFID],
				       &key, log);
	if (error)
		goto err_kfree_flow;

	/* Validate actions. */
	error = ovs_nla_copy_actions(a[OVS_FLOW_ATTR_ACTIONS], &new_flow->key,
				     &acts, log);
	if (error) {
		OVS_NLERR(log, "Flow actions may not be safe on all matching packets.");
		goto err_kfree_flow;
	}

	reply = ovs_flow_cmd_alloc_info(acts, &new_flow->id, info, false,
					ufid_flags);
	if (IS_ERR(reply)) {
		error = PTR_ERR(reply);
		goto err_kfree_acts;
	}

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}

	/* Check if this is a duplicate flow */
	// 先按 UFID 查，再按 key 查，判断该流是否已存在
	if (ovs_identifier_is_ufid(&new_flow->id))
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &new_flow->id);
	if (!flow)
		flow = ovs_flow_tbl_lookup(&dp->table, &key);
	if (likely(!flow)) {
		// 不存在：把新流插入流表（连同其掩码）
		rcu_assign_pointer(new_flow->sf_acts, acts);

		/* Put flow in bucket. */
		error = ovs_flow_tbl_insert(&dp->table, new_flow, &mask);
		if (unlikely(error)) {
			acts = NULL;
			goto err_unlock_ovs;
		}

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(new_flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
		ovs_unlock();
	} else {
		// 已存在：走更新路径
		struct sw_flow_actions *old_acts;

		/* Bail out if we're not allowed to modify an existing flow.
		 * We accept NLM_F_CREATE in place of the intended NLM_F_EXCL
		 * because Generic Netlink treats the latter as a dump
		 * request.  We also accept NLM_F_EXCL in case that bug ever
		 * gets fixed.
		 */
		// 若用户以“独占创建”语义下发（F_CREATE/F_EXCL），流已存在则返回 EEXIST
		if (unlikely(info->nlhdr->nlmsg_flags & (NLM_F_CREATE
							 | NLM_F_EXCL))) {
			error = -EEXIST;
			goto err_unlock_ovs;
		}
		/* The flow identifier has to be the same for flow updates.
		 * Look for any overlapping flow.
		 */
		// 更新要求标识一致：若 key 不匹配，用精确匹配再找一次，找不到则 ENOENT
		if (unlikely(!ovs_flow_cmp(flow, &match))) {
			if (ovs_identifier_is_key(&flow->id))
				flow = ovs_flow_tbl_lookup_exact(&dp->table,
								 &match);
			else /* UFID matches but key is different */
				flow = NULL;
			if (!flow) {
				error = -ENOENT;
				goto err_unlock_ovs;
			}
		}
		/* Update actions. */
		// 用新动作替换旧动作（RCU 发布），旧动作待 unlock 后释放
		old_acts = ovsl_dereference(flow->sf_acts);
		rcu_assign_pointer(flow->sf_acts, acts);

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
		ovs_unlock();

		// 经过 RCU 宽限后释放旧动作，并释放本次未用到的 new_flow
		ovs_nla_free_flow_actions(old_acts);
		ovs_flow_free(new_flow, false);
	}

	// 若构造了回复，则向发起者/组播组通告
	if (reply)
		ovs_notify(&dp_flow_genl_family, reply, info);
	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	kfree(acts);
err_kfree_flow:
	ovs_flow_free(new_flow, false);
error:
	return error;
}

/* Factor out action copy to avoid "Wframe-larger-than=1024" warning. */
// 单独抽出动作拷贝以减小栈帧（避免编译告警）：用 mask 得到掩码后的 key，再校验并拷贝动作
static struct sw_flow_actions *get_flow_actions(const struct nlattr *a,
						const struct sw_flow_key *key,
						const struct sw_flow_mask *mask,
						bool log)
{
	struct sw_flow_actions *acts;
	struct sw_flow_key masked_key;
	int error;

	ovs_flow_mask_key(&masked_key, key, mask);
	error = ovs_nla_copy_actions(a, &masked_key, &acts, log);
	if (error) {
		OVS_NLERR(log,
			  "Actions may not be safe on all matching packets");
		return ERR_PTR(error);
	}

	return acts;
}

// OVS_FLOW_CMD_SET 处理：修改一条已存在流的动作，或清空其统计。需管理员权限
static int ovs_flow_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sw_flow *flow;
	struct sw_flow_mask mask;
	struct sk_buff *reply = NULL;
	struct datapath *dp;
	struct sw_flow_actions *old_acts = NULL, *acts = NULL;
	struct sw_flow_match match;
	struct sw_flow_id sfid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int error;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	/* Extract key. */
	error = -EINVAL;
	if (!a[OVS_FLOW_ATTR_KEY]) {
		OVS_NLERR(log, "Flow key attribute not present in set flow.");
		goto error;
	}

	ufid_present = ovs_nla_get_ufid(&sfid, a[OVS_FLOW_ATTR_UFID], log);
	ovs_match_init(&match, &key, &mask);
	error = ovs_nla_get_match(&match, a[OVS_FLOW_ATTR_KEY],
				  a[OVS_FLOW_ATTR_MASK], log);
	if (error)
		goto error;

	/* Validate actions. */
	if (a[OVS_FLOW_ATTR_ACTIONS]) {
		acts = get_flow_actions(a[OVS_FLOW_ATTR_ACTIONS], &key, &mask,
					log);
		if (IS_ERR(acts)) {
			error = PTR_ERR(acts);
			goto error;
		}

		/* Can allocate before locking if have acts. */
		reply = ovs_flow_cmd_alloc_info(acts, &sfid, info, false,
						ufid_flags);
		if (IS_ERR(reply)) {
			error = PTR_ERR(reply);
			goto err_kfree_acts;
		}
	}

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		error = -ENODEV;
		goto err_unlock_ovs;
	}
	/* Check that the flow exists. */
	// 按 UFID 或精确 match 查找目标流，不存在则 ENOENT
	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &sfid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (unlikely(!flow)) {
		error = -ENOENT;
		goto err_unlock_ovs;
	}

	/* Update actions, if present. */
	// 带了新动作则替换（旧动作留待解锁后释放）；否则仅构造回复
	if (likely(acts)) {
		old_acts = ovsl_dereference(flow->sf_acts);
		rcu_assign_pointer(flow->sf_acts, acts);

		if (unlikely(reply)) {
			error = ovs_flow_cmd_fill_info(flow,
						       ovs_header->dp_ifindex,
						       reply, info->snd_portid,
						       info->snd_seq, 0,
						       OVS_FLOW_CMD_NEW,
						       ufid_flags);
			BUG_ON(error < 0);
		}
	} else {
		/* Could not alloc without acts before locking. */
		reply = ovs_flow_cmd_build_info(flow, ovs_header->dp_ifindex,
						info, OVS_FLOW_CMD_NEW, false,
						ufid_flags);

		if (unlikely(IS_ERR(reply))) {
			error = PTR_ERR(reply);
			goto err_unlock_ovs;
		}
	}

	/* Clear stats. */
	// 带 CLEAR 标志则清空该流的统计计数
	if (a[OVS_FLOW_ATTR_CLEAR])
		ovs_flow_stats_clear(flow);
	ovs_unlock();

	if (reply)
		ovs_notify(&dp_flow_genl_family, reply, info);
	if (old_acts)
		ovs_nla_free_flow_actions(old_acts);

	return 0;

err_unlock_ovs:
	ovs_unlock();
	kfree_skb(reply);
err_kfree_acts:
	kfree(acts);
error:
	return error;
}

// OVS_FLOW_CMD_GET 处理：查询单条流并回复其完整信息。允许非特权用户
static int ovs_flow_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow;
	struct datapath *dp;
	struct sw_flow_match match;
	struct sw_flow_id ufid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int err = 0;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&ufid, a[OVS_FLOW_ATTR_UFID], log);
	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(&match, &key, NULL);
		err = ovs_nla_get_match(&match, a[OVS_FLOW_ATTR_KEY], NULL,
					log);
	} else if (!ufid_present) {
		OVS_NLERR(log,
			  "Flow get message rejected, Key attribute missing.");
		err = -EINVAL;
	}
	if (err)
		return err;

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		err = -ENODEV;
		goto unlock;
	}

	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &ufid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (!flow) {
		err = -ENOENT;
		goto unlock;
	}

	reply = ovs_flow_cmd_build_info(flow, ovs_header->dp_ifindex, info,
					OVS_FLOW_CMD_NEW, true, ufid_flags);
	if (IS_ERR(reply)) {
		err = PTR_ERR(reply);
		goto unlock;
	}

	ovs_unlock();
	return genlmsg_reply(reply, info);
unlock:
	ovs_unlock();
	return err;
}

// OVS_FLOW_CMD_DEL 处理：删除单条流；若既无 key 也无 UFID 则清空整张流表。需管理员权限
static int ovs_flow_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sw_flow_key key;
	struct sk_buff *reply;
	struct sw_flow *flow = NULL;
	struct datapath *dp;
	struct sw_flow_match match;
	struct sw_flow_id ufid;
	u32 ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);
	int err;
	bool log = !a[OVS_FLOW_ATTR_PROBE];
	bool ufid_present;

	ufid_present = ovs_nla_get_ufid(&ufid, a[OVS_FLOW_ATTR_UFID], log);
	if (a[OVS_FLOW_ATTR_KEY]) {
		ovs_match_init(&match, &key, NULL);
		err = ovs_nla_get_match(&match, a[OVS_FLOW_ATTR_KEY], NULL,
					log);
		if (unlikely(err))
			return err;
	}

	ovs_lock();
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (unlikely(!dp)) {
		err = -ENODEV;
		goto unlock;
	}

	if (unlikely(!a[OVS_FLOW_ATTR_KEY] && !ufid_present)) {
		// 无 key 且无 UFID：语义为清空整张流表
		err = ovs_flow_tbl_flush(&dp->table);
		goto unlock;
	}

	if (ufid_present)
		flow = ovs_flow_tbl_lookup_ufid(&dp->table, &ufid);
	else
		flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
	if (unlikely(!flow)) {
		err = -ENOENT;
		goto unlock;
	}

	// 从流表移除目标流，然后解锁
	ovs_flow_tbl_remove(&dp->table, flow);
	ovs_unlock();

	// 构造 DEL 通告（内部用 rcu_read_lock 仅为满足 RCU 检查），随后释放该流
	reply = ovs_flow_cmd_alloc_info((const struct sw_flow_actions __force *) flow->sf_acts,
					&flow->id, info, false, ufid_flags);
	if (likely(reply)) {
		if (likely(!IS_ERR(reply))) {
			rcu_read_lock();	/*To keep RCU checker happy. */
			err = ovs_flow_cmd_fill_info(flow, ovs_header->dp_ifindex,
						     reply, info->snd_portid,
						     info->snd_seq, 0,
						     OVS_FLOW_CMD_DEL,
						     ufid_flags);
			rcu_read_unlock();
			BUG_ON(err < 0);

			ovs_notify(&dp_flow_genl_family, reply, info);
		} else {
			netlink_set_err(sock_net(skb->sk)->genl_sock, 0, 0, PTR_ERR(reply));
		}
	}

	ovs_flow_free(flow, true);
	return 0;
unlock:
	ovs_unlock();
	return err;
}

// OVS_FLOW_CMD_GET 的 dump 回调：遍历流表逐条填入，支持分批（用 cb->args 记录游标）
static int ovs_flow_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct nlattr *a[__OVS_FLOW_ATTR_MAX];
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct table_instance *ti;
	struct datapath *dp;
	u32 ufid_flags;
	int err;

	// 从 dump 请求头解析属性，取出 ufid_flags 控制输出内容
	err = genlmsg_parse(cb->nlh, &dp_flow_genl_family, a,
			    OVS_FLOW_ATTR_MAX, flow_policy);
	if (err)
		return err;
	ufid_flags = ovs_nla_get_ufid_flags(a[OVS_FLOW_ATTR_UFID_FLAGS]);

	rcu_read_lock();
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		rcu_read_unlock();
		return -ENODEV;
	}

	// cb->args[0]/[1] 保存桶号与桶内偏移，跨多次调用续传遍历
	ti = rcu_dereference(dp->table.ti);
	for (;;) {
		struct sw_flow *flow;
		u32 bucket, obj;

		bucket = cb->args[0];
		obj = cb->args[1];
		flow = ovs_flow_tbl_dump_next(ti, &bucket, &obj);
		if (!flow)
			break;

		// 若本条填不下（skb 满），停止并保留游标，等待下次 dump 续传
		if (ovs_flow_cmd_fill_info(flow, ovs_header->dp_ifindex, skb,
					   NETLINK_CB(cb->skb).portid,
					   cb->nlh->nlmsg_seq, NLM_F_MULTI,
					   OVS_FLOW_CMD_NEW, ufid_flags) < 0)
			break;

		cb->args[0] = bucket;
		cb->args[1] = obj;
	}
	rcu_read_unlock();
	return skb->len;
}

// flow 族属性校验策略：key/mask/actions 为嵌套，CLEAR/PROBE 为标志，UFID 及其 flags
static const struct nla_policy flow_policy[OVS_FLOW_ATTR_MAX + 1] = {
	[OVS_FLOW_ATTR_KEY] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_MASK] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_ACTIONS] = { .type = NLA_NESTED },
	[OVS_FLOW_ATTR_CLEAR] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_PROBE] = { .type = NLA_FLAG },
	[OVS_FLOW_ATTR_UFID] = { .type = NLA_UNSPEC, .len = 1 },
	[OVS_FLOW_ATTR_UFID_FLAGS] = { .type = NLA_U32 },
};

// flow 族命令表：NEW/DEL/SET 需管理员权限，GET 允许非特权并支持 dump 遍历
static const struct genl_ops dp_flow_genl_ops[] = {
	{ .cmd = OVS_FLOW_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_new
	},
	{ .cmd = OVS_FLOW_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_del
	},
	{ .cmd = OVS_FLOW_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_get,
	  .dumpit = ovs_flow_cmd_dump
	},
	{ .cmd = OVS_FLOW_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = flow_policy,
	  .doit = ovs_flow_cmd_set,
	},
};

// flow 命令族定义
static struct genl_family dp_flow_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_FLOW_FAMILY,
	.version = OVS_FLOW_VERSION,
	.maxattr = OVS_FLOW_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_flow_genl_ops,
	.n_ops = ARRAY_SIZE(dp_flow_genl_ops),
	.mcgrps = &ovs_dp_flow_multicast_group,
	.n_mcgrps = 1,
};

// 预估一条 datapath 信息回复消息的字节数（名字、两组统计、user_features）
static size_t ovs_dp_cmd_msg_size(void)
{
	size_t msgsize = NLMSG_ALIGN(sizeof(struct ovs_header));

	msgsize += nla_total_size(IFNAMSIZ);
	msgsize += nla_total_size(sizeof(struct ovs_dp_stats));
	msgsize += nla_total_size(sizeof(struct ovs_dp_megaflow_stats));
	msgsize += nla_total_size(sizeof(u32)); /* OVS_DP_ATTR_USER_FEATURES */

	return msgsize;
}

/* Called with ovs_mutex. */
// 把一个 datapath 的信息（名字、统计、megaflow 统计、user_features）填入 netlink 消息；须持 ovs_mutex
static int ovs_dp_cmd_fill_info(struct datapath *dp, struct sk_buff *skb,
				u32 portid, u32 seq, u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct ovs_dp_stats dp_stats;
	struct ovs_dp_megaflow_stats dp_megaflow_stats;
	int err;

	ovs_header = genlmsg_put(skb, portid, seq, &dp_datapath_genl_family,
				   flags, cmd);
	if (!ovs_header)
		goto error;

	ovs_header->dp_ifindex = get_dpifindex(dp);

	err = nla_put_string(skb, OVS_DP_ATTR_NAME, ovs_dp_name(dp));
	if (err)
		goto nla_put_failure;

	get_dp_stats(dp, &dp_stats, &dp_megaflow_stats);
	if (nla_put(skb, OVS_DP_ATTR_STATS, sizeof(struct ovs_dp_stats),
			&dp_stats))
		goto nla_put_failure;

	if (nla_put(skb, OVS_DP_ATTR_MEGAFLOW_STATS,
			sizeof(struct ovs_dp_megaflow_stats),
			&dp_megaflow_stats))
		goto nla_put_failure;

	if (nla_put_u32(skb, OVS_DP_ATTR_USER_FEATURES, dp->user_features))
		goto nla_put_failure;

	genlmsg_end(skb, ovs_header);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, ovs_header);
error:
	return -EMSGSIZE;
}

// 分配一条 datapath 回复消息的 skb
static struct sk_buff *ovs_dp_cmd_alloc_info(struct genl_info *info)
{
	return genlmsg_new_unicast(ovs_dp_cmd_msg_size(), info, GFP_KERNEL);
}

/* Called with rcu_read_lock or ovs_mutex. */
// 按名字或 ifindex 定位 datapath；须持 rcu_read_lock 或 ovs_mutex。找不到返回 ERR_PTR(-ENODEV)
static struct datapath *lookup_datapath(struct net *net,
					const struct ovs_header *ovs_header,
					struct nlattr *a[OVS_DP_ATTR_MAX + 1])
{
	struct datapath *dp;

	// 无名字则按 dp_ifindex 找；有名字则定位对应本地口(OVSP_LOCAL)的 datapath
	if (!a[OVS_DP_ATTR_NAME])
		dp = get_dp(net, ovs_header->dp_ifindex);
	else {
		struct vport *vport;

		vport = ovs_vport_locate(net, nla_data(a[OVS_DP_ATTR_NAME]));
		dp = vport && vport->port_no == OVSP_LOCAL ? vport->dp : NULL;
	}
	return dp ? dp : ERR_PTR(-ENODEV);
}

// 兼容旧用户态：当它不理解 user_features 又重用了已存在的 datapath 时，清空其特性位
static void ovs_dp_reset_user_features(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath *dp;

	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	if (IS_ERR(dp))
		return;

	WARN(dp->user_features, "Dropping previously announced user features\n");
	dp->user_features = 0;
}

// 应用用户态下发的 datapath 参数变更（目前仅 user_features）；须在持锁后调用
static void ovs_dp_change(struct datapath *dp, struct nlattr *a[])
{
	if (a[OVS_DP_ATTR_USER_FEATURES])
		dp->user_features = nla_get_u32(a[OVS_DP_ATTR_USER_FEATURES]);
}

// OVS_DP_CMD_NEW 处理：创建一个新的 datapath（虚拟交换机）。需管理员权限
// 分配 dp 结构、流表、per-CPU 统计与端口数组，创建本地内部口 OVSP_LOCAL，挂入 per-netns 链表
static int ovs_dp_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct datapath *dp;
	struct vport *vport;
	struct ovs_net *ovs_net;
	int err, i;

	err = -EINVAL;
	if (!a[OVS_DP_ATTR_NAME] || !a[OVS_DP_ATTR_UPCALL_PID])
		goto err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	// 分配并清零 datapath 结构
	err = -ENOMEM;
	dp = kzalloc(sizeof(*dp), GFP_KERNEL);
	if (dp == NULL)
		goto err_free_reply;

	// 绑定所属网络命名空间（增加引用）
	ovs_dp_set_net(dp, hold_net(sock_net(skb->sk)));

	/* Allocate table. */
	// 初始化流表
	err = ovs_flow_tbl_init(&dp->table);
	if (err)
		goto err_free_dp;

	// 分配 per-CPU 统计
	dp->stats_percpu = netdev_alloc_pcpu_stats(struct dp_stats_percpu);
	if (!dp->stats_percpu) {
		err = -ENOMEM;
		goto err_destroy_table;
	}

	// 分配并初始化端口哈希表数组
	dp->ports = kmalloc(DP_VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dp->ports) {
		err = -ENOMEM;
		goto err_destroy_percpu;
	}

	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++)
		INIT_HLIST_HEAD(&dp->ports[i]);

	/* Set up our datapath device. */
	// 准备本地内部口(OVSP_LOCAL)的参数：类型为 internal，名字即 datapath 名
	parms.name = nla_data(a[OVS_DP_ATTR_NAME]);
	parms.type = OVS_VPORT_TYPE_INTERNAL;
	parms.options = NULL;
	parms.dp = dp;
	parms.port_no = OVSP_LOCAL;
	parms.upcall_portids = a[OVS_DP_ATTR_UPCALL_PID];

	// 应用 user_features 等参数（此时还只是本地改动，无需锁）
	ovs_dp_change(dp, a);

	/* So far only local changes have been made, now need the lock. */
	// 至此都是本地改动；接下来要接触全局状态，取写锁
	ovs_lock();

	// 创建本地口；若名字冲突返回 EEXIST
	vport = new_vport(&parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		if (err == -EBUSY)
			err = -EEXIST;

		if (err == -EEXIST) {
			/* An outdated user space instance that does not understand
			 * the concept of user_features has attempted to create a new
			 * datapath and is likely to reuse it. Drop all user features.
			 */
			// 旧用户态重建并重用已存在 datapath：清掉之前声明的 user_features
			if (info->genlhdr->version < OVS_DP_VER_FEATURES)
				ovs_dp_reset_user_features(skb, info);
		}

		goto err_destroy_ports_array;
	}

	// 填好回复消息
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);

	// 把新 datapath 挂入本 netns 的 dps 链表
	ovs_net = net_generic(ovs_dp_get_net(dp), ovs_net_id);
	list_add_tail_rcu(&dp->list_node, &ovs_net->dps);

	ovs_unlock();

	// 通告创建事件
	ovs_notify(&dp_datapath_genl_family, reply, info);
	return 0;

err_destroy_ports_array:
	// 出错回滚：按分配的相反顺序逐级释放
	ovs_unlock();
	kfree(dp->ports);
err_destroy_percpu:
	free_percpu(dp->stats_percpu);
err_destroy_table:
	ovs_flow_tbl_destroy(&dp->table);
err_free_dp:
	release_net(ovs_dp_get_net(dp));
	kfree(dp);
err_free_reply:
	kfree_skb(reply);
err:
	return err;
}

/* Called with ovs_mutex. */
// 销毁一个 datapath：先摘除所有非本地端口，再从链表摘链，最后摘本地口并 RCU 延迟释放整个 dp
static void __dp_destroy(struct datapath *dp)
{
	int i;

	// 先销毁除 OVSP_LOCAL 外的全部端口
	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;
		struct hlist_node *n;

		hlist_for_each_entry_safe(vport, n, &dp->ports[i], dp_hash_node)
			if (vport->port_no != OVSP_LOCAL)
				ovs_dp_detach_port(vport);
	}

	// 从 per-netns 的 dps 链表摘除
	list_del_rcu(&dp->list_node);

	/* OVSP_LOCAL is datapath internal port. We need to make sure that
	 * all ports in datapath are destroyed first before freeing datapath.
	 */
	// 最后销毁本地内部口
	ovs_dp_detach_port(ovs_vport_ovsl(dp, OVSP_LOCAL));

	/* RCU destroy the flow table */
	// RCU 宽限期后回收整个 datapath（流表、统计、端口数组等）
	call_rcu(&dp->rcu, destroy_dp_rcu);
}

// OVS_DP_CMD_DEL 处理：删除一个 datapath。需管理员权限
static int ovs_dp_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto err_unlock_free;

	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_DEL);
	BUG_ON(err < 0);

	__dp_destroy(dp);
	ovs_unlock();

	ovs_notify(&dp_datapath_genl_family, reply, info);

	return 0;

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

// OVS_DP_CMD_SET 处理：修改 datapath 参数（user_features）。需管理员权限
static int ovs_dp_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	err = PTR_ERR(dp);
	if (IS_ERR(dp))
		goto err_unlock_free;

	ovs_dp_change(dp, info->attrs);

	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);

	ovs_unlock();
	ovs_notify(&dp_datapath_genl_family, reply, info);

	return 0;

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

// OVS_DP_CMD_GET 处理：查询单个 datapath 的信息。允许非特权用户
static int ovs_dp_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	struct datapath *dp;
	int err;

	reply = ovs_dp_cmd_alloc_info(info);
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	if (IS_ERR(dp)) {
		err = PTR_ERR(dp);
		goto err_unlock_free;
	}
	err = ovs_dp_cmd_fill_info(dp, reply, info->snd_portid,
				   info->snd_seq, 0, OVS_DP_CMD_NEW);
	BUG_ON(err < 0);
	ovs_unlock();

	return genlmsg_reply(reply, info);

err_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

// OVS_DP_CMD_GET 的 dump 回调：遍历本 netns 内所有 datapath，用 cb->args[0] 记录跳过数
static int ovs_dp_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_net *ovs_net = net_generic(sock_net(skb->sk), ovs_net_id);
	struct datapath *dp;
	int skip = cb->args[0];
	int i = 0;

	ovs_lock();
	list_for_each_entry(dp, &ovs_net->dps, list_node) {
		if (i >= skip &&
		    ovs_dp_cmd_fill_info(dp, skb, NETLINK_CB(cb->skb).portid,
					 cb->nlh->nlmsg_seq, NLM_F_MULTI,
					 OVS_DP_CMD_NEW) < 0)
			break;
		i++;
	}
	ovs_unlock();

	cb->args[0] = i;

	return skb->len;
}

// datapath 族属性校验策略：名字（长度受限）、上送 PID、user_features
static const struct nla_policy datapath_policy[OVS_DP_ATTR_MAX + 1] = {
	[OVS_DP_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_DP_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_DP_ATTR_USER_FEATURES] = { .type = NLA_U32 },
};

// datapath 族命令表：NEW/DEL/SET 需管理员权限，GET 允许非特权并支持 dump
static const struct genl_ops dp_datapath_genl_ops[] = {
	{ .cmd = OVS_DP_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_new
	},
	{ .cmd = OVS_DP_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_del
	},
	{ .cmd = OVS_DP_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_get,
	  .dumpit = ovs_dp_cmd_dump
	},
	{ .cmd = OVS_DP_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = datapath_policy,
	  .doit = ovs_dp_cmd_set,
	},
};

// datapath 命令族定义
static struct genl_family dp_datapath_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_DATAPATH_FAMILY,
	.version = OVS_DATAPATH_VERSION,
	.maxattr = OVS_DP_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_datapath_genl_ops,
	.n_ops = ARRAY_SIZE(dp_datapath_genl_ops),
	.mcgrps = &ovs_dp_datapath_multicast_group,
	.n_mcgrps = 1,
};

/* Called with ovs_mutex or RCU read lock. */
// 把一个 vport 的信息（端口号、类型、名字、统计、上送 PID、选项）填入 netlink 消息；须持 ovs_mutex 或 RCU
static int ovs_vport_cmd_fill_info(struct vport *vport, struct sk_buff *skb,
				   u32 portid, u32 seq, u32 flags, u8 cmd)
{
	struct ovs_header *ovs_header;
	struct ovs_vport_stats vport_stats;
	int err;

	ovs_header = genlmsg_put(skb, portid, seq, &dp_vport_genl_family,
				 flags, cmd);
	if (!ovs_header)
		return -EMSGSIZE;

	ovs_header->dp_ifindex = get_dpifindex(vport->dp);

	if (nla_put_u32(skb, OVS_VPORT_ATTR_PORT_NO, vport->port_no) ||
	    nla_put_u32(skb, OVS_VPORT_ATTR_TYPE, vport->ops->type) ||
	    nla_put_string(skb, OVS_VPORT_ATTR_NAME,
			   vport->ops->get_name(vport)))
		goto nla_put_failure;

	ovs_vport_get_stats(vport, &vport_stats);
	if (nla_put(skb, OVS_VPORT_ATTR_STATS, sizeof(struct ovs_vport_stats),
		    &vport_stats))
		goto nla_put_failure;

	if (ovs_vport_get_upcall_portids(vport, skb))
		goto nla_put_failure;

	err = ovs_vport_get_options(vport, skb);
	if (err == -EMSGSIZE)
		goto error;

	genlmsg_end(skb, ovs_header);
	return 0;

nla_put_failure:
	err = -EMSGSIZE;
error:
	genlmsg_cancel(skb, ovs_header);
	return err;
}

// 分配一条 vport 回复消息的 skb
static struct sk_buff *ovs_vport_cmd_alloc_info(void)
{
	return nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
}

/* Called with ovs_mutex, only via ovs_dp_notify_wq(). */
// 为一个 vport 构造并填好通告消息（供设备变化通知使用）；须持 ovs_mutex
struct sk_buff *ovs_vport_cmd_build_info(struct vport *vport, u32 portid,
					 u32 seq, u8 cmd)
{
	struct sk_buff *skb;
	int retval;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	retval = ovs_vport_cmd_fill_info(vport, skb, portid, seq, 0, cmd);
	BUG_ON(retval < 0);

	return skb;
}

/* Called with ovs_mutex or RCU read lock. */
// 按名字或（dp_ifindex + 端口号）定位一个 vport；须持 ovs_mutex 或 RCU
static struct vport *lookup_vport(struct net *net,
				  const struct ovs_header *ovs_header,
				  struct nlattr *a[OVS_VPORT_ATTR_MAX + 1])
{
	struct datapath *dp;
	struct vport *vport;

	// 优先按名字全局定位；若给了 dp_ifindex 需校验该口确实属于该 datapath
	if (a[OVS_VPORT_ATTR_NAME]) {
		vport = ovs_vport_locate(net, nla_data(a[OVS_VPORT_ATTR_NAME]));
		if (!vport)
			return ERR_PTR(-ENODEV);
		if (ovs_header->dp_ifindex &&
		    ovs_header->dp_ifindex != get_dpifindex(vport->dp))
			return ERR_PTR(-ENODEV);
		return vport;
	} else if (a[OVS_VPORT_ATTR_PORT_NO]) {
		// 否则按端口号：先定位 datapath，再在其端口表中查
		u32 port_no = nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]);

		if (port_no >= DP_MAX_PORTS)
			return ERR_PTR(-EFBIG);

		dp = get_dp(net, ovs_header->dp_ifindex);
		if (!dp)
			return ERR_PTR(-ENODEV);

		vport = ovs_vport_ovsl_rcu(dp, port_no);
		if (!vport)
			return ERR_PTR(-ENODEV);
		return vport;
	} else
		return ERR_PTR(-EINVAL);
}

// OVS_VPORT_CMD_NEW 处理：向 datapath 添加一个端口。需管理员权限
// 若未指定端口号则自动分配一个空闲号；创建成功后回通告
static int ovs_vport_cmd_new(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct vport_parms parms;
	struct sk_buff *reply;
	struct vport *vport;
	struct datapath *dp;
	u32 port_no;
	int err;

	if (!a[OVS_VPORT_ATTR_NAME] || !a[OVS_VPORT_ATTR_TYPE] ||
	    !a[OVS_VPORT_ATTR_UPCALL_PID])
		return -EINVAL;

	// 用户指定端口号则用之，否则先置 0 表示待自动分配
	port_no = a[OVS_VPORT_ATTR_PORT_NO]
		? nla_get_u32(a[OVS_VPORT_ATTR_PORT_NO]) : 0;
	if (port_no >= DP_MAX_PORTS)
		return -EFBIG;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
restart:
	dp = get_dp(sock_net(skb->sk), ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto exit_unlock_free;

	if (port_no) {
		// 指定了端口号：若已被占用返回 EBUSY
		vport = ovs_vport_ovsl(dp, port_no);
		err = -EBUSY;
		if (vport)
			goto exit_unlock_free;
	} else {
		// 未指定：从 1 开始线性扫描第一个空闲端口号
		for (port_no = 1; ; port_no++) {
			if (port_no >= DP_MAX_PORTS) {
				err = -EFBIG;
				goto exit_unlock_free;
			}
			vport = ovs_vport_ovsl(dp, port_no);
			if (!vport)
				break;
		}
	}

	// 组装端口参数并创建
	parms.name = nla_data(a[OVS_VPORT_ATTR_NAME]);
	parms.type = nla_get_u32(a[OVS_VPORT_ATTR_TYPE]);
	parms.options = a[OVS_VPORT_ATTR_OPTIONS];
	parms.dp = dp;
	parms.port_no = port_no;
	parms.upcall_portids = a[OVS_VPORT_ATTR_UPCALL_PID];

	vport = new_vport(&parms);
	err = PTR_ERR(vport);
	if (IS_ERR(vport)) {
		// EAGAIN 表示号被并发抢占，回到 restart 重新选号
		if (err == -EAGAIN)
			goto restart;
		goto exit_unlock_free;
	}

	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);
	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

// OVS_VPORT_CMD_SET 处理：修改端口的选项或上送 PID（类型不可改）。需管理员权限
static int ovs_vport_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	vport = lookup_vport(sock_net(skb->sk), info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;

	// 若带了类型属性，必须与现有类型一致——端口类型不允许在 SET 中更改
	if (a[OVS_VPORT_ATTR_TYPE] &&
	    nla_get_u32(a[OVS_VPORT_ATTR_TYPE]) != vport->ops->type) {
		err = -EINVAL;
		goto exit_unlock_free;
	}

	// 更新端口选项（如隧道参数）
	if (a[OVS_VPORT_ATTR_OPTIONS]) {
		err = ovs_vport_set_options(vport, a[OVS_VPORT_ATTR_OPTIONS]);
		if (err)
			goto exit_unlock_free;
	}


	// 更新上送用的 netlink portid 集合
	if (a[OVS_VPORT_ATTR_UPCALL_PID]) {
		struct nlattr *ids = a[OVS_VPORT_ATTR_UPCALL_PID];

		err = ovs_vport_set_upcall_portids(vport, ids);
		if (err)
			goto exit_unlock_free;
	}

	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);

	ovs_unlock();
	ovs_notify(&dp_vport_genl_family, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

// OVS_VPORT_CMD_DEL 处理：从 datapath 删除一个端口。需管理员权限。本地口 OVSP_LOCAL 不可删
static int ovs_vport_cmd_del(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	ovs_lock();
	vport = lookup_vport(sock_net(skb->sk), info->userhdr, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;

	if (vport->port_no == OVSP_LOCAL) {
		// 本地内部口是 datapath 自身的口，随 datapath 生灭，不能单独删除
		err = -EINVAL;
		goto exit_unlock_free;
	}

	// 先构造 DEL 通告（此时端口信息还在），再真正摘除端口
	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_DEL);
	BUG_ON(err < 0);
	ovs_dp_detach_port(vport);
	ovs_unlock();

	ovs_notify(&dp_vport_genl_family, reply, info);
	return 0;

exit_unlock_free:
	ovs_unlock();
	kfree_skb(reply);
	return err;
}

// OVS_VPORT_CMD_GET 处理：查询单个端口信息。允许非特权用户；用 RCU 读侧保护
static int ovs_vport_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr **a = info->attrs;
	struct ovs_header *ovs_header = info->userhdr;
	struct sk_buff *reply;
	struct vport *vport;
	int err;

	reply = ovs_vport_cmd_alloc_info();
	if (!reply)
		return -ENOMEM;

	rcu_read_lock();
	vport = lookup_vport(sock_net(skb->sk), ovs_header, a);
	err = PTR_ERR(vport);
	if (IS_ERR(vport))
		goto exit_unlock_free;
	err = ovs_vport_cmd_fill_info(vport, reply, info->snd_portid,
				      info->snd_seq, 0, OVS_VPORT_CMD_NEW);
	BUG_ON(err < 0);
	rcu_read_unlock();

	return genlmsg_reply(reply, info);

exit_unlock_free:
	rcu_read_unlock();
	kfree_skb(reply);
	return err;
}

// OVS_VPORT_CMD_GET 的 dump 回调：遍历指定 datapath 的所有端口
// cb->args[0]=桶号、cb->args[1]=桶内偏移，支持分批续传
static int ovs_vport_cmd_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ovs_header *ovs_header = genlmsg_data(nlmsg_data(cb->nlh));
	struct datapath *dp;
	int bucket = cb->args[0], skip = cb->args[1];
	int i, j = 0;

	rcu_read_lock();
	dp = get_dp_rcu(sock_net(skb->sk), ovs_header->dp_ifindex);
	if (!dp) {
		rcu_read_unlock();
		return -ENODEV;
	}
	for (i = bucket; i < DP_VPORT_HASH_BUCKETS; i++) {
		struct vport *vport;

		j = 0;
		hlist_for_each_entry_rcu(vport, &dp->ports[i], dp_hash_node) {
			if (j >= skip &&
			    ovs_vport_cmd_fill_info(vport, skb,
						    NETLINK_CB(cb->skb).portid,
						    cb->nlh->nlmsg_seq,
						    NLM_F_MULTI,
						    OVS_VPORT_CMD_NEW) < 0)
				goto out;

			j++;
		}
		skip = 0;
	}
out:
	rcu_read_unlock();

	cb->args[0] = i;
	cb->args[1] = j;

	return skb->len;
}

// vport 族属性校验策略：名字、统计、端口号、类型、上送 PID、选项
static const struct nla_policy vport_policy[OVS_VPORT_ATTR_MAX + 1] = {
	[OVS_VPORT_ATTR_NAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[OVS_VPORT_ATTR_STATS] = { .len = sizeof(struct ovs_vport_stats) },
	[OVS_VPORT_ATTR_PORT_NO] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_TYPE] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_UPCALL_PID] = { .type = NLA_U32 },
	[OVS_VPORT_ATTR_OPTIONS] = { .type = NLA_NESTED },
};

// vport 族命令表：NEW/DEL/SET 需管理员权限，GET 允许非特权并支持 dump
static const struct genl_ops dp_vport_genl_ops[] = {
	{ .cmd = OVS_VPORT_CMD_NEW,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_new
	},
	{ .cmd = OVS_VPORT_CMD_DEL,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_del
	},
	{ .cmd = OVS_VPORT_CMD_GET,
	  .flags = 0,		    /* OK for unprivileged users. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_get,
	  .dumpit = ovs_vport_cmd_dump
	},
	{ .cmd = OVS_VPORT_CMD_SET,
	  .flags = GENL_ADMIN_PERM, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = vport_policy,
	  .doit = ovs_vport_cmd_set,
	},
};

// vport 命令族定义（非 static：datapath.h 声明为 extern，供 vport-netdev 等模块引用）
struct genl_family dp_vport_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = sizeof(struct ovs_header),
	.name = OVS_VPORT_FAMILY,
	.version = OVS_VPORT_VERSION,
	.maxattr = OVS_VPORT_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = dp_vport_genl_ops,
	.n_ops = ARRAY_SIZE(dp_vport_genl_ops),
	.mcgrps = &ovs_dp_vport_multicast_group,
	.n_mcgrps = 1,
};

// 需要向 Generic Netlink 注册的四个 OVS 命令族
static struct genl_family * const dp_genl_families[] = {
	&dp_datapath_genl_family,
	&dp_vport_genl_family,
	&dp_flow_genl_family,
	&dp_packet_genl_family,
};

// 注销前 n 个命令族（用于注册失败时的回滚，以及模块卸载）
static void dp_unregister_genl(int n_families)
{
	int i;

	for (i = 0; i < n_families; i++)
		genl_unregister_family(dp_genl_families[i]);
}

// 依次注册全部命令族；任一失败则回滚已注册的部分
static int dp_register_genl(void)
{
	int err;
	int i;

	for (i = 0; i < ARRAY_SIZE(dp_genl_families); i++) {

		err = genl_register_family(dp_genl_families[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	dp_unregister_genl(i);
	return err;
}

// per-netns 初始化：初始化本命名空间的 datapath 链表与设备通知工作项
static int __net_init ovs_init_net(struct net *net)
{
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);

	INIT_LIST_HEAD(&ovs_net->dps);
	INIT_WORK(&ovs_net->dp_notify_work, ovs_dp_notify_wq);
	return 0;
}

// 收集 net 命名空间内、底层设备属于 dnet 的所有 internal 型端口，挂到 head 待批量摘除
static void __net_exit list_vports_from_net(struct net *net, struct net *dnet,
					    struct list_head *head)
{
	struct ovs_net *ovs_net = net_generic(net, ovs_net_id);
	struct datapath *dp;

	list_for_each_entry(dp, &ovs_net->dps, list_node) {
		int i;

		for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
			struct vport *vport;

			hlist_for_each_entry(vport, &dp->ports[i], dp_hash_node) {
				struct netdev_vport *netdev_vport;

				if (vport->ops->type != OVS_VPORT_TYPE_INTERNAL)
					continue;

				netdev_vport = netdev_vport_priv(vport);
				if (dev_net(netdev_vport->dev) == dnet)
					list_add(&vport->detach_list, head);
			}
		}
	}
}

// per-netns 退出：销毁本命名空间内所有 datapath，并把散落在其它命名空间、
// 但底层设备属于本命名空间的 internal 端口一并摘除
static void __net_exit ovs_exit_net(struct net *dnet)
{
	struct datapath *dp, *dp_next;
	struct ovs_net *ovs_net = net_generic(dnet, ovs_net_id);
	struct vport *vport, *vport_next;
	struct net *net;
	LIST_HEAD(head);

	ovs_lock();
	// 销毁本 netns 拥有的全部 datapath
	list_for_each_entry_safe(dp, dp_next, &ovs_net->dps, list_node)
		__dp_destroy(dp);

	// 遍历所有命名空间，收集底层设备属于本 netns 的 internal 端口
	rtnl_lock();
	for_each_net(net)
		list_vports_from_net(net, dnet, &head);
	rtnl_unlock();

	/* Detach all vports from given namespace. */
	// 逐个摘除上面收集到的端口
	list_for_each_entry_safe(vport, vport_next, &head, detach_list) {
		list_del(&vport->detach_list);
		ovs_dp_detach_port(vport);
	}

	ovs_unlock();

	// 等待设备通知工作项完成，避免退出后仍访问已释放数据
	cancel_work_sync(&ovs_net->dp_notify_work);
}

// per-netns 操作注册：init/exit 回调，size 为每 netns 的 ovs_net 大小
static struct pernet_operations ovs_net_ops = {
	.init = ovs_init_net,
	.exit = ovs_exit_net,
	.id   = &ovs_net_id,
	.size = sizeof(struct ovs_net),
};

// 模块加载入口：按依赖顺序初始化各子系统，任一失败逐级回滚
static int __init dp_init(void)
{
	int err;

	// 编译期断言：OVS 私有控制块必须能塞进 skb->cb
	BUILD_BUG_ON(sizeof(struct ovs_skb_cb) > FIELD_SIZEOF(struct sk_buff, cb));

	pr_info("Open vSwitch switching datapath\n");

	err = action_fifos_init();
	if (err)
		goto error;

	err = ovs_internal_dev_rtnl_link_register();
	if (err)
		goto error_action_fifos_exit;

	err = ovs_flow_init();
	if (err)
		goto error_unreg_rtnl_link;

	err = ovs_vport_init();
	if (err)
		goto error_flow_exit;

	err = register_pernet_device(&ovs_net_ops);
	if (err)
		goto error_vport_exit;

	err = register_netdevice_notifier(&ovs_dp_device_notifier);
	if (err)
		goto error_netns_exit;

	err = ovs_netdev_init();
	if (err)
		goto error_unreg_notifier;

	// 最后注册 Generic Netlink 命令族，对外开放控制接口
	err = dp_register_genl();
	if (err < 0)
		goto error_unreg_netdev;

	return 0;

error_unreg_netdev:
	ovs_netdev_exit();
error_unreg_notifier:
	unregister_netdevice_notifier(&ovs_dp_device_notifier);
error_netns_exit:
	unregister_pernet_device(&ovs_net_ops);
error_vport_exit:
	ovs_vport_exit();
error_flow_exit:
	ovs_flow_exit();
error_unreg_rtnl_link:
	ovs_internal_dev_rtnl_link_unregister();
error_action_fifos_exit:
	action_fifos_exit();
error:
	return err;
}

// 模块卸载出口：按与加载相反的顺序注销各子系统；rcu_barrier 确保延迟释放全部完成
static void dp_cleanup(void)
{
	dp_unregister_genl(ARRAY_SIZE(dp_genl_families));
	ovs_netdev_exit();
	unregister_netdevice_notifier(&ovs_dp_device_notifier);
	unregister_pernet_device(&ovs_net_ops);
	rcu_barrier();
	ovs_vport_exit();
	ovs_flow_exit();
	ovs_internal_dev_rtnl_link_unregister();
	action_fifos_exit();
}

module_init(dp_init);
module_exit(dp_cleanup);

MODULE_DESCRIPTION("Open vSwitch switching datapath");
MODULE_LICENSE("GPL");
