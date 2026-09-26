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

#include <linux/netdevice.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>

#include "datapath.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

// 把一个 vport 从 datapath 上摘除，并通过 generic netlink 向用户态
// (ovs-vswitchd)广播一条 OVS_VPORT_CMD_DEL 通知，告知该端口已被删除。
static void dp_detach_port_notify(struct vport *vport)
{
	struct sk_buff *notify;
	struct datapath *dp;

	dp = vport->dp;
	// 先构造删除通知消息(在真正摘除前构造，此时 vport 信息仍完整)
	notify = ovs_vport_cmd_build_info(vport, 0, 0,
					  OVS_VPORT_CMD_DEL);
	// 将端口从 datapath 摘除
	ovs_dp_detach_port(vport);
	// 构造消息失败：向监听者广播错误码后返回
	if (IS_ERR(notify)) {
		genl_set_err(&dp_vport_genl_family, ovs_dp_get_net(dp), 0,
			     0, PTR_ERR(notify));
		return;
	}

	// 向该 netns 内 vport 组播组广播删除通知
	genlmsg_multicast_netns(&dp_vport_genl_family,
				ovs_dp_get_net(dp), notify, 0,
				0, GFP_KERNEL);
}

// 工作队列处理函数：由 dp_device_event 在设备注销时调度到 system_wq 执行。
// 之所以延迟到工作队列，是因为设备注销发生在 notifier(可能持有 rtnl 等)上下文，
// 而真正摘除端口需要 ovs_lock 并可能睡眠，不宜在原上下文直接做。
// 这里遍历本 netns 所有 datapath 的所有 netdev 端口，找出底层设备已消失
// (IFF_OVS_DATAPATH 标记已被 ovs_netdev_detach_dev 清除)的端口并彻底摘除。
void ovs_dp_notify_wq(struct work_struct *work)
{
	struct ovs_net *ovs_net = container_of(work, struct ovs_net, dp_notify_work);
	struct datapath *dp;

	ovs_lock();
	// 遍历本网络命名空间下所有 datapath
	list_for_each_entry(dp, &ovs_net->dps, list_node) {
		int i;

		// 遍历该 datapath 端口哈希表的每个桶
		for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
			struct vport *vport;
			struct hlist_node *n;

			// 用 safe 变体，因为循环体内可能删除当前节点
			hlist_for_each_entry_safe(vport, n, &dp->ports[i], dp_hash_node) {
				struct netdev_vport *netdev_vport;

				// 只处理 netdev 类型端口，其它类型跳过
				if (vport->ops->type != OVS_VPORT_TYPE_NETDEV)
					continue;

				netdev_vport = netdev_vport_priv(vport);
				// 标记已被清除说明底层设备已解绑/消失，需摘除该端口
				if (!(netdev_vport->dev->priv_flags & IFF_OVS_DATAPATH))
					dp_detach_port_notify(vport);
			}
		}
	}
	ovs_unlock();
}

// 网络设备事件回调：注册到内核 netdev 事件链(见文件末尾 notifier_block)。
// 当某个网络设备发生注册/注销/改名等事件时被调用，用来感知作为 OVS 端口的
// 底层设备是否消失，从而及时把对应端口从 datapath 清理掉。
static int dp_device_event(struct notifier_block *unused, unsigned long event,
			   void *ptr)
{
	struct ovs_net *ovs_net;
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct vport *vport = NULL;

	// 内部设备由 OVS 自己管理，其事件无需在此处理;
	// 非内部设备则尝试反查它对应的 netdev vport
	if (!ovs_is_internal_dev(dev))
		vport = ovs_netdev_get_vport(dev);

	// 该设备不是 OVS 端口，忽略此事件
	if (!vport)
		return NOTIFY_DONE;

	// 只关心设备被注销的事件
	if (event == NETDEV_UNREGISTER) {
		/* upper_dev_unlink and decrement promisc immediately */
		// 立刻解除主从关系、注销 rx_handler、恢复混杂计数
		// (必须在设备真正消失前、仍持有 rtnl 的上下文里同步完成)
		ovs_netdev_detach_dev(vport);

		/* schedule vport destroy, dev_put and genl notification */
		// 剩余的 vport 销毁、dev_put 和 netlink 通知延迟到工作队列去做
		ovs_net = net_generic(dev_net(dev), ovs_net_id);
		queue_work(system_wq, &ovs_net->dp_notify_work);
	}

	return NOTIFY_DONE;
}

// OVS 的网络设备事件 notifier，注册到内核以便接收上述设备事件。
struct notifier_block ovs_dp_device_notifier = {
	.notifier_call = dp_device_event
};
