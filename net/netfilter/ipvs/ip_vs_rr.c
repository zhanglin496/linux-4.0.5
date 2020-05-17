/*
 * IPVS:        Round-Robin Scheduling module
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Peter Kese <peter.kese@ijs.si>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Fixes/Changes:
 *     Wensong Zhang            :     changed the ip_vs_rr_schedule to return dest
 *     Julian Anastasov         :     fixed the NULL pointer access bug in debugging
 *     Wensong Zhang            :     changed some comestics things for debugging
 *     Wensong Zhang            :     changed for the d-linked destination list
 *     Wensong Zhang            :     added the ip_vs_rr_update_svc
 *     Wensong Zhang            :     added any dest with weight=0 is quiesced
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>

#include <net/ip_vs.h>


static int ip_vs_rr_init_svc(struct ip_vs_service *svc)
{
	svc->sched_data = &svc->destinations;
	return 0;
}


static int ip_vs_rr_del_dest(struct ip_vs_service *svc, struct ip_vs_dest *dest)
{
	struct list_head *p;

	spin_lock_bh(&svc->sched_lock);
	p = (struct list_head *) svc->sched_data;
	/* dest is already unlinked, so p->prev is not valid but
	 * p->next is valid, use it to reach previous entry.
	 */
	if (p == &dest->n_list)
		svc->sched_data = p->next->prev;
	spin_unlock_bh(&svc->sched_lock);
	return 0;
}


/*
 * Round-Robin Scheduling
 */
 //轮转调度算法
 //每来一个连接就依次选择一个服务器
static struct ip_vs_dest *
ip_vs_rr_schedule(struct ip_vs_service *svc, const struct sk_buff *skb,
		  struct ip_vs_iphdr *iph)
{
	struct list_head *p;
	struct ip_vs_dest *dest, *last;
	int pass = 0;

	IP_VS_DBG(6, "%s(): Scheduling...\n", __func__);

	spin_lock_bh(&svc->sched_lock);
	p = (struct list_head *) svc->sched_data;
	last = dest = list_entry(p, struct ip_vs_dest, n_list);

	do {
		list_for_each_entry_continue_rcu(dest,
						 &svc->destinations,
						 n_list) {
			//检查服务器是否超载
			//检查服务器的权重值是否为0 
			//用户可以配置weight为0来临时禁止使用该服务器
			//ipvsadm -A -t 192.168.121.130:80 -s rr
			//ipvsadm -a -t 192.168.121.130:80 -r 192.168.121.131:80 -w 1 -m
			if (!(dest->flags & IP_VS_DEST_F_OVERLOAD) &&
			    atomic_read(&dest->weight) > 0)
				/* HIT */
				goto out;
			//所有节点已经遍历完毕，未找到合适的服务器
			if (dest == last)
				goto stop;
		}
		pass++;
		/* Previous dest could be unlinked, do not loop forever.
		 * If we stay at head there is no need for 2nd pass.
		 */
		 //要遍历的两次的原因是last 和 dest 会指向中间节点
		 //为了保证把所有的节点都能遍历一遍
	} while (pass < 2 && p != &svc->destinations);

stop:
	spin_unlock_bh(&svc->sched_lock);
	ip_vs_scheduler_err(svc, "no destination available");
	return NULL;

out:
  	//记住下次从哪个节点开始遍历
	svc->sched_data = &dest->n_list;
	spin_unlock_bh(&svc->sched_lock);
	IP_VS_DBG_BUF(6, "RR: server %s:%u "
		      "activeconns %d refcnt %d weight %d\n",
		      IP_VS_DBG_ADDR(dest->af, &dest->addr), ntohs(dest->port),
		      atomic_read(&dest->activeconns),
		      atomic_read(&dest->refcnt), atomic_read(&dest->weight));

	return dest;
}


static struct ip_vs_scheduler ip_vs_rr_scheduler = {
	.name =			"rr",			/* name */
	.refcnt =		ATOMIC_INIT(0),
	.module =		THIS_MODULE,
	.n_list =		LIST_HEAD_INIT(ip_vs_rr_scheduler.n_list),
	.init_service =		ip_vs_rr_init_svc,
	.add_dest =		NULL,
	.del_dest =		ip_vs_rr_del_dest,
	.schedule =		ip_vs_rr_schedule,
};

static int __init ip_vs_rr_init(void)
{
	return register_ip_vs_scheduler(&ip_vs_rr_scheduler);
}

static void __exit ip_vs_rr_cleanup(void)
{
	unregister_ip_vs_scheduler(&ip_vs_rr_scheduler);
	synchronize_rcu();
}

module_init(ip_vs_rr_init);
module_exit(ip_vs_rr_cleanup);
MODULE_LICENSE("GPL");
