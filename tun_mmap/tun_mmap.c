/*
 *  TUN - Universal TUN/TAP device driver.
 *  Copyright (C) 1999-2002 Maxim Krasnyansky <maxk@qualcomm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  $Id: tun.c,v 1.15 2002/03/01 02:44:24 maxk Exp $
 */

/*
 *  Changes:
 *
 *  Mike Kershaw <dragorn@kismetwireless.net> 2005/08/14
 *    Add TUNSETLINK ioctl to set the link encapsulation
 *
 *  Mark Smith <markzzzsmith@yahoo.com.au>
 *    Use eth_random_addr() for tap MAC address.
 *
 *  Harald Roelle <harald.roelle@ifi.lmu.de>  2004/04/20
 *    Fixes in packet dropping, queue length setting and queue wakeup.
 *    Increased default tx queue length.
 *    Added ethtool API.
 *    Minor cleanups
 *
 *  Daniel Podlejski <underley@underley.eu.org>
 *    Modifications for 2.3.99-pre5 kernel.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define DRV_NAME	"tun_mmap"
#define DRV_VERSION	"1.6"
#define DRV_DESCRIPTION	"Universal TUN/TAP device driver"
#define DRV_COPYRIGHT	"(C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>"

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/miscdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/crc32.h>
#include <linux/nsproxy.h>
#include <linux/virtio_net.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/sock.h>

#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>

#include <asm/uaccess.h>
#include <asm/cacheflush.h>


#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif

#define TUN_STATUS_KERNEL		      0
#define TUN_STATUS_USER			(1 << 0)

struct tun_packet_req {
	unsigned int	tp_block_size;	/* Minimal size of contiguous block */
	unsigned int	tp_block_nr;	/* Number of blocks */
	unsigned int	tp_frame_size;	/* Size of frame */
	unsigned int	tp_frame_nr;	/* Total number of frames */
};

struct tun_packet_hdr {
	unsigned long	tp_status;
	unsigned int	tp_len;
	unsigned int	tp_snaplen;
	unsigned short tp_mac;
	unsigned short tp_net;
	unsigned int	tp_sec;
	unsigned int	tp_usec;
};

union tun_packet_uhdr {
	struct tun_packet_hdr  *h1;
	void *raw;
};

struct pgv {
	char *buffer;
};

struct tun_ring_buffer {
	struct pgv		*pg_vec;

	unsigned int		head;
	unsigned int		frames_per_block;
	unsigned int		frame_size;
	unsigned int		frame_max;

	unsigned int		pg_vec_order;
	unsigned int		pg_vec_pages;
	unsigned int		pg_vec_len;

	unsigned int __percpu	*pending_refcnt;
};

enum tun_packet_versions {
	TUN_PACKET_V1,
};

union tun_packet_req_u {
	struct tun_packet_req req;
};

#define TUN_PACKET_RX_RING _IOW('T', 224, union tun_packet_req_u)
#define TUN_PACKET_TX_RING _IOW('T', 225, union tun_packet_req_u)

/* Uncomment to enable debugging */
/* #define TUN_DEBUG 1 */

#ifdef TUN_DEBUG
static int debug;

#define tun_debug(level, tun, fmt, args...)			\
do {								\
	if (tun->debug)						\
		netdev_printk(level, tun->dev, fmt, ##args);	\
} while (0)
#define DBG1(level, fmt, args...)				\
do {								\
	if (debug == 2)						\
		printk(level fmt, ##args);			\
} while (0)
#else
#define tun_debug(level, tun, fmt, args...)			\
do {								\
	if (0)							\
		netdev_printk(level, tun->dev, fmt, ##args);	\
} while (0)
#define DBG1(level, fmt, args...)				\
do {								\
	if (0)							\
		printk(level fmt, ##args);			\
} while (0)
#endif

#define GOODCOPY_LEN 128

#define FLT_EXACT_COUNT 8
struct tap_filter {
	unsigned int    count;    /* Number of addrs. Zero means disabled */
	u32             mask[2];  /* Mask of the hashed addrs */
	unsigned char	addr[FLT_EXACT_COUNT][ETH_ALEN];
};

/* DEFAULT_MAX_NUM_RSS_QUEUES were choosed to let the rx/tx queues allocated for
 * the netdevice to be fit in one page. So we can make sure the success of
 * memory allocation. TODO: increase the limit. */
#define MAX_TAP_QUEUES DEFAULT_MAX_NUM_RSS_QUEUES
#define MAX_TAP_FLOWS  4096

#define TUN_FLOW_EXPIRE (3 * HZ)

/* A tun_file connects an open character device to a tuntap netdevice. It
 * also contains all socket related strctures (except sock_fprog and tap_filter)
 * to serve as one transmit queue for tuntap device. The sock_fprog and
 * tap_filter were kept in tun_struct since they were used for filtering for the
 * netdevice not for a specific queue (at least I didn't see the requirement for
 * this).
 *
 * RCU usage:
 * The tun_file and tun_struct are loosely coupled, the pointer from one to the
 * other can only be read while rcu_read_lock or rtnl_lock is held.
 */
struct tun_file {
	struct sock sk;
	struct socket socket;
	struct socket_wq wq;
	struct tun_struct __rcu *tun;
	struct net *net;
	struct fasync_struct *fasync;

	union  tpacket_stats_u	stats;
	struct tun_ring_buffer	rx_ring;
	struct tun_ring_buffer	tx_ring;
	struct mutex		pg_vec_lock;
	__be16			num;
	atomic_t		mapped;
	enum tun_packet_versions	tp_version;
	unsigned int		tp_hdrlen;
	unsigned int		tp_reserve;

	/* only used for fasnyc */
	unsigned int flags;
	u16 queue_index;
	struct list_head next;
	struct tun_struct *detached;
};

struct tun_flow_entry {
	struct hlist_node hash_link;
	struct rcu_head rcu;
	struct tun_struct *tun;

	u32 rxhash;
	int queue_index;
	unsigned long updated;
};



#define TUN_NUM_FLOW_ENTRIES 1024

/* Since the socket were moved to tun_file, to preserve the behavior of persist
 * device, socket filter, sndbuf and vnet header size were restore when the
 * file were attached to a persist device.
 */
struct tun_struct {
	struct tun_file __rcu	*tfiles[MAX_TAP_QUEUES];
	unsigned int            numqueues;
	unsigned int 		flags;
	kuid_t			owner;
	kgid_t			group;

	struct net_device	*dev;
	netdev_features_t	set_features;
#define TUN_USER_FEATURES (NETIF_F_HW_CSUM|NETIF_F_TSO_ECN|NETIF_F_TSO| \
			  NETIF_F_TSO6|NETIF_F_UFO)

	int			vnet_hdr_sz;
	int			sndbuf;
	struct tap_filter	txflt;
	struct sock_fprog	fprog;
	/* protected by rtnl lock */
	bool			filter_attached;
#ifdef TUN_DEBUG
	int debug;
#endif
	spinlock_t lock;
	struct hlist_head flows[TUN_NUM_FLOW_ENTRIES];
	struct timer_list flow_gc_timer;
	unsigned long ageing_time;
	unsigned int numdisabled;
	struct list_head disabled;
	void *security;
	u32 flow_count;
};


static inline __pure struct page *pgv_to_page(void *addr);
static void *packet_lookup_frame(struct tun_file *po,
		struct tun_ring_buffer *rb,
		unsigned int position,
		int status);
static long tun_mmap_ioctl(struct file *file,
                          unsigned int cmd, unsigned long arg);
static int packet_set_ring(struct tun_file *tfile, struct sock *sk, union tun_packet_req_u *req_u,
		int closing, int tx_ring);


static void packet_inc_pending(struct tun_ring_buffer *rb)
{
	this_cpu_inc(*rb->pending_refcnt);
}

static void packet_dec_pending(struct tun_ring_buffer *rb)
{
	this_cpu_dec(*rb->pending_refcnt);
}

static unsigned int packet_read_pending(const struct tun_ring_buffer *rb)
{
	unsigned int refcnt = 0;
	int cpu;

	/* We don't use pending refcount in rx_ring. */
	if (rb->pending_refcnt == NULL)
		return 0;

	for_each_possible_cpu(cpu)
		refcnt += *per_cpu_ptr(rb->pending_refcnt, cpu);

	return refcnt;
}

static int packet_alloc_pending(struct tun_file *po)
{
	po->rx_ring.pending_refcnt = NULL;

	po->tx_ring.pending_refcnt = alloc_percpu(unsigned int);
	if (unlikely(po->tx_ring.pending_refcnt == NULL))
		return -ENOBUFS;

	return 0;
}

static void packet_free_pending(struct tun_file *po)
{
	free_percpu(po->tx_ring.pending_refcnt);
}

static int __packet_get_status(struct tun_file *po, void *frame)
{
	union tun_packet_uhdr h;

	smp_rmb();

	h.raw = frame;
	switch (po->tp_version) {
	case TUN_PACKET_V1:
		flush_dcache_page(pgv_to_page(&h.h1->tp_status));
		return h.h1->tp_status;
	default:
		WARN(1, "TUN_PACKET version not supported.\n");
		BUG();
		return 0;
	}
}

static void *packet_lookup_frame(struct tun_file *po,
		struct tun_ring_buffer *rb,
		unsigned int position,
		int status)
{
	unsigned int pg_vec_pos, frame_offset;
	union tun_packet_uhdr h;

	pg_vec_pos = position / rb->frames_per_block;
	frame_offset = position % rb->frames_per_block;

	h.raw = rb->pg_vec[pg_vec_pos].buffer +
		(frame_offset * rb->frame_size);
	if (status != __packet_get_status(po, h.raw))
		return NULL;

	return h.raw;
}

static void *packet_current_rx_frame(struct tun_file *po,
					    struct sk_buff *skb,
					    int status, unsigned int len)
{
	char *curr = NULL;
	switch (po->tp_version) {
	case TUN_PACKET_V1:
		curr = packet_lookup_frame(po, &po->rx_ring,
					po->rx_ring.head, status);
		return curr;
	default:
		WARN(1, "TUN_PACKET version not supported\n");
		BUG();
		return NULL;
	}
}

static void *packet_current_frame(struct tun_file *po,
		struct tun_ring_buffer *rb,
		int status)
{
	return packet_lookup_frame(po, rb, rb->head, status);
}

static void packet_increment_head(struct tun_ring_buffer *buff)
{
	buff->head = buff->head != buff->frame_max ? buff->head+1 : 0;
}


static void packet_increment_rx_head(struct tun_file *po,
					    struct tun_ring_buffer *rb)
{
	switch (po->tp_version) {
	case TUN_PACKET_V1:
		return packet_increment_head(rb);
	default:
		WARN(1, "TUN_PACKET version not supported.\n");
		BUG();
		return;
	}
}

static void __packet_set_status(struct tun_file *po, void *frame, int status)
{
	union tun_packet_uhdr h;

	h.raw = frame;
	switch (po->tp_version) {
	case TUN_PACKET_V1:
		h.h1->tp_status = status;
		flush_dcache_page(pgv_to_page(&h.h1->tp_status));
		break;
	default:
		WARN(1, "TUN_PACKET version not supported.\n");
		BUG();
	}

	smp_wmb();
}

static inline u32 tun_hashfn(u32 rxhash)
{
	return rxhash & 0x3ff;
}

static struct tun_flow_entry *tun_flow_find(struct hlist_head *head, u32 rxhash)
{
	struct tun_flow_entry *e;

	hlist_for_each_entry_rcu(e, head, hash_link) {
		if (e->rxhash == rxhash)
			return e;
	}
	return NULL;
}

static struct tun_flow_entry *tun_flow_create(struct tun_struct *tun,
					      struct hlist_head *head,
					      u32 rxhash, u16 queue_index)
{
	struct tun_flow_entry *e = kmalloc(sizeof(*e), GFP_ATOMIC);

	if (e) {
		tun_debug(KERN_INFO, tun, "create flow: hash %u index %u\n",
			  rxhash, queue_index);
		e->updated = jiffies;
		e->rxhash = rxhash;
		e->queue_index = queue_index;
		e->tun = tun;
		hlist_add_head_rcu(&e->hash_link, head);
		++tun->flow_count;
	}
	return e;
}

static void tun_flow_delete(struct tun_struct *tun, struct tun_flow_entry *e)
{
	tun_debug(KERN_INFO, tun, "delete flow: hash %u index %u\n",
		  e->rxhash, e->queue_index);
	hlist_del_rcu(&e->hash_link);
	kfree_rcu(e, rcu);
	--tun->flow_count;
}

static void tun_flow_flush(struct tun_struct *tun)
{
	int i;

	spin_lock_bh(&tun->lock);
	for (i = 0; i < TUN_NUM_FLOW_ENTRIES; i++) {
		struct tun_flow_entry *e;
		struct hlist_node *n;

		hlist_for_each_entry_safe(e, n, &tun->flows[i], hash_link)
			tun_flow_delete(tun, e);
	}
	spin_unlock_bh(&tun->lock);
}

static void tun_flow_delete_by_queue(struct tun_struct *tun, u16 queue_index)
{
	int i;

	spin_lock_bh(&tun->lock);
	for (i = 0; i < TUN_NUM_FLOW_ENTRIES; i++) {
		struct tun_flow_entry *e;
		struct hlist_node *n;

		hlist_for_each_entry_safe(e, n, &tun->flows[i], hash_link) {
			if (e->queue_index == queue_index)
				tun_flow_delete(tun, e);
		}
	}
	spin_unlock_bh(&tun->lock);
}

static void tun_flow_cleanup(unsigned long data)
{
	struct tun_struct *tun = (struct tun_struct *)data;
	unsigned long delay = tun->ageing_time;
	unsigned long next_timer = jiffies + delay;
	unsigned long count = 0;
	int i;

	tun_debug(KERN_INFO, tun, "tun_flow_cleanup\n");

	spin_lock_bh(&tun->lock);
	for (i = 0; i < TUN_NUM_FLOW_ENTRIES; i++) {
		struct tun_flow_entry *e;
		struct hlist_node *n;

		hlist_for_each_entry_safe(e, n, &tun->flows[i], hash_link) {
			unsigned long this_timer;
			count++;
			this_timer = e->updated + delay;
			if (time_before_eq(this_timer, jiffies))
				tun_flow_delete(tun, e);
			else if (time_before(this_timer, next_timer))
				next_timer = this_timer;
		}
	}

	if (count)
		mod_timer(&tun->flow_gc_timer, round_jiffies_up(next_timer));
	spin_unlock_bh(&tun->lock);
}

static void tun_flow_update(struct tun_struct *tun, u32 rxhash,
			    struct tun_file *tfile)
{
	struct hlist_head *head;
	struct tun_flow_entry *e;
	unsigned long delay = tun->ageing_time;
	u16 queue_index = tfile->queue_index;

	if (!rxhash)
		return;
	else
		head = &tun->flows[tun_hashfn(rxhash)];

	rcu_read_lock();

	/* We may get a very small possibility of OOO during switching, not
	 * worth to optimize.*/
	if (tun->numqueues == 1 || tfile->detached)
		goto unlock;

	e = tun_flow_find(head, rxhash);
	if (likely(e)) {
		/* TODO: keep queueing to old queue until it's empty? */
		e->queue_index = queue_index;
		e->updated = jiffies;
	} else {
		spin_lock_bh(&tun->lock);
		if (!tun_flow_find(head, rxhash) &&
		    tun->flow_count < MAX_TAP_FLOWS)
			tun_flow_create(tun, head, rxhash, queue_index);

		if (!timer_pending(&tun->flow_gc_timer))
			mod_timer(&tun->flow_gc_timer,
				  round_jiffies_up(jiffies + delay));
		spin_unlock_bh(&tun->lock);
	}

unlock:
	rcu_read_unlock();
}

/* We try to identify a flow through its rxhash first. The reason that
 * we do not check rxq no. is becuase some cards(e.g 82599), chooses
 * the rxq based on the txq where the last packet of the flow comes. As
 * the userspace application move between processors, we may get a
 * different rxq no. here. If we could not get rxhash, then we would
 * hope the rxq no. may help here.
 */
static u16 tun_select_queue(struct net_device *dev, struct sk_buff *skb)
{
	struct tun_struct *tun = netdev_priv(dev);
	struct tun_flow_entry *e;
	u32 txq = 0;
	u32 numqueues = 0;

	rcu_read_lock();
	numqueues = ACCESS_ONCE(tun->numqueues);

	txq = skb_get_rxhash(skb);
	if (txq) {
		e = tun_flow_find(&tun->flows[tun_hashfn(txq)], txq);
		if (e)
			txq = e->queue_index;
		else
			/* use multiply and shift instead of expensive divide */
			txq = ((u64)txq * numqueues) >> 32;
	} else if (likely(skb_rx_queue_recorded(skb))) {
		txq = skb_get_rx_queue(skb);
		while (unlikely(txq >= numqueues))
			txq -= numqueues;
	}

	rcu_read_unlock();
	return txq;
}

static inline bool tun_not_capable(struct tun_struct *tun)
{
	const struct cred *cred = current_cred();
	struct net *net = dev_net(tun->dev);

	return ((uid_valid(tun->owner) && !uid_eq(cred->euid, tun->owner)) ||
		  (gid_valid(tun->group) && !in_egroup_p(tun->group))) &&
		!ns_capable(net->user_ns, CAP_NET_ADMIN);
}

static void tun_set_real_num_queues(struct tun_struct *tun)
{
	netif_set_real_num_tx_queues(tun->dev, tun->numqueues);
	netif_set_real_num_rx_queues(tun->dev, tun->numqueues);
}

static void tun_disable_queue(struct tun_struct *tun, struct tun_file *tfile)
{
	tfile->detached = tun;
	list_add_tail(&tfile->next, &tun->disabled);
	++tun->numdisabled;
}

static struct tun_struct *tun_enable_queue(struct tun_file *tfile)
{
	struct tun_struct *tun = tfile->detached;

	tfile->detached = NULL;
	list_del_init(&tfile->next);
	--tun->numdisabled;
	return tun;
}

static void __tun_detach(struct tun_file *tfile, bool clean)
{
	struct tun_file *ntfile;
	struct tun_struct *tun;

	tun = rtnl_dereference(tfile->tun);

	if (tun && !tfile->detached) {
		u16 index = tfile->queue_index;
		BUG_ON(index >= tun->numqueues);

		rcu_assign_pointer(tun->tfiles[index],
				   tun->tfiles[tun->numqueues - 1]);
		ntfile = rtnl_dereference(tun->tfiles[index]);
		ntfile->queue_index = index;

		--tun->numqueues;
		if (clean) {
			rcu_assign_pointer(tfile->tun, NULL);
			sock_put(&tfile->sk);
		} else
			tun_disable_queue(tun, tfile);

		synchronize_net();
		tun_flow_delete_by_queue(tun, tun->numqueues + 1);
		/* Drop read queue */
		skb_queue_purge(&tfile->sk.sk_receive_queue);
		tun_set_real_num_queues(tun);
	} else if (tfile->detached && clean) {
		tun = tun_enable_queue(tfile);
		sock_put(&tfile->sk);
	}

	if (clean) {
		if (tun && tun->numqueues == 0 && tun->numdisabled == 0) {
			netif_carrier_off(tun->dev);

			if (!(tun->flags & TUN_PERSIST) &&
			    tun->dev->reg_state == NETREG_REGISTERED)
				unregister_netdevice(tun->dev);
		}

		BUG_ON(!test_bit(SOCK_EXTERNALLY_ALLOCATED,
				 &tfile->socket.flags));
		sk_release_kernel(&tfile->sk);
	}
}

static void tun_detach(struct tun_file *tfile, bool clean)
{
	rtnl_lock();
	__tun_detach(tfile, clean);
	rtnl_unlock();
}

static void tun_detach_all(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	struct tun_file *tfile, *tmp;
	int i, n = tun->numqueues;

	for (i = 0; i < n; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		BUG_ON(!tfile);
		wake_up_all(&tfile->wq.wait);
		rcu_assign_pointer(tfile->tun, NULL);
		--tun->numqueues;
	}
	list_for_each_entry(tfile, &tun->disabled, next) {
		wake_up_all(&tfile->wq.wait);
		rcu_assign_pointer(tfile->tun, NULL);
	}
	BUG_ON(tun->numqueues != 0);

	synchronize_net();
	for (i = 0; i < n; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		/* Drop read queue */
		skb_queue_purge(&tfile->sk.sk_receive_queue);
		sock_put(&tfile->sk);
	}
	list_for_each_entry_safe(tfile, tmp, &tun->disabled, next) {
		tun_enable_queue(tfile);
		skb_queue_purge(&tfile->sk.sk_receive_queue);
		sock_put(&tfile->sk);
	}
	BUG_ON(tun->numdisabled != 0);

	if (tun->flags & TUN_PERSIST)
		module_put(THIS_MODULE);
}

static int tun_attach(struct tun_struct *tun, struct file *file)
{
	struct tun_file *tfile = file->private_data;
	int err;

	err = security_tun_dev_attach(tfile->socket.sk, tun->security);
	if (err < 0)
		goto out;

	err = -EINVAL;
	if (rtnl_dereference(tfile->tun) && !tfile->detached)
		goto out;

	err = -EBUSY;
	if (!(tun->flags & TUN_TAP_MQ) && tun->numqueues == 1)
		goto out;

	err = -E2BIG;
	if (!tfile->detached &&
	    tun->numqueues + tun->numdisabled == MAX_TAP_QUEUES)
		goto out;

	err = 0;

	/* Re-attach the filter to presist device */
	if (tun->filter_attached == true) {
		err = sk_attach_filter(&tun->fprog, tfile->socket.sk);
		if (!err)
			goto out;
	}
	tfile->queue_index = tun->numqueues;
	rcu_assign_pointer(tfile->tun, tun);
	rcu_assign_pointer(tun->tfiles[tun->numqueues], tfile);
	tun->numqueues++;

	if (tfile->detached)
		tun_enable_queue(tfile);
	else
		sock_hold(&tfile->sk);

	tun_set_real_num_queues(tun);

	/* device is allowed to go away first, so no need to hold extra
	 * refcnt.
	 */

out:
	return err;
}

static struct tun_struct *__tun_get(struct tun_file *tfile)
{
	struct tun_struct *tun;

	rcu_read_lock();
	tun = rcu_dereference(tfile->tun);
	if (tun)
		dev_hold(tun->dev);
	rcu_read_unlock();

	return tun;
}

static struct tun_struct *tun_get(struct file *file)
{
	return __tun_get(file->private_data);
}

static void tun_put(struct tun_struct *tun)
{
	dev_put(tun->dev);
}

/* TAP filtering */
static void addr_hash_set(u32 *mask, const u8 *addr)
{
	int n = ether_crc(ETH_ALEN, addr) >> 26;
	mask[n >> 5] |= (1 << (n & 31));
}

static unsigned int addr_hash_test(const u32 *mask, const u8 *addr)
{
	int n = ether_crc(ETH_ALEN, addr) >> 26;
	return mask[n >> 5] & (1 << (n & 31));
}

static int update_filter(struct tap_filter *filter, void __user *arg)
{
	struct { u8 u[ETH_ALEN]; } *addr;
	struct tun_filter uf;
	int err, alen, n, nexact;

	if (copy_from_user(&uf, arg, sizeof(uf)))
		return -EFAULT;

	if (!uf.count) {
		/* Disabled */
		filter->count = 0;
		return 0;
	}

	alen = ETH_ALEN * uf.count;
	addr = kmalloc(alen, GFP_KERNEL);
	if (!addr)
		return -ENOMEM;

	if (copy_from_user(addr, arg + sizeof(uf), alen)) {
		err = -EFAULT;
		goto done;
	}

	/* The filter is updated without holding any locks. Which is
	 * perfectly safe. We disable it first and in the worst
	 * case we'll accept a few undesired packets. */
	filter->count = 0;
	wmb();

	/* Use first set of addresses as an exact filter */
	for (n = 0; n < uf.count && n < FLT_EXACT_COUNT; n++)
		memcpy(filter->addr[n], addr[n].u, ETH_ALEN);

	nexact = n;

	/* Remaining multicast addresses are hashed,
	 * unicast will leave the filter disabled. */
	memset(filter->mask, 0, sizeof(filter->mask));
	for (; n < uf.count; n++) {
		if (!is_multicast_ether_addr(addr[n].u)) {
			err = 0; /* no filter */
			goto done;
		}
		addr_hash_set(filter->mask, addr[n].u);
	}

	/* For ALLMULTI just set the mask to all ones.
	 * This overrides the mask populated above. */
	if ((uf.flags & TUN_FLT_ALLMULTI))
		memset(filter->mask, ~0, sizeof(filter->mask));

	/* Now enable the filter */
	wmb();
	filter->count = nexact;

	/* Return the number of exact filters */
	err = nexact;

done:
	kfree(addr);
	return err;
}

/* Returns: 0 - drop, !=0 - accept */
static int run_filter(struct tap_filter *filter, const struct sk_buff *skb)
{
	/* Cannot use eth_hdr(skb) here because skb_mac_hdr() is incorrect
	 * at this point. */
	struct ethhdr *eh = (struct ethhdr *) skb->data;
	int i;

	/* Exact match */
	for (i = 0; i < filter->count; i++)
		if (ether_addr_equal(eh->h_dest, filter->addr[i]))
			return 1;

	/* Inexact match (multicast only) */
	if (is_multicast_ether_addr(eh->h_dest))
		return addr_hash_test(filter->mask, eh->h_dest);

	return 0;
}

/*
 * Checks whether the packet is accepted or not.
 * Returns: 0 - drop, !=0 - accept
 */
static int check_filter(struct tap_filter *filter, const struct sk_buff *skb)
{
	if (!filter->count)
		return 1;

	return run_filter(filter, skb);
}

/* Network device part of the driver */

static const struct ethtool_ops tun_ethtool_ops;

/* Net device detach from fd. */
static void tun_net_uninit(struct net_device *dev)
{
	tun_detach_all(dev);
}

/* Net device open. */
static int tun_net_open(struct net_device *dev)
{
	netif_tx_start_all_queues(dev);
	return 0;
}

/* Net device close. */
static int tun_net_close(struct net_device *dev)
{
	netif_tx_stop_all_queues(dev);
	return 0;
}

#ifdef CONFIG_RTK_OPENVPN_HW_CRYPTO
extern int openvpn_fast_to_wan(struct sk_buff *skb);
#endif

static int tun_mmap_xmit(struct sk_buff *skb, struct tun_file *tfile)
{
	struct sock *sk = &tfile->sk;
	union tun_packet_uhdr h;
	unsigned int snaplen;
	unsigned long status = TUN_STATUS_USER;
	unsigned short macoff, netoff, hdrlen;
	struct timespec ts;

	snaplen = skb->len;

	macoff = netoff = TPACKET_ALIGN(tfile->tp_hdrlen) + 16 +
				 tfile->tp_reserve;

	spin_lock(&sk->sk_receive_queue.lock);
	h.raw = packet_current_rx_frame(tfile, skb,
					TUN_STATUS_KERNEL, (macoff+snaplen));
	if (!h.raw)
		goto ring_is_full;
	if (tfile->tp_version <= TUN_PACKET_V1)
		packet_increment_rx_head(tfile, &tfile->rx_ring);

	tfile->stats.stats1.tp_packets++;
	spin_unlock(&sk->sk_receive_queue.lock);

	if (macoff + snaplen > tfile->rx_ring.frame_size) {
		snaplen = tfile->rx_ring.frame_size - macoff;
		if ((int)snaplen < 0)
			snaplen = 0;
	}

	//注意patch中的skb_copy_bits这个调用
	//这个调用事实上是把本应该由skb往
	//用户态read调用缓冲区的拷贝提前到hard-xmit回调中往ring buffer拷贝，
	//仅仅可能节省了一次切换开销
	//(如果用户态正在busy polling的话，则无需唤醒/切换，
	//如果用户态没有在busy polling，那么唤醒/切换还是必须的！)，
	//内存拷贝的开销并没有省却。
	//这一点和物理网卡不一致。
	//物理网卡可以通过DMA机制可以直接将收到的数据包
	//从网卡mem无CPU开销地直接传输到系统mem，
	//而该系统mem是mmap到用户态的，用户态便可以直接操作该mem，
	//从网卡收到数据包到用户进程操作该数据包，全程无需任何数据拷贝。
	//虚拟网卡则无法做到这一点，因为虚拟网卡没有硬件辅助来完成类似DMA的功能。
	skb_copy_bits(skb, 0, h.raw + macoff, snaplen);

	switch (tfile->tp_version) {
	case TUN_PACKET_V1:
		h.h1->tp_len = skb->len;
		h.h1->tp_snaplen = snaplen;
		h.h1->tp_mac = macoff;
		h.h1->tp_net = netoff;
		{
		static int i = 10;
		h.h1->tp_sec = i++;
		}
		h.h1->tp_usec = ts.tv_nsec / NSEC_PER_USEC;
		hdrlen = sizeof(*h.h1);
		break;
	default:
		BUG();
	}

	smp_mb();
#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE == 1
	{
		u8 *start, *end;

		if (tfile->tp_version <= TUN_PACKET_V1) {
			end = (u8 *)PAGE_ALIGN((unsigned long)h.raw
				+ macoff + snaplen);
			for (start = h.raw; start < end; start += PAGE_SIZE)
				flush_dcache_page(pgv_to_page(start));
		}
		smp_wmb();
	}
#endif

	if (tfile->tp_version <= TUN_PACKET_V1)
		__packet_set_status(tfile, h.raw, status);
	//			printk("%s %d tp_sec=%u,status=%u,tp_status=%u,h.raw=%p,len=%d\n", 
	//				__func__, __LINE__, h.h1->tp_sec, status, h.h1->tp_status, h.raw, macoff + snaplen);
	wake_up_interruptible_poll(&tfile->wq.wait, POLLIN |
				  		POLLRDNORM | POLLRDBAND);
drop_n_restore:
	kfree_skb(skb);
	rcu_read_unlock();
	return NETDEV_TX_OK;

ring_is_full:
	tfile->stats.stats1.tp_drops++;
	spin_unlock(&sk->sk_receive_queue.lock);
	wake_up_interruptible_poll(&tfile->wq.wait, POLLIN |
						POLLRDNORM | POLLRDBAND);
	goto drop_n_restore;
}

/* Net device start xmit */
static netdev_tx_t tun_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	int txq = skb->queue_mapping;
	struct tun_file *tfile;

	rcu_read_lock();
	tfile = rcu_dereference(tun->tfiles[txq]);

	/* Drop packet if interface is not attached */
	if (txq >= tun->numqueues)
		goto drop;

	tun_debug(KERN_INFO, tun, "tun_net_xmit %d\n", skb->len);

	BUG_ON(!tfile);

	/* Drop if the filter does not like it.
	 * This is a noop if the filter is disabled.
	 * Filter can be enabled only for the TAP devices. */
	if (!check_filter(&tun->txflt, skb))
		goto drop;

	if (tfile->socket.sk->sk_filter &&
	    sk_filter(tfile->socket.sk, skb))
		goto drop;

	/* Limit the number of packets queued by dividing txq length with the
	 * number of queues.
	 */
	if (skb_queue_len(&tfile->socket.sk->sk_receive_queue)
			  >= dev->tx_queue_len / tun->numqueues)
		goto drop;

	/* Orphan the skb - required as we might hang on to it
	 * for indefinite time. */
	if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC)))
		goto drop;
	skb_orphan(skb);

	nf_reset(skb);

	if (tfile->rx_ring.pg_vec)
		return tun_mmap_xmit(skb, tfile);

	/* Enqueue packet */
	skb_queue_tail(&tfile->socket.sk->sk_receive_queue, skb);

	/* Notify and wake up reader process */
	if (tfile->flags & TUN_FASYNC)
		kill_fasync(&tfile->fasync, SIGIO, POLL_IN);
	wake_up_interruptible_poll(&tfile->wq.wait, POLLIN |
				   POLLRDNORM | POLLRDBAND);

	rcu_read_unlock();
	return NETDEV_TX_OK;

drop:
	dev->stats.tx_dropped++;
	skb_tx_error(skb);
	kfree_skb(skb);
	rcu_read_unlock();
	return NETDEV_TX_OK;
}

static void tun_net_mclist(struct net_device *dev)
{
	/*
	 * This callback is supposed to deal with mc filter in
	 * _rx_ path and has nothing to do with the _tx_ path.
	 * In rx path we always accept everything userspace gives us.
	 */
}

#define MIN_MTU 68
#define MAX_MTU 65535

static int
tun_net_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < MIN_MTU || new_mtu + dev->hard_header_len > MAX_MTU)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static netdev_features_t tun_net_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	struct tun_struct *tun = netdev_priv(dev);

	return (features & tun->set_features) | (features & ~TUN_USER_FEATURES);
}
#ifdef CONFIG_NET_POLL_CONTROLLER
static void tun_poll_controller(struct net_device *dev)
{
	/*
	 * Tun only receives frames when:
	 * 1) the char device endpoint gets data from user space
	 * 2) the tun socket gets a sendmsg call from user space
	 * Since both of those are syncronous operations, we are guaranteed
	 * never to have pending data when we poll for it
	 * so theres nothing to do here but return.
	 * We need this though so netpoll recognizes us as an interface that
	 * supports polling, which enables bridge devices in virt setups to
	 * still use netconsole
	 */
	return;
}
#endif
static const struct net_device_ops tun_netdev_ops = {
	.ndo_uninit		= tun_net_uninit,
	.ndo_open		= tun_net_open,
	.ndo_stop		= tun_net_close,
	.ndo_start_xmit		= tun_net_xmit,
	.ndo_change_mtu		= tun_net_change_mtu,
	.ndo_fix_features	= tun_net_fix_features,
	.ndo_select_queue	= tun_select_queue,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= tun_poll_controller,
#endif
};

static const struct net_device_ops tap_netdev_ops = {
	.ndo_uninit		= tun_net_uninit,
	.ndo_open		= tun_net_open,
	.ndo_stop		= tun_net_close,
	.ndo_start_xmit		= tun_net_xmit,
	.ndo_change_mtu		= tun_net_change_mtu,
	.ndo_fix_features	= tun_net_fix_features,
	.ndo_set_rx_mode	= tun_net_mclist,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_select_queue	= tun_select_queue,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= tun_poll_controller,
#endif
};

static int tun_flow_init(struct tun_struct *tun)
{
	int i;

	for (i = 0; i < TUN_NUM_FLOW_ENTRIES; i++)
		INIT_HLIST_HEAD(&tun->flows[i]);

	tun->ageing_time = TUN_FLOW_EXPIRE;
	setup_timer(&tun->flow_gc_timer, tun_flow_cleanup, (unsigned long)tun);
	mod_timer(&tun->flow_gc_timer,
		  round_jiffies_up(jiffies + tun->ageing_time));

	return 0;
}

static void tun_flow_uninit(struct tun_struct *tun)
{
	del_timer_sync(&tun->flow_gc_timer);
	tun_flow_flush(tun);
}

/* Initialize net device. */
static void tun_net_init(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		dev->netdev_ops = &tun_netdev_ops;

		/* Point-to-Point TUN Device */
		dev->hard_header_len = 0;
		dev->addr_len = 0;
		dev->mtu = 1500;

		/* Zero header length */
		dev->type = ARPHRD_NONE;
		dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
		dev->tx_queue_len = TUN_READQ_SIZE;  /* We prefer our own queue length */
		break;

	case TUN_TAP_DEV:
		dev->netdev_ops = &tap_netdev_ops;
		/* Ethernet TAP Device */
		ether_setup(dev);
		dev->priv_flags &= ~IFF_TX_SKB_SHARING;
		dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

		eth_hw_addr_random(dev);

		dev->tx_queue_len = TUN_READQ_SIZE;  /* We prefer our own queue length */
		break;
	}
}

/* Character device part */

static void *packet_previous_frame(struct tun_file *po,
		struct tun_ring_buffer *rb,
		int status)
{
	unsigned int previous = rb->head ? rb->head - 1 : rb->frame_max;
	return packet_lookup_frame(po, rb, previous, status);
}

static void *packet_previous_rx_frame(struct tun_file *po,
					     struct tun_ring_buffer *rb,
					     int status)
{
	if (po->tp_version <= TPACKET_V2)
		return packet_previous_frame(po, rb, status);
	return NULL;
}

/* Poll */
static unsigned int tun_chr_poll(struct file *file, poll_table *wait)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun = __tun_get(tfile);
	struct sock *sk;
	unsigned int mask = 0;

	if (!tun)
		return POLLERR;

	sk = tfile->socket.sk;

	tun_debug(KERN_INFO, tun, "tun_chr_poll\n");

	poll_wait(file, &tfile->wq.wait, wait);

	spin_lock_bh(&sk->sk_receive_queue.lock);
	if (tfile->rx_ring.pg_vec) {
		if (!packet_previous_rx_frame(tfile, &tfile->rx_ring,
			TUN_STATUS_KERNEL)) {
			mask |= POLLIN | POLLRDNORM;
		}
	}
	spin_unlock_bh(&sk->sk_receive_queue.lock);

	if (!skb_queue_empty(&sk->sk_receive_queue))
		mask |= POLLIN | POLLRDNORM;

	if (sock_writeable(sk) ||
	    (!test_and_set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags) &&
	     sock_writeable(sk)))
		mask |= POLLOUT | POLLWRNORM;

	if (tun->dev->reg_state != NETREG_REGISTERED)
		mask = POLLERR;

	tun_put(tun);
	return mask;
}

/* prepad is the amount to reserve at front.  len is length after that.
 * linear is a hint as to how much to copy (usually headers). */
static struct sk_buff *tun_alloc_skb(struct tun_file *tfile,
				     size_t prepad, size_t len,
				     size_t linear, int noblock)
{
	struct sock *sk = tfile->socket.sk;
	struct sk_buff *skb;
	int err;

	/* Under a page?  Don't bother with paged skb. */
	if (prepad + len < PAGE_SIZE || !linear)
		linear = len;

	skb = sock_alloc_send_pskb(sk, prepad + linear, len - linear, noblock,
				   &err);
	if (!skb)
		return ERR_PTR(err);

	skb_reserve(skb, prepad);
	skb_put(skb, linear);
	skb->data_len = len - linear;
	skb->len += len - linear;

	return skb;
}

/* set skb frags from iovec, this can move to core network code for reuse */
static int zerocopy_sg_from_iovec(struct sk_buff *skb, const struct iovec *from,
				  int offset, size_t count)
{
	int len = iov_length(from, count) - offset;
	int copy = skb_headlen(skb);
	int size, offset1 = 0;
	int i = 0;

	/* Skip over from offset */
	while (count && (offset >= from->iov_len)) {
		offset -= from->iov_len;
		++from;
		--count;
	}

	/* copy up to skb headlen */
	while (count && (copy > 0)) {
		size = min_t(unsigned int, copy, from->iov_len - offset);
		if (copy_from_user(skb->data + offset1, from->iov_base + offset,
				   size))
			return -EFAULT;
		if (copy > size) {
			++from;
			--count;
			offset = 0;
		} else
			offset += size;
		copy -= size;
		offset1 += size;
	}

	if (len == offset1)
		return 0;

	while (count--) {
		struct page *page[MAX_SKB_FRAGS];
		int num_pages;
		unsigned long base;
		unsigned long truesize;

		len = from->iov_len - offset;
		if (!len) {
			offset = 0;
			++from;
			continue;
		}
		base = (unsigned long)from->iov_base + offset;
		size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
		if (i + size > MAX_SKB_FRAGS)
			return -EMSGSIZE;
		num_pages = get_user_pages_fast(base, size, 0, &page[i]);
		if (num_pages != size) {
			int j;

			for (j = 0; j < num_pages; j++)
				put_page(page[i + j]);
			return -EFAULT;
		}
		truesize = size * PAGE_SIZE;
		skb->data_len += len;
		skb->len += len;
		skb->truesize += truesize;
		atomic_add(truesize, &skb->sk->sk_wmem_alloc);
		while (len) {
			int off = base & ~PAGE_MASK;
			int size = min_t(int, len, PAGE_SIZE - off);
			__skb_fill_page_desc(skb, i, page[i], off, size);
			skb_shinfo(skb)->nr_frags++;
			/* increase sk_wmem_alloc */
			base += size;
			len -= size;
			i++;
		}
		offset = 0;
		++from;
	}
	return 0;
}

static unsigned long iov_pages(const struct iovec *iv, int offset,
			       unsigned long nr_segs)
{
	unsigned long seg, base;
	int pages = 0, len, size;

	while (nr_segs && (offset >= iv->iov_len)) {
		offset -= iv->iov_len;
		++iv;
		--nr_segs;
	}

	for (seg = 0; seg < nr_segs; seg++) {
		base = (unsigned long)iv[seg].iov_base + offset;
		len = iv[seg].iov_len - offset;
		size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
		pages += size;
		offset = 0;
	}

	return pages;
}

/* Get packet from user space buffer */
static ssize_t tun_get_user(struct tun_struct *tun, struct tun_file *tfile,
			    void *msg_control, const struct iovec *iv,
			    size_t total_len, size_t count, int noblock)
{
	struct tun_pi pi = { 0, cpu_to_be16(ETH_P_IP) };
	struct sk_buff *skb;
	size_t len = total_len, align = NET_SKB_PAD, linear;
	struct virtio_net_hdr gso = { 0 };
	int good_linear;
	int offset = 0;
	int copylen;
	bool zerocopy = false;
	int err;
	u32 rxhash;

	if (!(tun->flags & TUN_NO_PI)) {
		if (len < sizeof(pi))
			return -EINVAL;
		len -= sizeof(pi);

		if (memcpy_fromiovecend((void *)&pi, iv, 0, sizeof(pi)))
			return -EFAULT;
		offset += sizeof(pi);
	}

	if (tun->flags & TUN_VNET_HDR) {
		if (len < tun->vnet_hdr_sz)
			return -EINVAL;
		len -= tun->vnet_hdr_sz;

		if (memcpy_fromiovecend((void *)&gso, iv, offset, sizeof(gso)))
			return -EFAULT;

		if ((gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
		    gso.csum_start + gso.csum_offset + 2 > gso.hdr_len)
			gso.hdr_len = gso.csum_start + gso.csum_offset + 2;

		if (gso.hdr_len > len)
			return -EINVAL;
		offset += tun->vnet_hdr_sz;
	}

	if ((tun->flags & TUN_TYPE_MASK) == TUN_TAP_DEV) {
		align += NET_IP_ALIGN;
		if (unlikely(len < ETH_HLEN ||
			     (gso.hdr_len && gso.hdr_len < ETH_HLEN)))
			return -EINVAL;
	}

	good_linear = SKB_MAX_HEAD(align);

	if (msg_control) {
		/* There are 256 bytes to be copied in skb, so there is
		 * enough room for skb expand head in case it is used.
		 * The rest of the buffer is mapped from userspace.
		 */
		copylen = gso.hdr_len ? gso.hdr_len : GOODCOPY_LEN;
		if (copylen > good_linear)
			copylen = good_linear;
		linear = copylen;
		if (iov_pages(iv, offset + copylen, count) <= MAX_SKB_FRAGS)
			zerocopy = true;
	}

	if (!zerocopy) {
		copylen = len;
		if (gso.hdr_len > good_linear)
			linear = good_linear;
		else
			linear = gso.hdr_len;
	}

	skb = tun_alloc_skb(tfile, align, copylen, linear, noblock);
	if (IS_ERR(skb)) {
		if (PTR_ERR(skb) != -EAGAIN)
			tun->dev->stats.rx_dropped++;
		return PTR_ERR(skb);
	}

	if (zerocopy)
		err = zerocopy_sg_from_iovec(skb, iv, offset, count);
	else {
		err = skb_copy_datagram_from_iovec(skb, 0, iv, offset, len);
		if (!err && msg_control) {
			struct ubuf_info *uarg = msg_control;
			uarg->callback(uarg, false);
		}
	}

	if (err) {
		tun->dev->stats.rx_dropped++;
		kfree_skb(skb);
		return -EFAULT;
	}

	if (gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
		if (!skb_partial_csum_set(skb, gso.csum_start,
					  gso.csum_offset)) {
			tun->dev->stats.rx_frame_errors++;
			kfree_skb(skb);
			return -EINVAL;
		}
	}

	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		if (tun->flags & TUN_NO_PI) {
			switch (skb->data[0] & 0xf0) {
			case 0x40:
				pi.proto = htons(ETH_P_IP);
				break;
			case 0x60:
				pi.proto = htons(ETH_P_IPV6);
				break;
			default:
				tun->dev->stats.rx_dropped++;
				kfree_skb(skb);
				return -EINVAL;
			}
		}

		skb_reset_mac_header(skb);
		skb->protocol = pi.proto;
		skb->dev = tun->dev;
		break;
	case TUN_TAP_DEV:
		skb->protocol = eth_type_trans(skb, tun->dev);
		break;
	}

	if (gso.gso_type != VIRTIO_NET_HDR_GSO_NONE) {
		pr_debug("GSO!\n");
		switch (gso.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
			break;
		case VIRTIO_NET_HDR_GSO_TCPV6:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
			break;
		case VIRTIO_NET_HDR_GSO_UDP:
			skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
			break;
		default:
			tun->dev->stats.rx_frame_errors++;
			kfree_skb(skb);
			return -EINVAL;
		}

		if (gso.gso_type & VIRTIO_NET_HDR_GSO_ECN)
			skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;

		skb_shinfo(skb)->gso_size = gso.gso_size;
		if (skb_shinfo(skb)->gso_size == 0) {
			tun->dev->stats.rx_frame_errors++;
			kfree_skb(skb);
			return -EINVAL;
		}

		/* Header must be checked, and gso_segs computed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	/* copy skb_ubuf_info for callback when skb has no error */
	if (zerocopy) {
		skb_shinfo(skb)->destructor_arg = msg_control;
		skb_shinfo(skb)->tx_flags |= SKBTX_DEV_ZEROCOPY;
		skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;
	}

	skb_reset_network_header(skb);
	skb_probe_transport_header(skb, 0);

	rxhash = skb_get_rxhash(skb);
	netif_rx_ni(skb);

	tun->dev->stats.rx_packets++;
	tun->dev->stats.rx_bytes += len;

	tun_flow_update(tun, rxhash, tfile);
	return total_len;
}

static int inline tp_frame_len(struct tun_file *po, void *frame)
{
	int tp_len = 0;
	union tun_packet_uhdr ph;
	ph.raw = frame;

	switch (po->tp_version) {
	case TUN_PACKET_V1:
		tp_len = ph.h1->tp_len;
		break;
	default:
		break;
	}
	return tp_len;
}

static void tun_packet_destruct_skb(struct sk_buff *skb)
{
	struct tun_file *po =  (void *)skb->sk;

	if (likely(po->tx_ring.pg_vec)) {
		void *ph;
//		__u32 ts;

		ph = skb_shinfo(skb)->destructor_arg;
		packet_dec_pending(&po->tx_ring);
		printk("%s free ph=%p\n", __func__, ph);

//		ts = __packet_set_timestamp(po, ph, skb);
		__packet_set_status(po, ph, TP_STATUS_AVAILABLE);
		skb->head = NULL;
	}

//	sock_wfree(skb);
}

static int tun_mmap_snd(struct tun_struct *tun, struct tun_file *po, int need_wait)
{
	struct sk_buff *skb;
	struct skb_shared_info *shinfo;
	int err = -ENOMEM;
	union tun_packet_uhdr ph;
	int tp_len = 0;

	mutex_lock(&po->pg_vec_lock);

	do {
		ph.raw = packet_current_frame(po, &po->tx_ring,
					  TP_STATUS_SEND_REQUEST);
		if (unlikely(ph.raw == NULL)) {
			if (need_wait && need_resched())
				schedule();
			goto out;
		}

		if ((tun->flags & TUN_TYPE_MASK) == TUN_TAP_DEV)
			if (unlikely(tp_frame_len(po, ph.raw) < ETH_HLEN))
				goto out;

		skb = alloc_skb_head(GFP_KERNEL);
		if (skb == NULL)
			goto out;

		printk("############ph->raw=%p, skb_shared_info=%u\n", ph.raw, sizeof(struct skb_shared_info));
 		skb->head = ph.raw;
		skb->data = ph.raw + ph.h1->tp_mac;
		skb_reset_tail_pointer(skb);
		skb->end = skb->tail + po->tx_ring.frame_size  - sizeof(struct skb_shared_info) - ph.h1->tp_mac;
		skb_set_tail_pointer(skb, ph.h1->tp_len);
		skb_set_network_header(skb, 0);
		skb->len = ph.h1->tp_len;
		skb->truesize += skb->len;
		skb->sk = &po->sk;

		shinfo = skb_shinfo(skb);
		memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));
		atomic_set(&shinfo->dataref, 1);

		switch (tun->flags & TUN_TYPE_MASK) {
		case TUN_TUN_DEV:
			if (tun->flags & TUN_NO_PI) {
				switch (skb->data[0] & 0xf0) {
				case 0x40:
					skb->protocol = htons(ETH_P_IP);
					break;
				case 0x60:
					skb->protocol = htons(ETH_P_IPV6);
					break;
				default:
					tun->dev->stats.rx_dropped++;
					kfree_skb(skb);
					goto out;
				}
			}
			skb_reset_mac_header(skb);
			skb->dev = tun->dev;
			break;
		case TUN_TAP_DEV:
			skb->protocol = eth_type_trans(skb, tun->dev);
			break;
		}
		{
			struct iphdr *iph;
			iph = ip_hdr(skb);
			printk("saddr="NIPQUAD_FMT",daddr="NIPQUAD_FMT"\n", 
					NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
		}
 		shinfo->destructor_arg = ph.raw;
		skb->destructor = tun_packet_destruct_skb;
		__packet_set_status(po, ph.raw, TP_STATUS_SENDING);
		packet_inc_pending(&po->tx_ring);
		packet_increment_head(&po->tx_ring);
		printk("#### rx =%d\n", netif_rx_ni(skb));
		tp_len += ph.h1->tp_len;
	} while (likely((ph.raw != NULL) ||
		/* Note: packet_read_pending() might be slow if we have
		 * to call it as it's per_cpu variable, but in fast-path
		 * we already short-circuit the loop with the first
		 * condition, and luckily don't have to go that path
		 * anyway.
		 */
		 (need_wait && packet_read_pending(&po->tx_ring))));
	err = tp_len;
out:
	mutex_unlock(&po->pg_vec_lock);
	return err;
}

static ssize_t tun_chr_aio_write(struct kiocb *iocb, const struct iovec *iv,
			      unsigned long count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct tun_struct *tun = tun_get(file);
	struct tun_file *tfile = file->private_data;
	ssize_t result;

	if (!tun)
		return -EBADFD;

	tun_debug(KERN_INFO, tun, "tun_chr_write %ld\n", count);

	if (tfile->tx_ring.pg_vec)
		result = tun_mmap_snd(tun, tfile, !(file->f_flags & O_NONBLOCK));
	else
		result = tun_get_user(tun, tfile, NULL, iv, iov_length(iv, count),
			      count, file->f_flags & O_NONBLOCK);

	tun_put(tun);
	return result;
}

/* Put packet to the user space buffer */
static ssize_t tun_put_user(struct tun_struct *tun,
			    struct tun_file *tfile,
			    struct sk_buff *skb,
			    const struct iovec *iv, int len)
{
	struct tun_pi pi = { 0, skb->protocol };
	ssize_t total = 0;

	if (!(tun->flags & TUN_NO_PI)) {
		if ((len -= sizeof(pi)) < 0)
			return -EINVAL;

		if (len < skb->len) {
			/* Packet will be striped */
			pi.flags |= TUN_PKT_STRIP;
		}

		if (memcpy_toiovecend(iv, (void *) &pi, 0, sizeof(pi)))
			return -EFAULT;
		total += sizeof(pi);
	}

	if (tun->flags & TUN_VNET_HDR) {
		struct virtio_net_hdr gso = { 0 }; /* no info leak */
		if ((len -= tun->vnet_hdr_sz) < 0)
			return -EINVAL;

		if (skb_is_gso(skb)) {
			struct skb_shared_info *sinfo = skb_shinfo(skb);

			/* This is a hint as to how much should be linear. */
			gso.hdr_len = skb_headlen(skb);
			gso.gso_size = sinfo->gso_size;
			if (sinfo->gso_type & SKB_GSO_TCPV4)
				gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
			else if (sinfo->gso_type & SKB_GSO_TCPV6)
				gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
			else if (sinfo->gso_type & SKB_GSO_UDP)
				gso.gso_type = VIRTIO_NET_HDR_GSO_UDP;
			else {
				pr_err("unexpected GSO type: "
				       "0x%x, gso_size %d, hdr_len %d\n",
				       sinfo->gso_type, gso.gso_size,
				       gso.hdr_len);
				print_hex_dump(KERN_ERR, "tun: ",
					       DUMP_PREFIX_NONE,
					       16, 1, skb->head,
					       min((int)gso.hdr_len, 64), true);
				WARN_ON_ONCE(1);
				return -EINVAL;
			}
			if (sinfo->gso_type & SKB_GSO_TCP_ECN)
				gso.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
		} else
			gso.gso_type = VIRTIO_NET_HDR_GSO_NONE;

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			gso.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
			gso.csum_start = skb_checksum_start_offset(skb);
			gso.csum_offset = skb->csum_offset;
		} else if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
			gso.flags = VIRTIO_NET_HDR_F_DATA_VALID;
		} /* else everything is zero */

		if (unlikely(memcpy_toiovecend(iv, (void *)&gso, total,
					       sizeof(gso))))
			return -EFAULT;
		total += tun->vnet_hdr_sz;
	}

	len = min_t(int, skb->len, len);

	skb_copy_datagram_const_iovec(skb, 0, iv, total, len);
	total += skb->len;

	tun->dev->stats.tx_packets++;
	tun->dev->stats.tx_bytes += len;

	return total;
}

static ssize_t tun_do_read(struct tun_struct *tun, struct tun_file *tfile,
			   struct kiocb *iocb, const struct iovec *iv,
			   ssize_t len, int noblock)
{
	DECLARE_WAITQUEUE(wait, current);
	struct sk_buff *skb;
	ssize_t ret = 0;

	tun_debug(KERN_INFO, tun, "tun_do_read\n");

	if (unlikely(!noblock))
		add_wait_queue(&tfile->wq.wait, &wait);
	while (len) {
		current->state = TASK_INTERRUPTIBLE;

		/* Read frames from the queue */
		if (!(skb = skb_dequeue(&tfile->socket.sk->sk_receive_queue))) {
			if (noblock) {
				ret = -EAGAIN;
				break;
			}
			if (signal_pending(current)) {
				ret = -ERESTARTSYS;
				break;
			}
			if (tun->dev->reg_state != NETREG_REGISTERED) {
				ret = -EIO;
				break;
			}

			/* Nothing to read, let's sleep */
			schedule();
			continue;
		}

		ret = tun_put_user(tun, tfile, skb, iv, len);
		kfree_skb(skb);
		break;
	}

	current->state = TASK_RUNNING;
	if (unlikely(!noblock))
		remove_wait_queue(&tfile->wq.wait, &wait);

	return ret;
}

static ssize_t tun_chr_aio_read(struct kiocb *iocb, const struct iovec *iv,
			    unsigned long count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun = __tun_get(tfile);
	ssize_t len, ret;

	if (!tun)
		return -EBADFD;
	len = iov_length(iv, count);
	if (len < 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = tun_do_read(tun, tfile, iocb, iv, len,
			  file->f_flags & O_NONBLOCK);
	ret = min_t(ssize_t, ret, len);
	if (ret > 0)
		iocb->ki_pos = ret;
out:
	tun_put(tun);
	return ret;
}

static void tun_free_netdev(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	BUG_ON(!(list_empty(&tun->disabled)));
	tun_flow_uninit(tun);
	security_tun_dev_free_security(tun->security);
	free_netdev(dev);
}

static void tun_setup(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	tun->owner = INVALID_UID;
	tun->group = INVALID_GID;

	dev->ethtool_ops = &tun_ethtool_ops;
	dev->destructor = tun_free_netdev;
}

/* Trivial set of netlink ops to allow deleting tun or tap
 * device with netlink.
 */
static int tun_validate(struct nlattr *tb[], struct nlattr *data[])
{
	return -EINVAL;
}

static struct rtnl_link_ops tun_link_ops __read_mostly = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct tun_struct),
	.setup		= tun_setup,
	.validate	= tun_validate,
};

static void tun_sock_write_space(struct sock *sk)
{
	struct tun_file *tfile;
	wait_queue_head_t *wqueue;

	if (!sock_writeable(sk))
		return;

	if (!test_and_clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags))
		return;

	wqueue = sk_sleep(sk);
	if (wqueue && waitqueue_active(wqueue))
		wake_up_interruptible_sync_poll(wqueue, POLLOUT |
						POLLWRNORM | POLLWRBAND);

	tfile = container_of(sk, struct tun_file, sk);
	kill_fasync(&tfile->fasync, SIGIO, POLL_OUT);
}

static int tun_sendmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *m, size_t total_len)
{
	int ret;
	struct tun_file *tfile = container_of(sock, struct tun_file, socket);
	struct tun_struct *tun = __tun_get(tfile);

	if (!tun)
		return -EBADFD;
	ret = tun_get_user(tun, tfile, m->msg_control, m->msg_iov, total_len,
			   m->msg_iovlen, m->msg_flags & MSG_DONTWAIT);
	tun_put(tun);
	return ret;
}


static int tun_recvmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *m, size_t total_len,
		       int flags)
{
	struct tun_file *tfile = container_of(sock, struct tun_file, socket);
	struct tun_struct *tun = __tun_get(tfile);
	int ret;

	if (!tun)
		return -EBADFD;

	if (flags & ~(MSG_DONTWAIT|MSG_TRUNC)) {
		ret = -EINVAL;
		goto out;
	}
	ret = tun_do_read(tun, tfile, iocb, m->msg_iov, total_len,
			  flags & MSG_DONTWAIT);
	if (ret > total_len) {
		m->msg_flags |= MSG_TRUNC;
		ret = flags & MSG_TRUNC ? ret : total_len;
	}
out:
	tun_put(tun);
	return ret;
}

static int tun_release(struct socket *sock)
{
	if (sock->sk)
		sock_put(sock->sk);
	return 0;
}

/* Ops structure to mimic raw sockets with tun */
static const struct proto_ops tun_socket_ops = {
	.sendmsg = tun_sendmsg,
	.recvmsg = tun_recvmsg,
	.release = tun_release,
};

static struct proto tun_proto = {
	.name		= "tun",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tun_file),
};

static int tun_flags(struct tun_struct *tun)
{
	int flags = 0;

	if (tun->flags & TUN_TUN_DEV)
		flags |= IFF_TUN;
	else
		flags |= IFF_TAP;

	if (tun->flags & TUN_NO_PI)
		flags |= IFF_NO_PI;

	/* This flag has no real effect.  We track the value for backwards
	 * compatibility.
	 */
	if (tun->flags & TUN_ONE_QUEUE)
		flags |= IFF_ONE_QUEUE;

	if (tun->flags & TUN_VNET_HDR)
		flags |= IFF_VNET_HDR;

	if (tun->flags & TUN_TAP_MQ)
		flags |= IFF_MULTI_QUEUE;

	return flags;
}

static ssize_t tun_show_flags(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct tun_struct *tun = netdev_priv(to_net_dev(dev));
	return sprintf(buf, "0x%x\n", tun_flags(tun));
}

static ssize_t tun_show_owner(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct tun_struct *tun = netdev_priv(to_net_dev(dev));
	return uid_valid(tun->owner)?
		sprintf(buf, "%u\n",
			from_kuid_munged(current_user_ns(), tun->owner)):
		sprintf(buf, "-1\n");
}

static ssize_t tun_show_group(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct tun_struct *tun = netdev_priv(to_net_dev(dev));
	return gid_valid(tun->group) ?
		sprintf(buf, "%u\n",
			from_kgid_munged(current_user_ns(), tun->group)):
		sprintf(buf, "-1\n");
}

static DEVICE_ATTR(tun_flags, 0444, tun_show_flags, NULL);
static DEVICE_ATTR(owner, 0444, tun_show_owner, NULL);
static DEVICE_ATTR(group, 0444, tun_show_group, NULL);

static int tun_set_iff(struct net *net, struct file *file, struct ifreq *ifr)
{
	struct tun_struct *tun;
	struct tun_file *tfile = file->private_data;
	struct net_device *dev;
	int err;

	if (tfile->detached)
		return -EINVAL;

	dev = __dev_get_by_name(net, ifr->ifr_name);
	if (dev) {
		if (ifr->ifr_flags & IFF_TUN_EXCL)
			return -EBUSY;
		if ((ifr->ifr_flags & IFF_TUN) && dev->netdev_ops == &tun_netdev_ops)
			tun = netdev_priv(dev);
		else if ((ifr->ifr_flags & IFF_TAP) && dev->netdev_ops == &tap_netdev_ops)
			tun = netdev_priv(dev);
		else
			return -EINVAL;

		if (!!(ifr->ifr_flags & IFF_MULTI_QUEUE) !=
		    !!(tun->flags & TUN_TAP_MQ))
			return -EINVAL;

		if (tun_not_capable(tun))
			return -EPERM;
		err = security_tun_dev_open(tun->security);
		if (err < 0)
			return err;

		err = tun_attach(tun, file);
		if (err < 0)
			return err;

		if (tun->flags & TUN_TAP_MQ &&
		    (tun->numqueues + tun->numdisabled > 1)) {
			/* One or more queue has already been attached, no need
			 * to initialize the device again.
			 */
			return 0;
		}
	}
	else {
		char *name;
		unsigned long flags = 0;
		int queues = ifr->ifr_flags & IFF_MULTI_QUEUE ?
			     MAX_TAP_QUEUES : 1;

		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			return -EPERM;
		err = security_tun_dev_create();
		if (err < 0)
			return err;

		/* Set dev type */
		if (ifr->ifr_flags & IFF_TUN) {
			/* TUN device */
			flags |= TUN_TUN_DEV;
			name = "tun%d";
		} else if (ifr->ifr_flags & IFF_TAP) {
			/* TAP device */
			flags |= TUN_TAP_DEV;
			name = "tap%d";
		} else
			return -EINVAL;

		if (*ifr->ifr_name)
			name = ifr->ifr_name;

		dev = alloc_netdev_mqs(sizeof(struct tun_struct), name,
				       tun_setup, queues, queues);

		if (!dev)
			return -ENOMEM;

		dev_net_set(dev, net);
		dev->rtnl_link_ops = &tun_link_ops;

		tun = netdev_priv(dev);
		tun->dev = dev;
		tun->flags = flags;
		tun->txflt.count = 0;
		tun->vnet_hdr_sz = sizeof(struct virtio_net_hdr);

		tun->filter_attached = false;
		tun->sndbuf = tfile->socket.sk->sk_sndbuf;

		spin_lock_init(&tun->lock);

		err = security_tun_dev_alloc_security(&tun->security);
		if (err < 0)
			goto err_free_dev;

		tun_net_init(dev);

		err = tun_flow_init(tun);
		if (err < 0)
			goto err_free_dev;

		dev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST |
			TUN_USER_FEATURES;
		dev->features = dev->hw_features;
		dev->vlan_features = dev->features;

		INIT_LIST_HEAD(&tun->disabled);
		err = tun_attach(tun, file);
		if (err < 0)
			goto err_free_flow;

		err = register_netdevice(tun->dev);
		if (err < 0)
			goto err_detach;

		if (device_create_file(&tun->dev->dev, &dev_attr_tun_flags) ||
		    device_create_file(&tun->dev->dev, &dev_attr_owner) ||
		    device_create_file(&tun->dev->dev, &dev_attr_group))
			pr_err("Failed to create tun sysfs files\n");
	}

	netif_carrier_on(tun->dev);

	tun_debug(KERN_INFO, tun, "tun_set_iff\n");

	if (ifr->ifr_flags & IFF_NO_PI)
		tun->flags |= TUN_NO_PI;
	else
		tun->flags &= ~TUN_NO_PI;

	/* This flag has no real effect.  We track the value for backwards
	 * compatibility.
	 */
	if (ifr->ifr_flags & IFF_ONE_QUEUE)
		tun->flags |= TUN_ONE_QUEUE;
	else
		tun->flags &= ~TUN_ONE_QUEUE;

	if (ifr->ifr_flags & IFF_VNET_HDR)
		tun->flags |= TUN_VNET_HDR;
	else
		tun->flags &= ~TUN_VNET_HDR;

	if (ifr->ifr_flags & IFF_MULTI_QUEUE)
		tun->flags |= TUN_TAP_MQ;
	else
		tun->flags &= ~TUN_TAP_MQ;

	/* Make sure persistent devices do not get stuck in
	 * xoff state.
	 */
	if (netif_running(tun->dev))
		netif_tx_wake_all_queues(tun->dev);

	strcpy(ifr->ifr_name, tun->dev->name);
	return 0;

err_detach:
	tun_detach_all(dev);
err_free_flow:
	tun_flow_uninit(tun);
	security_tun_dev_free_security(tun->security);
err_free_dev:
	free_netdev(dev);
	return err;
}

static void tun_get_iff(struct net *net, struct tun_struct *tun,
		       struct ifreq *ifr)
{
	tun_debug(KERN_INFO, tun, "tun_get_iff\n");

	strcpy(ifr->ifr_name, tun->dev->name);

	ifr->ifr_flags = tun_flags(tun);

}

/* This is like a cut-down ethtool ops, except done via tun fd so no
 * privs required. */
static int set_offload(struct tun_struct *tun, unsigned long arg)
{
	netdev_features_t features = 0;

	if (arg & TUN_F_CSUM) {
		features |= NETIF_F_HW_CSUM;
		arg &= ~TUN_F_CSUM;

		if (arg & (TUN_F_TSO4|TUN_F_TSO6)) {
			if (arg & TUN_F_TSO_ECN) {
				features |= NETIF_F_TSO_ECN;
				arg &= ~TUN_F_TSO_ECN;
			}
			if (arg & TUN_F_TSO4)
				features |= NETIF_F_TSO;
			if (arg & TUN_F_TSO6)
				features |= NETIF_F_TSO6;
			arg &= ~(TUN_F_TSO4|TUN_F_TSO6);
		}

		if (arg & TUN_F_UFO) {
			features |= NETIF_F_UFO;
			arg &= ~TUN_F_UFO;
		}
	}

	/* This gives the user a way to test for new features in future by
	 * trying to set them. */
	if (arg)
		return -EINVAL;

	tun->set_features = features;
	netdev_update_features(tun->dev);

	return 0;
}

static void tun_detach_filter(struct tun_struct *tun, int n)
{
	int i;
	struct tun_file *tfile;

	for (i = 0; i < n; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		sk_detach_filter(tfile->socket.sk);
	}

	tun->filter_attached = false;
}

static int tun_attach_filter(struct tun_struct *tun)
{
	int i, ret = 0;
	struct tun_file *tfile;

	for (i = 0; i < tun->numqueues; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		ret = sk_attach_filter(&tun->fprog, tfile->socket.sk);
		if (ret) {
			tun_detach_filter(tun, i);
			return ret;
		}
	}

	tun->filter_attached = true;
	return ret;
}

static void tun_set_sndbuf(struct tun_struct *tun)
{
	struct tun_file *tfile;
	int i;

	for (i = 0; i < tun->numqueues; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		tfile->socket.sk->sk_sndbuf = tun->sndbuf;
	}
}

static int tun_set_queue(struct file *file, struct ifreq *ifr)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun;
	int ret = 0;

	rtnl_lock();

	if (ifr->ifr_flags & IFF_ATTACH_QUEUE) {
		tun = tfile->detached;
		if (!tun) {
			ret = -EINVAL;
			goto unlock;
		}
		ret = security_tun_dev_attach_queue(tun->security);
		if (ret < 0)
			goto unlock;
		ret = tun_attach(tun, file);
	} else if (ifr->ifr_flags & IFF_DETACH_QUEUE) {
		tun = rtnl_dereference(tfile->tun);
		if (!tun || !(tun->flags & TUN_TAP_MQ) || tfile->detached)
			ret = -EINVAL;
		else
			__tun_detach(tfile, false);
	} else
		ret = -EINVAL;

unlock:
	rtnl_unlock();
	return ret;
}

static long __tun_chr_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg, int ifreq_len)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun;
	void __user* argp = (void __user*)arg;
	struct ifreq ifr;
	kuid_t owner;
	kgid_t group;
	int sndbuf;
	int vnet_hdr_sz;
	int ret;

	if (cmd == TUNSETIFF || cmd == TUNSETQUEUE || _IOC_TYPE(cmd) == 0x89) {
		if (copy_from_user(&ifr, argp, ifreq_len))
			return -EFAULT;
	} else {
		memset(&ifr, 0, sizeof(ifr));
	}
	if (cmd == TUNGETFEATURES) {
		/* Currently this just means: "what IFF flags are valid?".
		 * This is needed because we never checked for invalid flags on
		 * TUNSETIFF. */
		return put_user(IFF_TUN | IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE |
				IFF_VNET_HDR | IFF_MULTI_QUEUE,
				(unsigned int __user*)argp);
	} else if (cmd == TUNSETQUEUE)
		return tun_set_queue(file, &ifr);

	ret = 0;
	rtnl_lock();

	tun = __tun_get(tfile);
	if (cmd == TUNSETIFF && !tun) {
		ifr.ifr_name[IFNAMSIZ-1] = '\0';

		ret = tun_set_iff(tfile->net, file, &ifr);

		if (ret)
			goto unlock;

		if (copy_to_user(argp, &ifr, ifreq_len))
			ret = -EFAULT;
		goto unlock;
	}

	ret = -EBADFD;
	if (!tun)
		goto unlock;

	tun_debug(KERN_INFO, tun, "tun_chr_ioctl cmd %u\n", cmd);

	ret = 0;
	switch (cmd) {
	case TUNGETIFF:
		tun_get_iff(current->nsproxy->net_ns, tun, &ifr);

		if (copy_to_user(argp, &ifr, ifreq_len))
			ret = -EFAULT;
		break;

	case TUNSETNOCSUM:
		/* Disable/Enable checksum */

		/* [unimplemented] */
		tun_debug(KERN_INFO, tun, "ignored: set checksum %s\n",
			  arg ? "disabled" : "enabled");
		break;

	case TUNSETPERSIST:
		/* Disable/Enable persist mode. Keep an extra reference to the
		 * module to prevent the module being unprobed.
		 */
		if (arg && !(tun->flags & TUN_PERSIST)) {
			tun->flags |= TUN_PERSIST;
			__module_get(THIS_MODULE);
		}
		if (!arg && (tun->flags & TUN_PERSIST)) {
			tun->flags &= ~TUN_PERSIST;
			module_put(THIS_MODULE);
		}

		tun_debug(KERN_INFO, tun, "persist %s\n",
			  arg ? "enabled" : "disabled");
		break;

	case TUNSETOWNER:
		/* Set owner of the device */
		owner = make_kuid(current_user_ns(), arg);
		if (!uid_valid(owner)) {
			ret = -EINVAL;
			break;
		}
		tun->owner = owner;
		tun_debug(KERN_INFO, tun, "owner set to %u\n",
			  from_kuid(&init_user_ns, tun->owner));
		break;

	case TUNSETGROUP:
		/* Set group of the device */
		group = make_kgid(current_user_ns(), arg);
		if (!gid_valid(group)) {
			ret = -EINVAL;
			break;
		}
		tun->group = group;
		tun_debug(KERN_INFO, tun, "group set to %u\n",
			  from_kgid(&init_user_ns, tun->group));
		break;

	case TUNSETLINK:
		/* Only allow setting the type when the interface is down */
		if (tun->dev->flags & IFF_UP) {
			tun_debug(KERN_INFO, tun,
				  "Linktype set failed because interface is up\n");
			ret = -EBUSY;
		} else {
			tun->dev->type = (int) arg;
			tun_debug(KERN_INFO, tun, "linktype set to %d\n",
				  tun->dev->type);
			ret = 0;
		}
		break;

#ifdef TUN_DEBUG
	case TUNSETDEBUG:
		tun->debug = arg;
		break;
#endif
	case TUNSETOFFLOAD:
		ret = set_offload(tun, arg);
		break;

	case TUNSETTXFILTER:
		/* Can be set only for TAPs */
		ret = -EINVAL;
		if ((tun->flags & TUN_TYPE_MASK) != TUN_TAP_DEV)
			break;
		ret = update_filter(&tun->txflt, (void __user *)arg);
		break;

	case SIOCGIFHWADDR:
		/* Get hw address */
		memcpy(ifr.ifr_hwaddr.sa_data, tun->dev->dev_addr, ETH_ALEN);
		ifr.ifr_hwaddr.sa_family = tun->dev->type;
		if (copy_to_user(argp, &ifr, ifreq_len))
			ret = -EFAULT;
		break;

	case SIOCSIFHWADDR:
		/* Set hw address */
		tun_debug(KERN_DEBUG, tun, "set hw address: %pM\n",
			  ifr.ifr_hwaddr.sa_data);

		ret = dev_set_mac_address(tun->dev, &ifr.ifr_hwaddr);
		break;

	case TUNGETSNDBUF:
		sndbuf = tfile->socket.sk->sk_sndbuf;
		if (copy_to_user(argp, &sndbuf, sizeof(sndbuf)))
			ret = -EFAULT;
		break;

	case TUNSETSNDBUF:
		if (copy_from_user(&sndbuf, argp, sizeof(sndbuf))) {
			ret = -EFAULT;
			break;
		}

		tun->sndbuf = sndbuf;
		tun_set_sndbuf(tun);
		break;

	case TUNGETVNETHDRSZ:
		vnet_hdr_sz = tun->vnet_hdr_sz;
		if (copy_to_user(argp, &vnet_hdr_sz, sizeof(vnet_hdr_sz)))
			ret = -EFAULT;
		break;

	case TUNSETVNETHDRSZ:
		if (copy_from_user(&vnet_hdr_sz, argp, sizeof(vnet_hdr_sz))) {
			ret = -EFAULT;
			break;
		}
		if (vnet_hdr_sz < (int)sizeof(struct virtio_net_hdr)) {
			ret = -EINVAL;
			break;
		}

		tun->vnet_hdr_sz = vnet_hdr_sz;
		break;

	case TUNATTACHFILTER:
		/* Can be set only for TAPs */
		ret = -EINVAL;
		if ((tun->flags & TUN_TYPE_MASK) != TUN_TAP_DEV)
			break;
		ret = -EFAULT;
		if (copy_from_user(&tun->fprog, argp, sizeof(tun->fprog)))
			break;

		ret = tun_attach_filter(tun);
		break;

	case TUNDETACHFILTER:
		/* Can be set only for TAPs */
		ret = -EINVAL;
		if ((tun->flags & TUN_TYPE_MASK) != TUN_TAP_DEV)
			break;
		ret = 0;
		tun_detach_filter(tun, tun->numqueues);
		break;
	
	default:
		ret = tun_mmap_ioctl(file, cmd, arg);
		break;
	}

unlock:
	rtnl_unlock();
	if (tun)
		tun_put(tun);
	return ret;
}

static long tun_chr_ioctl(struct file *file,
			  unsigned int cmd, unsigned long arg)
{
	return __tun_chr_ioctl(file, cmd, arg, sizeof (struct ifreq));
}

#ifdef CONFIG_COMPAT
static long tun_chr_compat_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case TUNSETIFF:
	case TUNGETIFF:
	case TUNSETTXFILTER:
	case TUNGETSNDBUF:
	case TUNSETSNDBUF:
	case SIOCGIFHWADDR:
	case SIOCSIFHWADDR:
		arg = (unsigned long)compat_ptr(arg);
		break;
	default:
		arg = (compat_ulong_t)arg;
		break;
	}

	/*
	 * compat_ifreq is shorter than ifreq, so we must not access beyond
	 * the end of that structure. All fields that are used in this
	 * driver are compatible though, we don't need to convert the
	 * contents.
	 */
	return __tun_chr_ioctl(file, cmd, arg, sizeof(struct compat_ifreq));
}
#endif /* CONFIG_COMPAT */

static int tun_chr_fasync(int fd, struct file *file, int on)
{
	struct tun_file *tfile = file->private_data;
	int ret;

	if ((ret = fasync_helper(fd, file, on, &tfile->fasync)) < 0)
		goto out;

	if (on) {
		ret = __f_setown(file, task_pid(current), PIDTYPE_PID, 0);
		if (ret)
			goto out;
		tfile->flags |= TUN_FASYNC;
	} else
		tfile->flags &= ~TUN_FASYNC;
	ret = 0;
out:
	return ret;
}

static int tun_chr_open(struct inode *inode, struct file * file)
{
	struct tun_file *tfile;

	DBG1(KERN_INFO, "tunX: tun_chr_open\n");
	printk("%d\n", __LINE__);
	tfile = (struct tun_file *)sk_alloc(&init_net, AF_UNSPEC, GFP_KERNEL,
					    &tun_proto);
	if (!tfile)
		return -ENOMEM;
	
	if (packet_alloc_pending(tfile) < 0) {
		printk("packet_alloc_pending error\n");
		return -ENOMEM;
	}
	rcu_assign_pointer(tfile->tun, NULL);
	tfile->net = get_net(current->nsproxy->net_ns);
	tfile->flags = 0;

	rcu_assign_pointer(tfile->socket.wq, &tfile->wq);
	init_waitqueue_head(&tfile->wq.wait);

	tfile->socket.file = file;
	tfile->socket.ops = &tun_socket_ops;

	sock_init_data(&tfile->socket, &tfile->sk);
	sk_change_net(&tfile->sk, tfile->net);

	tfile->sk.sk_write_space = tun_sock_write_space;
	tfile->sk.sk_sndbuf = INT_MAX;

	file->private_data = tfile;
	set_bit(SOCK_EXTERNALLY_ALLOCATED, &tfile->socket.flags);
	INIT_LIST_HEAD(&tfile->next);

	sock_set_flag(&tfile->sk, SOCK_ZEROCOPY);
	mutex_init(&tfile->pg_vec_lock);

	return 0;
}

static int tun_chr_close(struct inode *inode, struct file *file)
{
	struct tun_file *tfile = file->private_data;
	struct net *net = tfile->net;
	union tun_packet_req_u req_u;

	if (tfile->rx_ring.pg_vec) {
		memset(&req_u, 0, sizeof(req_u));
		packet_set_ring(tfile, &tfile->sk, &req_u, 1, 0);
	}

	if (tfile->tx_ring.pg_vec) {
		memset(&req_u, 0, sizeof(req_u));
		packet_set_ring(tfile, &tfile->sk, &req_u, 1, 1);
	}

	packet_free_pending(tfile);
	tun_detach(tfile, true);
	put_net(net);

	return 0;
}

static int packet_mmap(struct file *file,
		struct vm_area_struct *vma);


static const struct file_operations tun_fops = {
	.owner	= THIS_MODULE,
	.llseek = no_llseek,
	.read  = do_sync_read,
	.aio_read  = tun_chr_aio_read,
	.write = do_sync_write,
	.aio_write = tun_chr_aio_write,
	.poll	= tun_chr_poll,
	.unlocked_ioctl	= tun_chr_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tun_chr_compat_ioctl,
#endif
	.mmap = packet_mmap,
	.open	= tun_chr_open,
	.release = tun_chr_close,
	.fasync = tun_chr_fasync
};

static struct tun_struct *__tun_get(struct tun_file *file);
static void tun_put(struct tun_struct *tun);

static inline __pure struct page *pgv_to_page(void *addr)
{
	if (is_vmalloc_addr(addr))
		return vmalloc_to_page(addr);
	return virt_to_page(addr);
}

static void free_pg_vec(struct pgv *pg_vec, unsigned int order,
			unsigned int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (likely(pg_vec[i].buffer)) {
			if (is_vmalloc_addr(pg_vec[i].buffer))
				vfree(pg_vec[i].buffer);
			else
				free_pages((unsigned long)pg_vec[i].buffer,
					   order);
			pg_vec[i].buffer = NULL;
		}
	}
	kfree(pg_vec);
}

static char *alloc_one_pg_vec_page(unsigned long order)
{
	char *buffer = NULL;
	gfp_t gfp_flags = GFP_KERNEL | __GFP_COMP |
			  __GFP_ZERO | __GFP_NOWARN | __GFP_NORETRY;

	buffer = (char *) __get_free_pages(gfp_flags, order);

	if (buffer)
		return buffer;

	/*
	 * __get_free_pages failed, fall back to vmalloc
	 */
	buffer = vzalloc((1 << order) * PAGE_SIZE);

	if (buffer)
		return buffer;

	/*
	 * vmalloc failed, lets dig into swap here
	 */
	gfp_flags &= ~__GFP_NORETRY;
	buffer = (char *)__get_free_pages(gfp_flags, order);
	if (buffer)
		return buffer;

	/*
	 * complete and utter failure
	 */
	return NULL;
}

static struct pgv *alloc_pg_vec(struct tun_packet_req *req, int order)
{
	unsigned int block_nr = req->tp_block_nr;
	struct pgv *pg_vec;
	int i;

	pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL);
	if (unlikely(!pg_vec))
		goto out;

	for (i = 0; i < block_nr; i++) {
		pg_vec[i].buffer = alloc_one_pg_vec_page(order);
		if (unlikely(!pg_vec[i].buffer))
			goto out_free_pgvec;
		printk("pg_vec[%d]=%p\n", i, pg_vec[i].buffer);
	}

out:
	return pg_vec;

out_free_pgvec:
	free_pg_vec(pg_vec, order, block_nr);
	pg_vec = NULL;
	goto out;
}

static int packet_set_ring(struct tun_file *tfile, struct sock *sk, union tun_packet_req_u *req_u,
		int closing, int tx_ring)
{
	struct pgv *pg_vec = NULL;
	int order = 0;
	struct tun_ring_buffer *rb;
	struct sk_buff_head *rb_queue;
	int err = -EINVAL;
	/* Added to avoid minimal code churn */
	struct tun_packet_req *req = &req_u->req;

	/* Opening a Tx-ring is NOT supported in TPACKET_V3 */
	if (!closing && tx_ring && (tfile->tp_version > TPACKET_V2)) {
		WARN(1, "Tx-ring is not supported.\n");
		goto out;
	}

	rb = tx_ring ? &tfile->tx_ring : &tfile->rx_ring;
	rb_queue = tx_ring ? &sk->sk_write_queue : &sk->sk_receive_queue;

	err = -EBUSY;
	if (!closing) {
		if (atomic_read(&tfile->mapped))
			goto out;
		if (packet_read_pending(rb))
			goto out;
	}

	if (req->tp_block_nr) {
		/* Sanity tests and some calculations */
		err = -EBUSY;
		if (unlikely(rb->pg_vec))
			goto out;

		switch (tfile->tp_version) {
		case TUN_PACKET_V1:
			tfile->tp_hdrlen = TPACKET_HDRLEN;
			break;
		default:
			goto out;	
		}

		err = -EINVAL;
		if (unlikely((int)req->tp_block_size <= 0))
			goto out;
		if (unlikely(req->tp_block_size & (PAGE_SIZE - 1)))
			goto out;
		if (unlikely(req->tp_frame_size < tfile->tp_hdrlen +
					tfile->tp_reserve))
			goto out;
		if (unlikely(req->tp_frame_size & (TPACKET_ALIGNMENT - 1)))
			goto out;

		rb->frames_per_block = req->tp_block_size/req->tp_frame_size;
		if (unlikely(rb->frames_per_block <= 0))
			goto out;
		if (unlikely((rb->frames_per_block * req->tp_block_nr) !=
					req->tp_frame_nr))
			goto out;

		err = -ENOMEM;
		order = get_order(req->tp_block_size);
		pg_vec = alloc_pg_vec(req, order);
		if (unlikely(!pg_vec))
			goto out;
	} else {
		err = -EINVAL;
		if (unlikely(req->tp_frame_nr))
			goto out;
	}

	lock_sock(sk);

	/* Detach socket from network */
//	spin_lock(&po->bind_lock);
//	was_running = po->running;
//	num = po->num;
//	if (was_running) {
//		po->num = 0;
//		__unregister_prot_hook(sk, false);
//	}
//	spin_unlock(&po->bind_lock);

	synchronize_net();

	err = -EBUSY;
	mutex_lock(&tfile->pg_vec_lock);
	if (closing || atomic_read(&tfile->mapped) == 0) {
		err = 0;
		spin_lock_bh(&rb_queue->lock);
		swap(rb->pg_vec, pg_vec);
		rb->frame_max = (req->tp_frame_nr - 1);
		rb->head = 0;
		rb->frame_size = req->tp_frame_size;
		spin_unlock_bh(&rb_queue->lock);

		swap(rb->pg_vec_order, order);
		swap(rb->pg_vec_len, req->tp_block_nr);

		rb->pg_vec_pages = req->tp_block_size/PAGE_SIZE;
		skb_queue_purge(rb_queue);
		if (atomic_read(&tfile->mapped))
			pr_err("packet_mmap: vma is busy: %d\n",
			       atomic_read(&tfile->mapped));
	}
	mutex_unlock(&tfile->pg_vec_lock);


	printk("%d, err=%d\n", __LINE__, err);

//	spin_lock(&po->bind_lock);
//	if (was_running) {
//		po->num = num;
//		register_prot_hook(sk);
//	}
//	spin_unlock(&po->bind_lock);
	release_sock(sk);

	if (pg_vec)
		free_pg_vec(pg_vec, order, req->tp_block_nr);
out:
	return err;
}

static void packet_mm_open(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct tun_file *tfile = file->private_data;
	printk("%s\n", __func__);
	if (tfile)
		atomic_inc(&tfile->mapped);
}

static void packet_mm_close(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct tun_file *tfile = file->private_data;

	printk("%s\n", __func__);
	if (tfile)
		atomic_dec(&tfile->mapped);
}

static const struct vm_operations_struct tun_packet_mmap_ops = {
	.open	=	packet_mm_open,
	.close	=	packet_mm_close,
};

static int packet_mmap(struct file *file,
		struct vm_area_struct *vma)
{
	struct tun_file *tfile = file->private_data;
	unsigned long size, expected_size;
	struct tun_ring_buffer *rb;
	unsigned long start;
	int err = -EINVAL;
	int i;

	if (vma->vm_pgoff)
		return -EINVAL;

	mutex_lock(&tfile->pg_vec_lock);

	expected_size = 0;
	for (rb = &tfile->rx_ring; rb <= &tfile->tx_ring; rb++) {
		if (rb->pg_vec) {
			expected_size += rb->pg_vec_len
						* rb->pg_vec_pages
						* PAGE_SIZE;
		}
	}

	if (expected_size == 0)
		goto out;
	printk("vm_end=%08lx, vm_start=%08lx\n", vma->vm_end,  vma->vm_start);
	size = vma->vm_end - vma->vm_start;
	if (size != expected_size)
		goto out;

	start = vma->vm_start;
	for (rb = &tfile->rx_ring; rb <= &tfile->tx_ring; rb++) {
		if (rb->pg_vec == NULL)
			continue;

		for (i = 0; i < rb->pg_vec_len; i++) {
			struct page *page;
			void *kaddr = rb->pg_vec[i].buffer;
			int pg_num;
			printk("mmap start=%08lx, kaddr=%p\n", start, kaddr);
			for (pg_num = 0; pg_num < rb->pg_vec_pages; pg_num++) {
//				printk("mmap start=%08x, kaddr=%08x\n", start, kaddr);
				page = pgv_to_page(kaddr);
				err = vm_insert_page(vma, start, page);
				if (unlikely(err))
					goto out;
				start += PAGE_SIZE;
				kaddr += PAGE_SIZE;
			}
		}
	}

	atomic_inc(&tfile->mapped);
	vma->vm_ops = &tun_packet_mmap_ops;
	err = 0;

out:
	mutex_unlock(&tfile->pg_vec_lock);
	return err;
}

static long tun_mmap_ioctl(struct file *file,
			  unsigned int cmd, unsigned long arg)
{
	int ret;
	void __user *argp = (void __user*)arg;
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun;
	tun = __tun_get(tfile);
	if (!tun)
		return -EINVAL;

	switch (cmd) {
	case TUN_PACKET_RX_RING:
	case TUN_PACKET_TX_RING:
	{
		union tun_packet_req_u req_u;
		int len;

		switch (tfile->tp_version) {
		case TUN_PACKET_V1:
			len = sizeof(req_u.req);
			break;
		default:
			ret =  -EINVAL;
			goto out;
		}
		if (copy_from_user(&req_u.req, argp, len))
			return -EFAULT;
		ret = packet_set_ring(tfile, &tfile->sk, &req_u, 0,
			cmd == TUN_PACKET_TX_RING);
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}
out:
	tun_put(tun);
	return ret;
}

static struct miscdevice tun_miscdev = {
	.minor = 240,
	.name = "tun_mmap",
	.nodename = "net/tun_mmap",
	.fops = &tun_fops,
};

/* ethtool interface */

static int tun_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported		= 0;
	cmd->advertising	= 0;
	ethtool_cmd_speed_set(cmd, SPEED_10);
	cmd->duplex		= DUPLEX_FULL;
	cmd->port		= PORT_TP;
	cmd->phy_address	= 0;
	cmd->transceiver	= XCVR_INTERNAL;
	cmd->autoneg		= AUTONEG_DISABLE;
	cmd->maxtxpkt		= 0;
	cmd->maxrxpkt		= 0;
	return 0;
}

static void tun_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct tun_struct *tun = netdev_priv(dev);

	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));

	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		strlcpy(info->bus_info, "tun", sizeof(info->bus_info));
		break;
	case TUN_TAP_DEV:
		strlcpy(info->bus_info, "tap", sizeof(info->bus_info));
		break;
	}
}

static u32 tun_get_msglevel(struct net_device *dev)
{
#ifdef TUN_DEBUG
	struct tun_struct *tun = netdev_priv(dev);
	return tun->debug;
#else
	return -EOPNOTSUPP;
#endif
}

static void tun_set_msglevel(struct net_device *dev, u32 value)
{
#ifdef TUN_DEBUG
	struct tun_struct *tun = netdev_priv(dev);
	tun->debug = value;
#endif
}

static const struct ethtool_ops tun_ethtool_ops = {
	.get_settings	= tun_get_settings,
	.get_drvinfo	= tun_get_drvinfo,
	.get_msglevel	= tun_get_msglevel,
	.set_msglevel	= tun_set_msglevel,
	.get_link	= ethtool_op_get_link,
};


static int __init tun_init(void)
{
	int ret = 0;

	pr_info("%s, %s\n", DRV_DESCRIPTION, DRV_VERSION);
	pr_info("%s\n", DRV_COPYRIGHT);

	ret = rtnl_link_register(&tun_link_ops);
	if (ret) {
		pr_err("Can't register link_ops\n");
		goto err_linkops;
	}

	ret = misc_register(&tun_miscdev);
	if (ret) {
		pr_err("Can't register misc device %d\n", TUN_MINOR);
		goto err_misc;
	}
	return  0;
err_misc:
	rtnl_link_unregister(&tun_link_ops);
err_linkops:
	return ret;
}

static void tun_cleanup(void)
{
	misc_deregister(&tun_miscdev);
	rtnl_link_unregister(&tun_link_ops);
}

/* Get an underlying socket object from tun file.  Returns error unless file is
 * attached to a device.  The returned object works like a packet socket, it
 * can be used for sock_sendmsg/sock_recvmsg.  The caller is responsible for
 * holding a reference to the file for as long as the socket is in use. */
struct socket *tun_get_socket2(struct file *file)
{
	struct tun_file *tfile;
	if (file->f_op != &tun_fops)
		return ERR_PTR(-EINVAL);
	tfile = file->private_data;
	if (!tfile)
		return ERR_PTR(-EBADFD);
	return &tfile->socket;
}
EXPORT_SYMBOL_GPL(tun_get_socket2);

module_init(tun_init);
module_exit(tun_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(TUN_MINOR);
MODULE_ALIAS("devname:net/tun");
