#ifndef _AF_NETLINK_H
#define _AF_NETLINK_H

#include <linux/rhashtable.h>
#include <linux/atomic.h>
#include <net/sock.h>

#define NLGRPSZ(x)	(ALIGN(x, sizeof(unsigned long) * 8) / 8)
#define NLGRPLONGS(x)	(NLGRPSZ(x)/sizeof(unsigned long))

struct netlink_ring {
	void			**pg_vec;
	//缓存区的索引值
	unsigned int		head;
	unsigned int		frames_per_block;
	unsigned int		frame_size;
	//缓存区的最大索引值
	unsigned int		frame_max;
	//每个块需要多少个PAGE_SIZE ，从0开始
	//意义同__get_free_pages中order的参数
	unsigned int		pg_vec_order;
	//每个块需要多少个PAGE_SIZE ，从1开始
	unsigned int		pg_vec_pages;
	//块的总数量
	unsigned int		pg_vec_len;

	atomic_t		pending;
};

struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
	u32			portid;
	u32			dst_portid;
	u32			dst_group;
	u32			flags;
	u32			subscriptions;
	u32			ngroups;
	unsigned long		*groups;
	unsigned long		state;
	size_t			max_recvmsg_len;
	wait_queue_head_t	wait;
	bool			cb_running;
	struct netlink_callback	cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
	void			(*netlink_rcv)(struct sk_buff *skb);
	int			(*netlink_bind)(struct net *net, int group);
	void			(*netlink_unbind)(struct net *net, int group);
	struct module		*module;
#ifdef CONFIG_NETLINK_MMAP
	struct mutex		pg_vec_lock;
	struct netlink_ring	rx_ring;
	struct netlink_ring	tx_ring;
	atomic_t		mapped;
#endif /* CONFIG_NETLINK_MMAP */

	struct rhash_head	node;
	struct rcu_head		rcu;
};

static inline struct netlink_sock *nlk_sk(struct sock *sk)
{
	return container_of(sk, struct netlink_sock, sk);
}

struct netlink_table {
	struct rhashtable	hash;
	//多播链表，连接所有加入了多播组的套接字
	struct hlist_head	mc_list;
	struct listeners __rcu	*listeners;
	unsigned int		flags;
	unsigned int		groups;
	struct mutex		*cb_mutex;
	struct module		*module;
	int			(*bind)(struct net *net, int group);
	void			(*unbind)(struct net *net, int group);
	bool			(*compare)(struct net *net, struct sock *sock);
	int			registered;
};

extern struct netlink_table *nl_table;
extern rwlock_t nl_table_lock;

#endif
