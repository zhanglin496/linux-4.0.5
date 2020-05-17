/* Connection state tracking for netfilter.  This is separated from,
   but required by, the NAT layer; it can also be used by an iptables
   extension. */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2003,2004 USAGI/WIDE Project <http://www.linux-ipv6.org>
 * (C) 2005-2012 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/mm.h>
#include <linux/nsproxy.h>
#include <linux/rculist_nulls.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_timestamp.h>
#include <net/netfilter/nf_conntrack_timeout.h>
#include <net/netfilter/nf_conntrack_labels.h>
#include <net/netfilter/nf_conntrack_synproxy.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>

#define NF_CONNTRACK_VERSION	"0.5.0"

int (*nfnetlink_parse_nat_setup_hook)(struct nf_conn *ct,
				      enum nf_nat_manip_type manip,
				      const struct nlattr *attr) __read_mostly;
EXPORT_SYMBOL_GPL(nfnetlink_parse_nat_setup_hook);

__cacheline_aligned_in_smp spinlock_t nf_conntrack_locks[CONNTRACK_LOCKS];
EXPORT_SYMBOL_GPL(nf_conntrack_locks);

__cacheline_aligned_in_smp DEFINE_SPINLOCK(nf_conntrack_expect_lock);
EXPORT_SYMBOL_GPL(nf_conntrack_expect_lock);

static void nf_conntrack_double_unlock(unsigned int h1, unsigned int h2)
{
	h1 %= CONNTRACK_LOCKS;
	h2 %= CONNTRACK_LOCKS;
	spin_unlock(&nf_conntrack_locks[h1]);
	if (h1 != h2)
		spin_unlock(&nf_conntrack_locks[h2]);
}

/* return true if we need to recompute hashes (in case hash table was resized) */
static bool nf_conntrack_double_lock(struct net *net, unsigned int h1,
				     unsigned int h2, unsigned int sequence)
{
	h1 %= CONNTRACK_LOCKS;
	h2 %= CONNTRACK_LOCKS;
	if (h1 <= h2) {
		spin_lock(&nf_conntrack_locks[h1]);
		if (h1 != h2)
			spin_lock_nested(&nf_conntrack_locks[h2],
					 SINGLE_DEPTH_NESTING);
	} else {
		spin_lock(&nf_conntrack_locks[h2]);
		spin_lock_nested(&nf_conntrack_locks[h1],
				 SINGLE_DEPTH_NESTING);
	}
	if (read_seqcount_retry(&net->ct.generation, sequence)) {
		nf_conntrack_double_unlock(h1, h2);
		return true;
	}
	return false;
}

static void nf_conntrack_all_lock(void)
{
	int i;

	for (i = 0; i < CONNTRACK_LOCKS; i++)
		spin_lock_nested(&nf_conntrack_locks[i], i);
}

static void nf_conntrack_all_unlock(void)
{
	int i;

	for (i = 0; i < CONNTRACK_LOCKS; i++)
		spin_unlock(&nf_conntrack_locks[i]);
}

unsigned int nf_conntrack_htable_size __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_htable_size);

unsigned int nf_conntrack_max __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_max);

DEFINE_PER_CPU(struct nf_conn, nf_conntrack_untracked);
EXPORT_PER_CPU_SYMBOL(nf_conntrack_untracked);

unsigned int nf_conntrack_hash_rnd __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_hash_rnd);

static u32 hash_conntrack_raw(const struct nf_conntrack_tuple *tuple, u16 zone)
{
	unsigned int n;

	/* The direction must be ignored, so we hash everything up to the
	 * destination ports (which is a multiple of 4) and treat the last
	 * three bytes manually.
	 */
	n = (sizeof(tuple->src) + sizeof(tuple->dst.u3)) / sizeof(u32);
	return jhash2((u32 *)tuple, n, zone ^ nf_conntrack_hash_rnd ^
		      (((__force __u16)tuple->dst.u.all << 16) |
		      tuple->dst.protonum));
}

static u32 __hash_bucket(u32 hash, unsigned int size)
{
	return reciprocal_scale(hash, size);
}

static u32 hash_bucket(u32 hash, const struct net *net)
{
	return __hash_bucket(hash, net->ct.htable_size);
}

static u_int32_t __hash_conntrack(const struct nf_conntrack_tuple *tuple,
				  u16 zone, unsigned int size)
{
	return __hash_bucket(hash_conntrack_raw(tuple, zone), size);
}

static inline u_int32_t hash_conntrack(const struct net *net, u16 zone,
				       const struct nf_conntrack_tuple *tuple)
{
	return __hash_conntrack(tuple, zone, net->ct.htable_size);
}

bool
nf_ct_get_tuple(const struct sk_buff *skb,
		unsigned int nhoff,
		unsigned int dataoff,
		u_int16_t l3num,
		u_int8_t protonum,
		struct nf_conntrack_tuple *tuple,
		const struct nf_conntrack_l3proto *l3proto,
		const struct nf_conntrack_l4proto *l4proto)
{
	memset(tuple, 0, sizeof(*tuple));

	tuple->src.l3num = l3num;
	if (l3proto->pkt_to_tuple(skb, nhoff, tuple) == 0)
		return false;

	tuple->dst.protonum = protonum;
	tuple->dst.dir = IP_CT_DIR_ORIGINAL;

	return l4proto->pkt_to_tuple(skb, dataoff, tuple);
}
EXPORT_SYMBOL_GPL(nf_ct_get_tuple);

bool nf_ct_get_tuplepr(const struct sk_buff *skb, unsigned int nhoff,
		       u_int16_t l3num, struct nf_conntrack_tuple *tuple)
{
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int protoff;
	u_int8_t protonum;
	int ret;

	rcu_read_lock();

	l3proto = __nf_ct_l3proto_find(l3num);
	ret = l3proto->get_l4proto(skb, nhoff, &protoff, &protonum);
	if (ret != NF_ACCEPT) {
		rcu_read_unlock();
		return false;
	}

	l4proto = __nf_ct_l4proto_find(l3num, protonum);

	ret = nf_ct_get_tuple(skb, nhoff, protoff, l3num, protonum, tuple,
			      l3proto, l4proto);

	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_get_tuplepr);

bool
nf_ct_invert_tuple(struct nf_conntrack_tuple *inverse,
		   const struct nf_conntrack_tuple *orig,
		   const struct nf_conntrack_l3proto *l3proto,
		   const struct nf_conntrack_l4proto *l4proto)
{
	memset(inverse, 0, sizeof(*inverse));

	inverse->src.l3num = orig->src.l3num;
	if (l3proto->invert_tuple(inverse, orig) == 0)
		return false;

	inverse->dst.dir = !orig->dst.dir;

	inverse->dst.protonum = orig->dst.protonum;
	return l4proto->invert_tuple(inverse, orig);
}
EXPORT_SYMBOL_GPL(nf_ct_invert_tuple);

static void
clean_from_lists(struct nf_conn *ct)
{
	pr_debug("clean_from_lists(%p)\n", ct);
	hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode);
	hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_REPLY].hnnode);

	/* Destroy all pending expectations */
	nf_ct_remove_expectations(ct);
}

/* must be called with local_bh_disable */
static void nf_ct_add_to_dying_list(struct nf_conn *ct)
{
	struct ct_pcpu *pcpu;

	/* add this conntrack to the (per cpu) dying list */
	ct->cpu = smp_processor_id();
	pcpu = per_cpu_ptr(nf_ct_net(ct)->ct.pcpu_lists, ct->cpu);

	spin_lock(&pcpu->lock);
	hlist_nulls_add_head(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
			     &pcpu->dying);
	spin_unlock(&pcpu->lock);
}

/* must be called with local_bh_disable */
static void nf_ct_add_to_unconfirmed_list(struct nf_conn *ct)
{
	struct ct_pcpu *pcpu;

	/* add this conntrack to the (per cpu) unconfirmed list */
	ct->cpu = smp_processor_id();
	pcpu = per_cpu_ptr(nf_ct_net(ct)->ct.pcpu_lists, ct->cpu);

	spin_lock(&pcpu->lock);
	hlist_nulls_add_head(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
			     &pcpu->unconfirmed);
	spin_unlock(&pcpu->lock);
}

/* must be called with local_bh_disable */
static void nf_ct_del_from_dying_or_unconfirmed_list(struct nf_conn *ct)
{
	struct ct_pcpu *pcpu;

	/* We overload first tuple to link into unconfirmed or dying list.*/
	pcpu = per_cpu_ptr(nf_ct_net(ct)->ct.pcpu_lists, ct->cpu);

	spin_lock(&pcpu->lock);
	BUG_ON(hlist_nulls_unhashed(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode));
	hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode);
	spin_unlock(&pcpu->lock);
}

static void
destroy_conntrack(struct nf_conntrack *nfct)
{
	struct nf_conn *ct = (struct nf_conn *)nfct;
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_l4proto *l4proto;

	pr_debug("destroy_conntrack(%p)\n", ct);
	NF_CT_ASSERT(atomic_read(&nfct->use) == 0);
	NF_CT_ASSERT(!timer_pending(&ct->timeout));

	rcu_read_lock();
	l4proto = __nf_ct_l4proto_find(nf_ct_l3num(ct), nf_ct_protonum(ct));
	if (l4proto && l4proto->destroy)
		l4proto->destroy(ct);

	rcu_read_unlock();

	local_bh_disable();
	/* Expectations will have been removed in clean_from_lists,
	 * except TFTP can create an expectation on the first packet,
	 * before connection is in the list, so we need to clean here,
	 * too.
	 */
	nf_ct_remove_expectations(ct);
	
	nf_ct_del_from_dying_or_unconfirmed_list(ct);

	NF_CT_STAT_INC(net, delete);
	local_bh_enable();
	//如果master不为空，表明这是一个子连接
	//需要递减原来在期待连接中增加的引用计数
	if (ct->master)
		nf_ct_put(ct->master);

	pr_debug("destroy_conntrack: returning ct=%p to slab\n", ct);
	nf_conntrack_free(ct);
}

static void nf_ct_delete_from_lists(struct nf_conn *ct)
{
	struct net *net = nf_ct_net(ct);
	unsigned int hash, reply_hash;
	u16 zone = nf_ct_zone(ct);
	unsigned int sequence;

	nf_ct_helper_destroy(ct);

	local_bh_disable();
	do {
		sequence = read_seqcount_begin(&net->ct.generation);
		hash = hash_conntrack(net, zone,
				      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
		reply_hash = hash_conntrack(net, zone,
					   &ct->tuplehash[IP_CT_DIR_REPLY].tuple);
	} while (nf_conntrack_double_lock(net, hash, reply_hash, sequence));

	clean_from_lists(ct);
	nf_conntrack_double_unlock(hash, reply_hash);

	nf_ct_add_to_dying_list(ct);

	NF_CT_STAT_INC(net, delete_list);
	local_bh_enable();
}

bool nf_ct_delete(struct nf_conn *ct, u32 portid, int report)
{
	struct nf_conn_tstamp *tstamp;

	tstamp = nf_conn_tstamp_find(ct);
	if (tstamp && tstamp->stop == 0)
		tstamp->stop = ktime_get_real_ns();

	if (nf_ct_is_dying(ct))
		goto delete;

	if (nf_conntrack_event_report(IPCT_DESTROY, ct,
				    portid, report) < 0) {
		/* destroy event was not delivered */
		nf_ct_delete_from_lists(ct);
		//发送事件失败，由工作队列延迟发送
		nf_conntrack_ecache_delayed_work(nf_ct_net(ct));
		return false;
	}
	//发送事件成功，如果有pending的发送事件，立即激活工作队列
	nf_conntrack_ecache_work(nf_ct_net(ct));
	set_bit(IPS_DYING_BIT, &ct->status);
 delete:
	nf_ct_delete_from_lists(ct);
	nf_ct_put(ct);
	return true;
}
EXPORT_SYMBOL_GPL(nf_ct_delete);

static void death_by_timeout(unsigned long ul_conntrack)
{
	nf_ct_delete((struct nf_conn *)ul_conntrack, 0, 0);
}

static inline bool
nf_ct_key_equal(struct nf_conntrack_tuple_hash *h,
			const struct nf_conntrack_tuple *tuple,
			u16 zone)
{
	struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

	/* A conntrack can be recreated with the equal tuple,
	 * so we need to check that the conntrack is confirmed
	 */
	return nf_ct_tuple_equal(tuple, &h->tuple) &&
		nf_ct_zone(ct) == zone &&
		nf_ct_is_confirmed(ct);
}

/*
 * Warning :
 * - Caller must take a reference on returned object
 *   and recheck nf_ct_tuple_equal(tuple, &h->tuple)
 */
static struct nf_conntrack_tuple_hash *
____nf_conntrack_find(struct net *net, u16 zone,
		      const struct nf_conntrack_tuple *tuple, u32 hash)
{
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *n;
	unsigned int bucket = hash_bucket(hash, net);

	/* Disable BHs the entire time since we normally need to disable them
	 * at least once for the stats anyway.
	 */
	local_bh_disable();
begin:
	hlist_nulls_for_each_entry_rcu(h, n, &net->ct.hash[bucket], hnnode) {
		if (nf_ct_key_equal(h, tuple, zone)) {
			NF_CT_STAT_INC(net, found);
			local_bh_enable();
			return h;
		}
		NF_CT_STAT_INC(net, searched);
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	//A->B->C
	//假设要找C，而C移动了到新的hash 表
	//变成A->B
	//这里并不能保证一定能找到C
	//如果发现B移动了，那么有可能C也移动了
	//所以要重新找
	//如果没有发现B移动，那么查找失败
	//nulls lookup algo must check the null value at the end of lookup and
	//should restart if the null value is not the expected one.
	///cf Documentation/RCU/rculist_nulls.txt for details
	//还有一种情况
	//比如 1：A->B->C->D和2：E->F->G->H两个链表
	//假设我们需要查找1中的C，因为rcu查找没有加锁，
	//所以到1中的B时，可能B移动到2中了，变成：2：E->F->B->G->H
	//比如调用了nf_conntrack_set_hashsize调整了hash桶的大小
	//就会出现这个情况
	//此时读取B的后继指针要么是C，要么就是G，不可能是其他值，因为rcu保证指针的读取和赋值是原子的
	//如果此时我们读取的后继指针是G,那么到链表末端读取的nulls值和1中开始的hash nulls值不同，
	//此时必须重新找，因为C实际是在1中的，只不过发生了链表移动导致在1中的遍历过程被错误的停止
	//如果读取的是C，那么不需要重新查找
	//如果B没有移动，只是删除并调用rcu等待释放，那么不需要重新查找，
	//因为hlist_del_rcu不会修改next指针，所以B仍然指向C

	//但是这里实现有bug，第一因为没有重新计算hash值，
	//所以即使发现B移动到了新的hash表中，
	//也可能找不到C
	//第二net->ct.hash可能读到新的hash指针，但是使用了旧
	//的hash值，可能会崩溃
	//比如hash桶是128，旧的hash值是256
	//不相等，表示节点移动了
	//注意 这里并不保证一定能发现查找的元素，有可能元素移动后的hash值恰好未改变
	//所以在ipv4_confirm会加写锁，再查找一次，这样就可以保证唯一性
	if (get_nulls_value(n) != bucket) {
		NF_CT_STAT_INC(net, search_restart);
		goto begin;
	}
	local_bh_enable();

	return NULL;
}

/* Find a connection corresponding to a tuple. */
static struct nf_conntrack_tuple_hash *
__nf_conntrack_find_get(struct net *net, u16 zone,
			const struct nf_conntrack_tuple *tuple, u32 hash)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	rcu_read_lock();
begin:
	h = ____nf_conntrack_find(net, zone, tuple, hash);
	if (h) {
		ct = nf_ct_tuplehash_to_ctrack(h);
		if (unlikely(nf_ct_is_dying(ct) ||
			     !atomic_inc_not_zero(&ct->ct_general.use)))
			h = NULL;
		else {
			if (unlikely(!nf_ct_key_equal(h, tuple, zone))) {
				nf_ct_put(ct);
				goto begin;
			}
		}
	}
	rcu_read_unlock();

	return h;
}

struct nf_conntrack_tuple_hash *
nf_conntrack_find_get(struct net *net, u16 zone,
		      const struct nf_conntrack_tuple *tuple)
{
	return __nf_conntrack_find_get(net, zone, tuple,
				       hash_conntrack_raw(tuple, zone));
}
EXPORT_SYMBOL_GPL(nf_conntrack_find_get);

static void __nf_conntrack_hash_insert(struct nf_conn *ct,
				       unsigned int hash,
				       unsigned int reply_hash)
{
	struct net *net = nf_ct_net(ct);

	hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
			   &net->ct.hash[hash]);
	hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_REPLY].hnnode,
			   &net->ct.hash[reply_hash]);
}

int
nf_conntrack_hash_check_insert(struct nf_conn *ct)
{
	struct net *net = nf_ct_net(ct);
	unsigned int hash, reply_hash;
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *n;
	u16 zone;
	unsigned int sequence;

	zone = nf_ct_zone(ct);

	local_bh_disable();
	do {
		sequence = read_seqcount_begin(&net->ct.generation);
		hash = hash_conntrack(net, zone,
				      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
		reply_hash = hash_conntrack(net, zone,
					   &ct->tuplehash[IP_CT_DIR_REPLY].tuple);
	} while (nf_conntrack_double_lock(net, hash, reply_hash, sequence));

	/* See if there's one in the list already, including reverse */
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
				      &h->tuple) &&
		    zone == nf_ct_zone(nf_ct_tuplehash_to_ctrack(h)))
			goto out;
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[reply_hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_REPLY].tuple,
				      &h->tuple) &&
		    zone == nf_ct_zone(nf_ct_tuplehash_to_ctrack(h)))
			goto out;

	add_timer(&ct->timeout);
	smp_wmb();
	/* The caller holds a reference to this object */
	atomic_set(&ct->ct_general.use, 2);
	__nf_conntrack_hash_insert(ct, hash, reply_hash);
	nf_conntrack_double_unlock(hash, reply_hash);
	NF_CT_STAT_INC(net, insert);
	local_bh_enable();
	return 0;

out:
	nf_conntrack_double_unlock(hash, reply_hash);
	NF_CT_STAT_INC(net, insert_failed);
	local_bh_enable();
	return -EEXIST;
}
EXPORT_SYMBOL_GPL(nf_conntrack_hash_check_insert);

/* deletion from this larval template list happens via nf_ct_put() */
void nf_conntrack_tmpl_insert(struct net *net, struct nf_conn *tmpl)
{
	struct ct_pcpu *pcpu;

	__set_bit(IPS_TEMPLATE_BIT, &tmpl->status);
	__set_bit(IPS_CONFIRMED_BIT, &tmpl->status);
	nf_conntrack_get(&tmpl->ct_general);

	/* add this conntrack to the (per cpu) tmpl list */
	local_bh_disable();
	tmpl->cpu = smp_processor_id();
	pcpu = per_cpu_ptr(nf_ct_net(tmpl)->ct.pcpu_lists, tmpl->cpu);

	spin_lock(&pcpu->lock);
	/* Overload tuple linked list to put us in template list. */
	hlist_nulls_add_head_rcu(&tmpl->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
				 &pcpu->tmpl);
	spin_unlock_bh(&pcpu->lock);
}
EXPORT_SYMBOL_GPL(nf_conntrack_tmpl_insert);

/* Confirm a connection given skb; places it in hash table */
int
__nf_conntrack_confirm(struct sk_buff *skb)
{
	unsigned int hash, reply_hash;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	struct nf_conn_help *help;
	struct nf_conn_tstamp *tstamp;
	struct hlist_nulls_node *n;
	enum ip_conntrack_info ctinfo;
	struct net *net;
	u16 zone;
	unsigned int sequence;

	ct = nf_ct_get(skb, &ctinfo);
	net = nf_ct_net(ct);

	/* ipt_REJECT uses nf_conntrack_attach to attach related
	   ICMP/TCP RST packets in other direction.  Actual packet
	   which created connection will be IP_CT_NEW or for an
	   expected connection, IP_CT_RELATED. */
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;

	zone = nf_ct_zone(ct);
	local_bh_disable();
	//这里要保证读取的hash指针和hash表大小是一致的
	//因为可能调用nf_conntrack_set_hashsize来更改hash表大小
	//所以使用了顺序锁
	do {
		sequence = read_seqcount_begin(&net->ct.generation);
		/* reuse the hash saved before */
		hash = *(unsigned long *)&ct->tuplehash[IP_CT_DIR_REPLY].hnnode.pprev;
		hash = hash_bucket(hash, net);
		reply_hash = hash_conntrack(net, zone,
					   &ct->tuplehash[IP_CT_DIR_REPLY].tuple);

	} while (nf_conntrack_double_lock(net, hash, reply_hash, sequence));

	/* We're not in hash table, and we refuse to set up related
	 * connections for unconfirmed conns.  But packet copies and
	 * REJECT will give spurious warnings here.
	 */
	/* NF_CT_ASSERT(atomic_read(&ct->ct_general.use) == 1); */

	/* No external references means no one else could have
	 * confirmed us.
	 */
	NF_CT_ASSERT(!nf_ct_is_confirmed(ct));
	pr_debug("Confirming conntrack %p\n", ct);
	/* We have to check the DYING flag after unlink to prevent
	 * a race against nf_ct_get_next_corpse() possibly called from
	 * user context, else we insert an already 'dead' hash, blocking
	 * further use of that particular connection -JM.
	 */
	nf_ct_del_from_dying_or_unconfirmed_list(ct);

	if (unlikely(nf_ct_is_dying(ct)))
		goto out;
	//这里可能会出现丢包问题，尤其是在NAT，IP地址和端口耗尽的情况下
	//tuple会出现冲突问题
	//或者可能同一个流的初始数据包在不同的CPU上达到，导致问题
	/* See if there's one in the list already, including reverse:
	   NAT could have grabbed it without realizing, since we're
	   not in the hash.  If there is, we lost race. */
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
				      &h->tuple) &&
		    zone == nf_ct_zone(nf_ct_tuplehash_to_ctrack(h)))
			goto out;
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[reply_hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_REPLY].tuple,
				      &h->tuple) &&
		    zone == nf_ct_zone(nf_ct_tuplehash_to_ctrack(h)))
			goto out;

	/* Timer relative to confirmation time, not original
	   setting time, otherwise we'd get timer wrap in
	   weird delay cases. */
	ct->timeout.expires += jiffies;
	add_timer(&ct->timeout);
	atomic_inc(&ct->ct_general.use);
	ct->status |= IPS_CONFIRMED;

	/* set conntrack timestamp, if enabled. */
	tstamp = nf_conn_tstamp_find(ct);
	if (tstamp) {
		if (skb->tstamp.tv64 == 0)
			__net_timestamp(skb);

		tstamp->start = ktime_to_ns(skb->tstamp);
	}
	/* Since the lookup is lockless, hash insertion must be done after
	 * starting the timer and setting the CONFIRMED bit. The RCU barriers
	 * guarantee that no other CPU can find the conntrack before the above
	 * stores are visible.
	 */
	__nf_conntrack_hash_insert(ct, hash, reply_hash);
	nf_conntrack_double_unlock(hash, reply_hash);
	NF_CT_STAT_INC(net, insert);
	local_bh_enable();

	help = nfct_help(ct);
	if (help && help->helper)
		nf_conntrack_event_cache(IPCT_HELPER, ct);

	nf_conntrack_event_cache(master_ct(ct) ?
				 IPCT_RELATED : IPCT_NEW, ct);
	return NF_ACCEPT;

out:
	nf_ct_add_to_dying_list(ct);
	nf_conntrack_double_unlock(hash, reply_hash);
	NF_CT_STAT_INC(net, insert_failed);
	local_bh_enable();
	return NF_DROP;
}
EXPORT_SYMBOL_GPL(__nf_conntrack_confirm);

/* Returns true if a connection correspondings to the tuple (required
   for NAT). */
int
nf_conntrack_tuple_taken(const struct nf_conntrack_tuple *tuple,
			 const struct nf_conn *ignored_conntrack)
{
	struct net *net = nf_ct_net(ignored_conntrack);
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *n;
	struct nf_conn *ct;
	u16 zone = nf_ct_zone(ignored_conntrack);
	unsigned int hash = hash_conntrack(net, zone, tuple);

	/* Disable BHs the entire time since we need to disable them at
	 * least once for the stats anyway.
	 */
	rcu_read_lock_bh();
	hlist_nulls_for_each_entry_rcu(h, n, &net->ct.hash[hash], hnnode) {
		ct = nf_ct_tuplehash_to_ctrack(h);
		if (ct != ignored_conntrack &&
		    nf_ct_tuple_equal(tuple, &h->tuple) &&
		    nf_ct_zone(ct) == zone) {
			NF_CT_STAT_INC(net, found);
			rcu_read_unlock_bh();
			return 1;
		}
		NF_CT_STAT_INC(net, searched);
	}
	rcu_read_unlock_bh();

	return 0;
}
EXPORT_SYMBOL_GPL(nf_conntrack_tuple_taken);

#define NF_CT_EVICTION_RANGE	8

/* There's a small race here where we may free a just-assured
   connection.  Too bad: we're in trouble anyway. */
static noinline int early_drop(struct net *net, unsigned int _hash)
{
	/* Use oldest entry, which is roughly LRU */
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct = NULL, *tmp;
	struct hlist_nulls_node *n;
	unsigned int i = 0, cnt = 0;
	int dropped = 0;
	unsigned int hash, sequence;
	spinlock_t *lockp;

	local_bh_disable();
restart:
	sequence = read_seqcount_begin(&net->ct.generation);
	hash = hash_bucket(_hash, net);
	for (; i < net->ct.htable_size; i++) {
		lockp = &nf_conntrack_locks[hash % CONNTRACK_LOCKS];
		spin_lock(lockp);
		if (read_seqcount_retry(&net->ct.generation, sequence)) {
			spin_unlock(lockp);
			goto restart;
		}
		hlist_nulls_for_each_entry_rcu(h, n, &net->ct.hash[hash],
					 hnnode) {
			tmp = nf_ct_tuplehash_to_ctrack(h);
			if (!test_bit(IPS_ASSURED_BIT, &tmp->status) &&
			    !nf_ct_is_dying(tmp) &&
			    atomic_inc_not_zero(&tmp->ct_general.use)) {
				ct = tmp;
				break;
			}
			cnt++;
		}

		hash = (hash + 1) % net->ct.htable_size;
		spin_unlock(lockp);

		if (ct || cnt >= NF_CT_EVICTION_RANGE)
			break;

	}
	local_bh_enable();

	if (!ct)
		return dropped;

	if (del_timer(&ct->timeout)) {
		if (nf_ct_delete(ct, 0, 0)) {
			dropped = 1;
			NF_CT_STAT_INC_ATOMIC(net, early_drop);
		}
	}
	nf_ct_put(ct);
	return dropped;
}

void init_nf_conntrack_hash_rnd(void)
{
	unsigned int rand;

	/*
	 * Why not initialize nf_conntrack_rnd in a "init()" function ?
	 * Because there isn't enough entropy when system initializing,
	 * and we initialize it as late as possible.
	 */
	do {
		get_random_bytes(&rand, sizeof(rand));
	} while (!rand);
	cmpxchg(&nf_conntrack_hash_rnd, 0, rand);
}

static struct nf_conn *
__nf_conntrack_alloc(struct net *net, u16 zone,
		     const struct nf_conntrack_tuple *orig,
		     const struct nf_conntrack_tuple *repl,
		     gfp_t gfp, u32 hash)
{
	struct nf_conn *ct;

	if (unlikely(!nf_conntrack_hash_rnd)) {
		init_nf_conntrack_hash_rnd();
		/* recompute the hash as nf_conntrack_hash_rnd is initialized */
		hash = hash_conntrack_raw(orig, zone);
	}

	/* We don't want any race condition at early drop stage */
	atomic_inc(&net->ct.count);

	if (nf_conntrack_max &&
	    unlikely(atomic_read(&net->ct.count) > nf_conntrack_max)) {
		if (!early_drop(net, hash)) {
			atomic_dec(&net->ct.count);
			net_warn_ratelimited("nf_conntrack: table full, dropping packet\n");
			return ERR_PTR(-ENOMEM);
		}
	}

	/*
	 * Do not use kmem_cache_zalloc(), as this cache uses
	 * SLAB_DESTROY_BY_RCU.
	 */
	ct = kmem_cache_alloc(net->ct.nf_conntrack_cachep, gfp);
	if (ct == NULL) {
		atomic_dec(&net->ct.count);
		return ERR_PTR(-ENOMEM);
	}
	spin_lock_init(&ct->lock);
	ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple = *orig;
	ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode.pprev = NULL;
	ct->tuplehash[IP_CT_DIR_REPLY].tuple = *repl;
	/* save hash for reusing when confirming */
	*(unsigned long *)(&ct->tuplehash[IP_CT_DIR_REPLY].hnnode.pprev) = hash;
	ct->status = 0;
	/* Don't set timer yet: wait for confirmation */
	setup_timer(&ct->timeout, death_by_timeout, (unsigned long)ct);
	write_pnet(&ct->ct_net, net);
	memset(&ct->__nfct_init_offset[0], 0,
	       offsetof(struct nf_conn, proto) -
	       offsetof(struct nf_conn, __nfct_init_offset[0]));
#ifdef CONFIG_NF_CONNTRACK_ZONES
	if (zone) {
		struct nf_conntrack_zone *nf_ct_zone;

		nf_ct_zone = nf_ct_ext_add(ct, NF_CT_EXT_ZONE, GFP_ATOMIC);
		if (!nf_ct_zone)
			goto out_free;
		nf_ct_zone->id = zone;
	}
#endif
	/* Because we use RCU lookups, we set ct_general.use to zero before
	 * this is inserted in any list.
	 */
	atomic_set(&ct->ct_general.use, 0);
	return ct;

#ifdef CONFIG_NF_CONNTRACK_ZONES
out_free:
	atomic_dec(&net->ct.count);
	kmem_cache_free(net->ct.nf_conntrack_cachep, ct);
	return ERR_PTR(-ENOMEM);
#endif
}

struct nf_conn *nf_conntrack_alloc(struct net *net, u16 zone,
				   const struct nf_conntrack_tuple *orig,
				   const struct nf_conntrack_tuple *repl,
				   gfp_t gfp)
{
	return __nf_conntrack_alloc(net, zone, orig, repl, gfp, 0);
}
EXPORT_SYMBOL_GPL(nf_conntrack_alloc);

void nf_conntrack_free(struct nf_conn *ct)
{
	struct net *net = nf_ct_net(ct);

	/* A freed object has refcnt == 0, that's
	 * the golden rule for SLAB_DESTROY_BY_RCU
	 */
	NF_CT_ASSERT(atomic_read(&ct->ct_general.use) == 0);

	nf_ct_ext_destroy(ct);
	nf_ct_ext_free(ct);
	kmem_cache_free(net->ct.nf_conntrack_cachep, ct);
	smp_mb__before_atomic();
	atomic_dec(&net->ct.count);
}
EXPORT_SYMBOL_GPL(nf_conntrack_free);


/* Allocate a new conntrack: we return -ENOMEM if classification
   failed due to stress.  Otherwise it really is unclassifiable. */
static struct nf_conntrack_tuple_hash *
init_conntrack(struct net *net, struct nf_conn *tmpl,
	       const struct nf_conntrack_tuple *tuple,
	       struct nf_conntrack_l3proto *l3proto,
	       struct nf_conntrack_l4proto *l4proto,
	       struct sk_buff *skb,
	       unsigned int dataoff, u32 hash)
{
	struct nf_conn *ct;
	struct nf_conn_help *help;
	struct nf_conntrack_tuple repl_tuple;
	struct nf_conntrack_ecache *ecache;
	struct nf_conntrack_expect *exp = NULL;
	u16 zone = tmpl ? nf_ct_zone(tmpl) : NF_CT_DEFAULT_ZONE;
	struct nf_conn_timeout *timeout_ext;
	unsigned int *timeouts;

	if (!nf_ct_invert_tuple(&repl_tuple, tuple, l3proto, l4proto)) {
		pr_debug("Can't invert tuple.\n");
		return NULL;
	}

	ct = __nf_conntrack_alloc(net, zone, tuple, &repl_tuple, GFP_ATOMIC,
				  hash);
	if (IS_ERR(ct))
		return (struct nf_conntrack_tuple_hash *)ct;
	//为synproxy功能提供支持，详见ipt_SYNPROXY.c
	if (tmpl && nfct_synproxy(tmpl)) {
		nfct_seqadj_ext_add(ct);
		nfct_synproxy_ext_add(ct);
	}
	//模板是否设置了超时扩展
	timeout_ext = tmpl ? nf_ct_timeout_find(tmpl) : NULL;
	if (timeout_ext)
		timeouts = NF_CT_TIMEOUT_EXT_DATA(timeout_ext);
	else
		timeouts = l4proto->get_timeouts(net);

	if (!l4proto->new(ct, skb, dataoff, timeouts)) {
		nf_conntrack_free(ct);
		pr_debug("init conntrack: can't track with proto module\n");
		return NULL;
	}
	//添加相关ct扩展，这里并不一定会重新分配空间
	//若在此前注册的扩展，这里会一次性分配已经注册的扩展所需所有的空间
	if (timeout_ext)
		nf_ct_timeout_ext_add(ct, timeout_ext->timeout, GFP_ATOMIC);

	nf_ct_acct_ext_add(ct, GFP_ATOMIC);
	nf_ct_tstamp_ext_add(ct, GFP_ATOMIC);
	nf_ct_labels_ext_add(ct);

	ecache = tmpl ? nf_ct_ecache_find(tmpl) : NULL;
	nf_ct_ecache_ext_add(ct, ecache ? ecache->ctmask : 0,
				 ecache ? ecache->expmask : 0,
			     GFP_ATOMIC);

	local_bh_disable();
	if (net->ct.expect_count) {
		spin_lock(&nf_conntrack_expect_lock);
		//检查该连接是否命中期待连接
		//由其他模块根据需求调用nf_ct_expect_insert 添加
		exp = nf_ct_find_expectation(net, zone, tuple);
		if (exp) {
			//expect_hash表中命中，表明这是一个期待连接
			//期待连接是由模块注册的helper函数根据数据包动态创建的
			pr_debug("conntrack: expectation arrives ct=%p exp=%p\n",
				 ct, exp);
			/* Welcome, Mr. Bond.  We've been expecting you... */
			//设置期待链接，通知防火墙
			__set_bit(IPS_EXPECTED_BIT, &ct->status);
			/* exp->master safe, refcnt bumped in nf_ct_find_expectation */
			//nf_ct_find_expectation 已经增加了主连接的引用计数
			//所以这里不需要再次增加
			//这里子连接增加了主连接的引用计数
			//意味着子连接未释放前主连接是不会释放的
			//记录当前ct 是属于哪个主连接
			ct->master = exp->master;
			if (exp->helper) {
				help = nf_ct_helper_ext_add(ct, exp->helper,
							    GFP_ATOMIC);
				if (help)
					rcu_assign_pointer(help->helper, exp->helper);
			}
			//设置为和主连接同样的标记
#ifdef CONFIG_NF_CONNTRACK_MARK
			ct->mark = exp->master->mark;
#endif
#ifdef CONFIG_NF_CONNTRACK_SECMARK
			ct->secmark = exp->master->secmark;
#endif
			NF_CT_STAT_INC(net, expect_new);
		}
		spin_unlock(&nf_conntrack_expect_lock);
	}
	if (!exp) {
		//不是期待连接,  查找该连接是否有匹配的helper函数
		//指派helper函数，并在ipv4_helper 调用helper函数创建期待连接
		//也就是构建struct nf_conntrack_expect 结构，并加入到expect_hash表中，
		//若没有helper函数，则不会分配help扩展区
		__nf_ct_try_assign_helper(ct, tmpl, GFP_ATOMIC);
		NF_CT_STAT_INC(net, new);
	}

	/* Now it is inserted into the unconfirmed list, bump refcount */
	nf_conntrack_get(&ct->ct_general);
	nf_ct_add_to_unconfirmed_list(ct);

	local_bh_enable();
	//调用expectfn函数，一般当主链接做了NAT转换
	//才需要额外指定expectfn函数，	
	if (exp) {
		// nf_nat_follow_master,期待链接必须和主链接做相同的NAT转换
		// 否则无法正常通信
		//保证子连接和主链接做相同的NAT转换
		if (exp->expectfn)
			exp->expectfn(ct, exp);
		//引用计数应该为1，释放期待连接
		nf_ct_expect_put(exp);
	}

	return &ct->tuplehash[IP_CT_DIR_ORIGINAL];
}

/* On success, returns conntrack ptr, sets skb->nfct and ctinfo */
static inline struct nf_conn *
resolve_normal_ct(struct net *net, struct nf_conn *tmpl,
		  struct sk_buff *skb,
		  unsigned int dataoff,
		  u_int16_t l3num,
		  u_int8_t protonum,
		  struct nf_conntrack_l3proto *l3proto,
		  struct nf_conntrack_l4proto *l4proto,
		  int *set_reply,
		  enum ip_conntrack_info *ctinfo)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	u16 zone = tmpl ? nf_ct_zone(tmpl) : NF_CT_DEFAULT_ZONE;
	u32 hash;

	if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
			     dataoff, l3num, protonum, &tuple, l3proto,
			     l4proto)) {
		pr_debug("resolve_normal_ct: Can't get tuple\n");
		return NULL;
	}

	//1. 基本NAT
	//　　基本NAT只转换IP地址，而不转换端口。
	//一个基本NAT往往需要具有多个公网IP来满足
	//多个内网节点中具有相同端口的应用程序的
	//同时访问。由于这种类型的NAT设备限制大，现在已不常见。
	//　　2. NAPT
	//　　（注：Endpoint表示一个IP地址和端口对）
	//　　与基本NAT只转换IP地址不同，NAPT转换整个
	//Endpoint。由于NAPT允许内网内的多个节点通过共享的
	//方式使用同一个IP地址，因此，
	//如今NAPT类型的NAT设备已经越来越多。
	//　　NAPT又可以进一步分为以下四种类型：
	//		(1) 完全锥型NAT(FULL CONE NAT)
	//　　完全锥型NAT在内网用户A(Private Endpoint)首次向外部主机
	//发送数据包时创建地址映射会话，
	//并为A分配一个公网地址和端口(Public Endpoint)，
	//以后任何A向外部发送的数据都将使用这个Public Endpoint。
	//此后，任何外部主机想要与A通信，
	//只要将数据包发送到Public Endpoint上，A就能够顺利的进行接收。
	//也就是不限制外部主机的IP地址和端口
	//同时也不需要内部主机向外部主机主动发数据包
	//A full cone NAT is also known as a one-to-one NAT. Once an
	//internal IP address and port are mapped to some external
	//IP address and port respectively, all the packets with the
	//internal IP address and port will be translated to the fixed
	//external IP address and port. Furthermore, any external
	//host can send a packet to the internal host by sending a
	//packet to the mapped external address.
	//　　(2) 限制锥型NAT (RESTRICT CONE NAT)
	//　　限制锥型NAT在内网用户A(Private Endpoint)首次向外部主机
	//发送数据包时创建地址映射会话，并为A分配一个公网地址和端口
	//(Public Endpoint)，以后任何A向外部发送的数据包都将使用这个
	//Public Endpoint。此后，如果某个外部主机（Endpoint IP:PORT）
	//想要与A通信，只要将数据包发送到Public Endpoint并且保证A
	//曾用当前与NAT的会话向该外部主机的IP地址发送过数据，
	//A就能够正常收到外部主机（Endpoint IP:PORT）发送来的数据包。
	//也就是说限制了外部的主机的IP地址，但是不限制端口。
	//In the restricted cone NAT, all requests from an internal IP
	//address and port are mapped to a fixed external IP address
	//and port. It is similar to the full cone NAT except that unlike the full cone NAT, 
	//an external host s2 (with IP address x) 
	//can send a packet to an internal host only if 
	//the internal host has previously sent a packet to the IP address x
	//through the restricted cone NAT.
	//　　(3) 端口限制锥型NAT(PORT RESTRICT CONE NAT)
	//　　端口限制锥型在内网用户A(Private Endpoint)首次向外部主机
	//发送数据包时创建地址映射会话，并为A分配一个公网地址
	//和端口(Public Endpoint)，以后任何A向外部发送的数据都将使用
	//这个Public Endpoint。此后，如果某个外部主机（Endpoint IP:PORT）
	//想要与A通信，只要将数据包发送到Public Endpoint并且保证A
	//曾用当前与NAT的会话向该外部主机的Endpoint发送过数据，
	//A就能够正常收到外部主机（Endpoint IP:PORT）发送来的数据包。
	//也就是说限制了外部的主机的IP地址和端口。
	//The port restricted cone NAT is similar to the restricted
	//cone NAT. However, the port restricted cone NAT also takes
	//the port numbers into account along with the IP addresses.
	//An external host can send a packet with source IP address
	//x and source port p to an internal host only if the internal
	//host has previously sent a packet to the IP address x and port p. 
	//　　(4) 对称型NAT(SYMMETRIC NAT)
	//　　对称型NAT是一种比较特殊的NAT。内网用户A(Private Endpoint)首次
	//向外部主机S1发送数据包时创建地址映射会话Session1，
	//并为A分配一个公网地址和端口(Public Endpoint1)，
	//以后A所有发向S1的数据包都使用这个Public Endpoint1。
	//如果之后A用同一个Socket向外部主机S2发送数据包，
	//这时对称型NAT又为其分配一个地址映射会话，
	//并为A分配一个新的公网地址和端口对（Public Endpoint2），
	//以后A所有发向S2的数据包都使用这个Public Endpoint2。
	//对称型NAT规定Public Endpoint1和Public Endpoint2一定不相同。
	//此外，如果任何外部主机想要发送数据给A，那么它首先应该
	//收到A发给他的数据，然后才能往回发送，
	//否则即使他知道内网主机的Public Endpoint也不能发送数据给A。
	//这种NAT可以通过端口猜测等方法进行穿透，
	//但是效果并不是很好，很难实现UDP-P2P通信。
	//In a symmetric NAT, any request from an internal IP address and a port number 
	//to some destination IP address and
	//port number is mapped to a unique external IP address and
	//a unique port number. If the same host sends a packet from
	//the same source address and the same port number but to
	//a different destination, a different mapping is used. Only
	//the external host that receives a packet from an internal
	//host can send a UDP packet back to the internal host.

	/* look for tuple match */
	//NAT类型, 内容来自rfc3489.txt
	/*//前面3 中NAT都是相同的内部IP地址和端口会
	  * //一直映射到相同的外部IP地址和端口
         * Based on NAT treatments of UDP in RFC3489:
         *  //只要知道了内部主机的映射关系
         * //任意外部主机都可以发送报文给
         * //内部主机，不需要内部主机提前发送报文
         * //不限制外部主机的IP地址和端口
         * //全锥形NAT 是最容易打洞成功的
         * 1)Full Cone: A full cone NAT is one where all requests from the
         * same internal IP address and port are mapped to the same external
         * IP address and port.  Furthermore, any external host can send a
         * packet to the internal host, by sending a packet to the mapped
         * external address.
         *
         * //内部主机要先发报文到外部主机指定的IP
         * //这样外部主机才能发送报文到内部主机
         * //和全锥形NAT 不同的是，这里限制了外部主机的IP地址
         * 2)Restricted Cone: A restricted cone NAT is one where all requests
         * from the same internal IP address and port are mapped to the same
         * external IP address and port.  Unlike a full cone NAT, an external
         * host (with IP address X) can send a packet to the internal host
         * only if the internal host had previously sent a packet to IP
         * address X.
         *
         * //内部主机要先发报文到外部主机指定的IP和端口
         * //和全锥形NAT 不同的是，这里同时限制了外部主机的IP地址和端口
         * 3)Port Restricted Cone: A port restricted cone NAT is like a
         * restricted cone NAT, but the restriction includes port numbers.
         * Specifically, an external host can send a packet, with source IP
         * address X and source port P, to the internal host only if the
         * internal host had previously sent a packet to IP address X and
         * port P.
	  * 
         * // 对称NAT，根据五元组来映射
         * //不同的5元组使用不同的映射
         * //和锥形NAT不一样，锥形NAT始终会把相同的内部IP地址和端口
         * //映射到相同的 外部IP地址和端口
         * //如果目的地址或端口不一样，则相同的IP源地址和端口
         * //一定会映射到不同的外部地址和端口(注意: 外部地址可能相同
         * //但是端口要求一定不相同)
         * //而且要求内部主机先向外部主机发送数据包
         * //外部主机才能和内部主机通信
         * //对称NAT 要求比上面3中NAT都高，用于高安全的通信
         * //和cone nat 不一样
         * 4)Symmetric: A symmetric NAT is one where all requests from the
         * same internal IP address and port, to a specific destination IP
         * address and port, are mapped to the same external IP address and
         * port.  If the same host sends a packet with the same source
         * address and port, but to a different destination, a different
         * mapping is used.  Furthermore, only the external host that
         * receives a packet can send a UDP packet back to the internal host.
         *
         *
         *
         * //linux的NAT混合了对称NAT和端口受限制的NAT特征
         * Original Linux NAT type is hybrid 'port restricted cone' and
         * 'symmetric'. XBOX certificate recommands NAT type is 'fully cone'
         * or 'restricted cone', so i patch the linux kernel to support
         * this feature
         * Tradition scenario from LAN->WAN:
         *
         *        (LAN)     (WAN)
         * Client------>AP---------> Server
         * -------------> (I)
         *              -------------->(II)
         *              <--------------(III)
         * <------------- (IV)
         *
         */
	/* CASE III */
	hash = hash_conntrack_raw(&tuple, zone);
	h = __nf_conntrack_find_get(net, zone, &tuple, hash);
	if (!h) {
		h = init_conntrack(net, tmpl, &tuple, l3proto, l4proto,
				   skb, dataoff, hash);
		if (!h)
			return NULL;
		if (IS_ERR(h))
			return (void *)h;
	}
	ct = nf_ct_tuplehash_to_ctrack(h);

	/* It exists; we have (non-exclusive) reference. */
	if (NF_CT_DIRECTION(h) == IP_CT_DIR_REPLY) {
		*ctinfo = IP_CT_ESTABLISHED_REPLY;
		/* Please set reply bit if this packet OK */
		*set_reply = 1;
	} else {
		/* Once we've had two way comms, always ESTABLISHED. */
		if (test_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
			pr_debug("nf_conntrack_in: normal packet for %p\n", ct);
			*ctinfo = IP_CT_ESTABLISHED;
		} else if (test_bit(IPS_EXPECTED_BIT, &ct->status)) {
			pr_debug("nf_conntrack_in: related packet for %p\n",
				 ct);
			*ctinfo = IP_CT_RELATED;
		} else {
			pr_debug("nf_conntrack_in: new packet for %p\n", ct);
			*ctinfo = IP_CT_NEW;
		}
		*set_reply = 0;
	}
	skb->nfct = &ct->ct_general;
	skb->nfctinfo = *ctinfo;
	return ct;
}

unsigned int
nf_conntrack_in(struct net *net, u_int8_t pf, unsigned int hooknum,
		struct sk_buff *skb)
{
	struct nf_conn *ct, *tmpl = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int *timeouts;
	unsigned int dataoff;
	u_int8_t protonum;
	int set_reply = 0;
	int ret;

	if (skb->nfct) {
		/* Previously seen (loopback or untracked)?  Ignore. */
		tmpl = (struct nf_conn *)skb->nfct;
		if (!nf_ct_is_template(tmpl)) {
			NF_CT_STAT_INC_ATOMIC(net, ignore);
			return NF_ACCEPT;
		}
		skb->nfct = NULL;
	}
	
	/* rcu_read_lock()ed by nf_hook_slow */
	l3proto = __nf_ct_l3proto_find(pf);
	ret = l3proto->get_l4proto(skb, skb_network_offset(skb),
				   &dataoff, &protonum);
	if (ret <= 0) {
		pr_debug("not prepared to track yet or error occurred\n");
		NF_CT_STAT_INC_ATOMIC(net, error);
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		ret = -ret;
		goto out;
	}

	l4proto = __nf_ct_l4proto_find(pf, protonum);
	//udp_error 和 tcp_error函数
	//tcp_error会对tcp 头部的标志组合做合法性检查
	/* It may be an special packet, error, unclean...
	 * inverse of the return code tells to the netfilter
	 * core what to do with the packet. */
	if (l4proto->error != NULL) {
		ret = l4proto->error(net, tmpl, skb, dataoff, &ctinfo,
				     pf, hooknum);
		if (ret <= 0) {
			NF_CT_STAT_INC_ATOMIC(net, error);
			NF_CT_STAT_INC_ATOMIC(net, invalid);
			ret = -ret;
			goto out;
		}
		//对于ICMP协议
		//ICMP差错报文应该和一个已经存在的
		//conntrack关联，详见icmp_error
		/* ICMP[v6] protocol trackers may assign one conntrack. */
		//跳过余下的匹配流程
		//可以利用icmp 来探测ttl
		//实现tcp打洞功能 
		//这是因为对于正常的tcp 连接
		//如果ttl设置的过小，不会导致tcp 连接的异常终止
		//因为这不是一个致命错误，
		//同时也不会刷新tcp状态，这样就会留下一个有效
		//的conntrack 连接记录，利用这一点就可以实现tcp打洞
		if (skb->nfct)
			goto out;
	}

	ct = resolve_normal_ct(net, tmpl, skb, dataoff, pf, protonum,
			       l3proto, l4proto, &set_reply, &ctinfo);
	if (!ct) {
		/* Not valid part of a connection */
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		ret = NF_ACCEPT;
		goto out;
	}

	if (IS_ERR(ct)) {
		/* Too stressed to deal. */
		NF_CT_STAT_INC_ATOMIC(net, drop);
		ret = NF_DROP;
		goto out;
	}


	NF_CT_ASSERT(skb->nfct);

	/* Decide what timeout policy we want to apply to this flow. */
	timeouts = nf_ct_timeout_lookup(net, ct, l4proto);
	
	//udp_packet 和  tcp_packet
	//tcp_packet会做状态检查和序列号检查，重传检查等
	ret = l4proto->packet(ct, skb, dataoff, ctinfo, pf, hooknum, timeouts);
	if (ret <= 0) {
		/* Invalid: inverse of the return code tells
		 * the netfilter core what to do */
		pr_debug("nf_conntrack_in: Can't track with proto module\n");
		nf_conntrack_put(skb->nfct);
		skb->nfct = NULL;
		NF_CT_STAT_INC_ATOMIC(net, invalid);
		if (ret == -NF_DROP)
			NF_CT_STAT_INC_ATOMIC(net, drop);
		ret = -ret;
		goto out;
	}
	//这里为什么没有先test_bit再set_bit
	//是因为要保证是一个原子操作
	//否则会出现调用nf_conntrack_event_cache两次的情况
	//比如两个reply包同时到达这里
	//只有一个包会触发nf_conntrack_event_cache
	if (set_reply && !test_and_set_bit(IPS_SEEN_REPLY_BIT, &ct->status))
		//通过netlink 多播conntrack事件
		//每个conntrack都有struct nf_conntrack_ecache NF_CT_EXT_ECACHE扩展
		//记录了需要多播的事件
		nf_conntrack_event_cache(IPCT_REPLY, ct);
out:
	if (tmpl) {
		/* Special case: we have to repeat this hook, assign the
		 * template again to this packet. We assume that this packet
		 * has no conntrack assigned. This is used by nf_ct_tcp. */
		if (ret == NF_REPEAT)
			skb->nfct = (struct nf_conntrack *)tmpl;
		else
			nf_ct_put(tmpl);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(nf_conntrack_in);

bool nf_ct_invert_tuplepr(struct nf_conntrack_tuple *inverse,
			  const struct nf_conntrack_tuple *orig)
{
	bool ret;

	rcu_read_lock();
	ret = nf_ct_invert_tuple(inverse, orig,
				 __nf_ct_l3proto_find(orig->src.l3num),
				 __nf_ct_l4proto_find(orig->src.l3num,
						      orig->dst.protonum));
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_invert_tuplepr);

/* Alter reply tuple (maybe alter helper).  This is for NAT, and is
   implicitly racy: see __nf_conntrack_confirm */
void nf_conntrack_alter_reply(struct nf_conn *ct,
			      const struct nf_conntrack_tuple *newreply)
{
	struct nf_conn_help *help = nfct_help(ct);

	/* Should be unconfirmed, so not in hash table yet */
	NF_CT_ASSERT(!nf_ct_is_confirmed(ct));

	pr_debug("Altering reply tuple of %p to ", ct);
	nf_ct_dump_tuple(newreply);

	ct->tuplehash[IP_CT_DIR_REPLY].tuple = *newreply;
	if (ct->master || (help && !hlist_empty(&help->expectations)))
		return;

	rcu_read_lock();
	__nf_ct_try_assign_helper(ct, NULL, GFP_ATOMIC);
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(nf_conntrack_alter_reply);

/* Refresh conntrack for this many jiffies and do accounting if do_acct is 1 */
void __nf_ct_refresh_acct(struct nf_conn *ct,
			  enum ip_conntrack_info ctinfo,
			  const struct sk_buff *skb,
			  unsigned long extra_jiffies,
			  int do_acct)
{
	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);
	NF_CT_ASSERT(skb);

	/* Only update if this is not a fixed timeout */
	if (test_bit(IPS_FIXED_TIMEOUT_BIT, &ct->status))
		goto acct;

	/* If not in hash table, timer will not be active yet */
	if (!nf_ct_is_confirmed(ct)) {
		ct->timeout.expires = extra_jiffies;
	} else {
		unsigned long newtime = jiffies + extra_jiffies;

		/* Only update the timeout if the new timeout is at least
		   HZ jiffies from the old timeout. Need del_timer for race
		   avoidance (may already be dying). */
		if (newtime - ct->timeout.expires >= HZ)
			mod_timer_pending(&ct->timeout, newtime);
	}

acct:
	if (do_acct) {
		struct nf_conn_acct *acct;

		acct = nf_conn_acct_find(ct);
		if (acct) {
			struct nf_conn_counter *counter = acct->counter;

			atomic64_inc(&counter[CTINFO2DIR(ctinfo)].packets);
			atomic64_add(skb->len, &counter[CTINFO2DIR(ctinfo)].bytes);
		}
	}
}
EXPORT_SYMBOL_GPL(__nf_ct_refresh_acct);

bool __nf_ct_kill_acct(struct nf_conn *ct,
		       enum ip_conntrack_info ctinfo,
		       const struct sk_buff *skb,
		       int do_acct)
{
	if (do_acct) {
		struct nf_conn_acct *acct;

		acct = nf_conn_acct_find(ct);
		if (acct) {
			struct nf_conn_counter *counter = acct->counter;

			atomic64_inc(&counter[CTINFO2DIR(ctinfo)].packets);
			atomic64_add(skb->len - skb_network_offset(skb),
				     &counter[CTINFO2DIR(ctinfo)].bytes);
		}
	}

	if (del_timer(&ct->timeout)) {
		//定时器删除成功，手动执行销毁函数
		ct->timeout.function((unsigned long)ct);
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(__nf_ct_kill_acct);

#ifdef CONFIG_NF_CONNTRACK_ZONES
static struct nf_ct_ext_type nf_ct_zone_extend __read_mostly = {
	.len	= sizeof(struct nf_conntrack_zone),
	.align	= __alignof__(struct nf_conntrack_zone),
	.id	= NF_CT_EXT_ZONE,
};
#endif

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/mutex.h>

/* Generic function for tcp/udp/sctp/dccp and alike. This needs to be
 * in ip_conntrack_core, since we don't want the protocols to autoload
 * or depend on ctnetlink */
int nf_ct_port_tuple_to_nlattr(struct sk_buff *skb,
			       const struct nf_conntrack_tuple *tuple)
{
	if (nla_put_be16(skb, CTA_PROTO_SRC_PORT, tuple->src.u.tcp.port) ||
	    nla_put_be16(skb, CTA_PROTO_DST_PORT, tuple->dst.u.tcp.port))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -1;
}
EXPORT_SYMBOL_GPL(nf_ct_port_tuple_to_nlattr);

const struct nla_policy nf_ct_port_nla_policy[CTA_PROTO_MAX+1] = {
	[CTA_PROTO_SRC_PORT]  = { .type = NLA_U16 },
	[CTA_PROTO_DST_PORT]  = { .type = NLA_U16 },
};
EXPORT_SYMBOL_GPL(nf_ct_port_nla_policy);

int nf_ct_port_nlattr_to_tuple(struct nlattr *tb[],
			       struct nf_conntrack_tuple *t)
{
	if (!tb[CTA_PROTO_SRC_PORT] || !tb[CTA_PROTO_DST_PORT])
		return -EINVAL;

	t->src.u.tcp.port = nla_get_be16(tb[CTA_PROTO_SRC_PORT]);
	t->dst.u.tcp.port = nla_get_be16(tb[CTA_PROTO_DST_PORT]);

	return 0;
}
EXPORT_SYMBOL_GPL(nf_ct_port_nlattr_to_tuple);

int nf_ct_port_nlattr_tuple_size(void)
{
	return nla_policy_len(nf_ct_port_nla_policy, CTA_PROTO_MAX + 1);
}
EXPORT_SYMBOL_GPL(nf_ct_port_nlattr_tuple_size);
#endif

/* Used by ipt_REJECT and ip6t_REJECT. */
static void nf_conntrack_attach(struct sk_buff *nskb, const struct sk_buff *skb)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	/* This ICMP is in reverse direction to the packet which caused it */
	ct = nf_ct_get(skb, &ctinfo);
	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL)
		ctinfo = IP_CT_RELATED_REPLY;
	else
		ctinfo = IP_CT_RELATED;

	/* Attach to new skbuff, and increment count */
	nskb->nfct = &ct->ct_general;
	nskb->nfctinfo = ctinfo;
	nf_conntrack_get(nskb->nfct);
}

/* Bring out ya dead! */
static struct nf_conn *
get_next_corpse(struct net *net, int (*iter)(struct nf_conn *i, void *data),
		void *data, unsigned int *bucket)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	struct hlist_nulls_node *n;
	int cpu;
	spinlock_t *lockp;

	for (; *bucket < net->ct.htable_size; (*bucket)++) {
		lockp = &nf_conntrack_locks[*bucket % CONNTRACK_LOCKS];
		local_bh_disable();
		spin_lock(lockp);
		if (*bucket < net->ct.htable_size) {
			hlist_nulls_for_each_entry(h, n, &net->ct.hash[*bucket], hnnode) {
				if (NF_CT_DIRECTION(h) != IP_CT_DIR_ORIGINAL)
					continue;
				ct = nf_ct_tuplehash_to_ctrack(h);
				if (iter(ct, data))
					goto found;
			}
		}
		spin_unlock(lockp);
		local_bh_enable();
	}

	for_each_possible_cpu(cpu) {
		struct ct_pcpu *pcpu = per_cpu_ptr(net->ct.pcpu_lists, cpu);

		spin_lock_bh(&pcpu->lock);
		hlist_nulls_for_each_entry(h, n, &pcpu->unconfirmed, hnnode) {
			ct = nf_ct_tuplehash_to_ctrack(h);
			if (iter(ct, data))
				set_bit(IPS_DYING_BIT, &ct->status);
		}
		spin_unlock_bh(&pcpu->lock);
	}
	return NULL;
found:
	atomic_inc(&ct->ct_general.use);
	spin_unlock(lockp);
	local_bh_enable();
	return ct;
}

void nf_ct_iterate_cleanup(struct net *net,
			   int (*iter)(struct nf_conn *i, void *data),
			   void *data, u32 portid, int report)
{
	struct nf_conn *ct;
	unsigned int bucket = 0;

	while ((ct = get_next_corpse(net, iter, data, &bucket)) != NULL) {
		/* Time to push up daises... */
		if (del_timer(&ct->timeout))
			nf_ct_delete(ct, portid, report);

		/* ... else the timer will get him soon. */

		nf_ct_put(ct);
	}
}
EXPORT_SYMBOL_GPL(nf_ct_iterate_cleanup);

static int kill_all(struct nf_conn *i, void *data)
{
	return 1;
}

void nf_ct_free_hashtable(void *hash, unsigned int size)
{
	if (is_vmalloc_addr(hash))
		vfree(hash);
	else
		free_pages((unsigned long)hash,
			   get_order(sizeof(struct hlist_head) * size));
}
EXPORT_SYMBOL_GPL(nf_ct_free_hashtable);

static int untrack_refs(void)
{
	int cnt = 0, cpu;

	for_each_possible_cpu(cpu) {
		struct nf_conn *ct = &per_cpu(nf_conntrack_untracked, cpu);

		cnt += atomic_read(&ct->ct_general.use) - 1;
	}
	return cnt;
}

void nf_conntrack_cleanup_start(void)
{
	RCU_INIT_POINTER(ip_ct_attach, NULL);
}

void nf_conntrack_cleanup_end(void)
{
	RCU_INIT_POINTER(nf_ct_destroy, NULL);
	while (untrack_refs() > 0)
		schedule();

#ifdef CONFIG_NF_CONNTRACK_ZONES
	nf_ct_extend_unregister(&nf_ct_zone_extend);
#endif
	nf_conntrack_proto_fini();
	nf_conntrack_seqadj_fini();
	nf_conntrack_labels_fini();
	nf_conntrack_helper_fini();
	nf_conntrack_timeout_fini();
	nf_conntrack_ecache_fini();
	nf_conntrack_tstamp_fini();
	nf_conntrack_acct_fini();
	nf_conntrack_expect_fini();
}

/*
 * Mishearing the voices in his head, our hero wonders how he's
 * supposed to kill the mall.
 */
void nf_conntrack_cleanup_net(struct net *net)
{
	LIST_HEAD(single);

	list_add(&net->exit_list, &single);
	nf_conntrack_cleanup_net_list(&single);
}

void nf_conntrack_cleanup_net_list(struct list_head *net_exit_list)
{
	int busy;
	struct net *net;

	/*
	 * This makes sure all current packets have passed through
	 *  netfilter framework.  Roll on, two-stage module
	 *  delete...
	 */
	synchronize_net();
i_see_dead_people:
	busy = 0;
	list_for_each_entry(net, net_exit_list, exit_list) {
		nf_ct_iterate_cleanup(net, kill_all, NULL, 0, 0);
		if (atomic_read(&net->ct.count) != 0)
			busy = 1;
	}
	if (busy) {
		schedule();
		goto i_see_dead_people;
	}

	list_for_each_entry(net, net_exit_list, exit_list) {
		nf_ct_free_hashtable(net->ct.hash, net->ct.htable_size);
		nf_conntrack_proto_pernet_fini(net);
		nf_conntrack_helper_pernet_fini(net);
		nf_conntrack_ecache_pernet_fini(net);
		nf_conntrack_tstamp_pernet_fini(net);
		nf_conntrack_acct_pernet_fini(net);
		nf_conntrack_expect_pernet_fini(net);
		kmem_cache_destroy(net->ct.nf_conntrack_cachep);
		kfree(net->ct.slabname);
		free_percpu(net->ct.stat);
		free_percpu(net->ct.pcpu_lists);
	}
}

void *nf_ct_alloc_hashtable(unsigned int *sizep, int nulls)
{
	struct hlist_nulls_head *hash;
	unsigned int nr_slots, i;
	size_t sz;

	BUILD_BUG_ON(sizeof(struct hlist_nulls_head) != sizeof(struct hlist_head));
	nr_slots = *sizep = roundup(*sizep, PAGE_SIZE / sizeof(struct hlist_nulls_head));
	sz = nr_slots * sizeof(struct hlist_nulls_head);
	hash = (void *)__get_free_pages(GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
					get_order(sz));
	if (!hash) {
		printk(KERN_WARNING "nf_conntrack: falling back to vmalloc.\n");
		hash = vzalloc(sz);
	}

	if (hash && nulls)
		//初始化hash桶，null节点的实际存储的值是1，3，5，7，9，11，.....
		//都是奇数, 调用get_nulls_value 获取的有效值是0，1，2，3，...
		//对应hash桶的数组下标
		for (i = 0; i < nr_slots; i++)
			INIT_HLIST_NULLS_HEAD(&hash[i], i);

	return hash;
}
EXPORT_SYMBOL_GPL(nf_ct_alloc_hashtable);

int nf_conntrack_set_hashsize(const char *val, struct kernel_param *kp)
{
	int i, bucket, rc;
	unsigned int hashsize, old_size;
	struct hlist_nulls_head *hash, *old_hash;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	if (current->nsproxy->net_ns != &init_net)
		return -EOPNOTSUPP;

	/* On boot, we can set this without any fancy locking. */
	if (!nf_conntrack_htable_size)
		return param_set_uint(val, kp);

	rc = kstrtouint(val, 0, &hashsize);
	if (rc)
		return rc;
	if (!hashsize)
		return -EINVAL;

	hash = nf_ct_alloc_hashtable(&hashsize, 1);
	if (!hash)
		return -ENOMEM;

	local_bh_disable();
	//加锁，锁住所有的hash桶
	//和ipv4_confirm的插入操作互斥，
	//所以在hash调整未完成之前，其他的CPU都会在锁上等待直到调整完成
	nf_conntrack_all_lock();
	write_seqcount_begin(&init_net.ct.generation);

	/* Lookups in the old hash might happen in parallel, which means we
	 * might get false negatives during connection lookup. New connections
	 * created because of a false negative won't make it into the hash
	 * though since that required taking the locks.
	 */

	for (i = 0; i < init_net.ct.htable_size; i++) {
		while (!hlist_nulls_empty(&init_net.ct.hash[i])) {
			h = hlist_nulls_entry(init_net.ct.hash[i].first,
					struct nf_conntrack_tuple_hash, hnnode);
			ct = nf_ct_tuplehash_to_ctrack(h);
			hlist_nulls_del_rcu(&h->hnnode);
			bucket = __hash_conntrack(&h->tuple, nf_ct_zone(ct),
						  hashsize);
			hlist_nulls_add_head_rcu(&h->hnnode, &hash[bucket]);
		}
	}
	old_size = init_net.ct.htable_size;
	old_hash = init_net.ct.hash;

	init_net.ct.htable_size = nf_conntrack_htable_size = hashsize;
	init_net.ct.hash = hash;

	write_seqcount_end(&init_net.ct.generation);
	nf_conntrack_all_unlock();
	local_bh_enable();

	nf_ct_free_hashtable(old_hash, old_size);
	return 0;
}
EXPORT_SYMBOL_GPL(nf_conntrack_set_hashsize);

module_param_call(hashsize, nf_conntrack_set_hashsize, param_get_uint,
		  &nf_conntrack_htable_size, 0600);

void nf_ct_untracked_status_or(unsigned long bits)
{
	int cpu;

	for_each_possible_cpu(cpu)
		per_cpu(nf_conntrack_untracked, cpu).status |= bits;
}
EXPORT_SYMBOL_GPL(nf_ct_untracked_status_or);

int nf_conntrack_init_start(void)
{
	int max_factor = 8;
	int i, ret, cpu;

	for (i = 0; i < CONNTRACK_LOCKS; i++)
		spin_lock_init(&nf_conntrack_locks[i]);

	if (!nf_conntrack_htable_size) {
		/* Idea from tcp.c: use 1/16384 of memory.
		 * On i386: 32MB machine has 512 buckets.
		 * >= 1GB machines have 16384 buckets.
		 * >= 4GB machines have 65536 buckets.
		 */
		nf_conntrack_htable_size
			= (((totalram_pages << PAGE_SHIFT) / 16384)
			   / sizeof(struct hlist_head));
		if (totalram_pages > (4 * (1024 * 1024 * 1024 / PAGE_SIZE)))
			nf_conntrack_htable_size = 65536;
		else if (totalram_pages > (1024 * 1024 * 1024 / PAGE_SIZE))
			nf_conntrack_htable_size = 16384;
		if (nf_conntrack_htable_size < 32)
			nf_conntrack_htable_size = 32;

		/* Use a max. factor of four by default to get the same max as
		 * with the old struct list_heads. When a table size is given
		 * we use the old value of 8 to avoid reducing the max.
		 * entries. */
		max_factor = 4;
	}
	nf_conntrack_max = max_factor * nf_conntrack_htable_size;

	printk(KERN_INFO "nf_conntrack version %s (%u buckets, %d max)\n",
	       NF_CONNTRACK_VERSION, nf_conntrack_htable_size,
	       nf_conntrack_max);

	ret = nf_conntrack_expect_init();
	if (ret < 0)
		goto err_expect;

	ret = nf_conntrack_acct_init();
	if (ret < 0)
		goto err_acct;

	ret = nf_conntrack_tstamp_init();
	if (ret < 0)
		goto err_tstamp;

	ret = nf_conntrack_ecache_init();
	if (ret < 0)
		goto err_ecache;

	ret = nf_conntrack_timeout_init();
	if (ret < 0)
		goto err_timeout;

	ret = nf_conntrack_helper_init();
	if (ret < 0)
		goto err_helper;

	ret = nf_conntrack_labels_init();
	if (ret < 0)
		goto err_labels;

	ret = nf_conntrack_seqadj_init();
	if (ret < 0)
		goto err_seqadj;

#ifdef CONFIG_NF_CONNTRACK_ZONES
	ret = nf_ct_extend_register(&nf_ct_zone_extend);
	if (ret < 0)
		goto err_extend;
#endif
	ret = nf_conntrack_proto_init();
	if (ret < 0)
		goto err_proto;

	/* Set up fake conntrack: to never be deleted, not in any hashes */
	for_each_possible_cpu(cpu) {
		struct nf_conn *ct = &per_cpu(nf_conntrack_untracked, cpu);
		write_pnet(&ct->ct_net, &init_net);
		atomic_set(&ct->ct_general.use, 1);
	}
	/*  - and look it like as a confirmed connection */
	nf_ct_untracked_status_or(IPS_CONFIRMED | IPS_UNTRACKED);
	return 0;

err_proto:
#ifdef CONFIG_NF_CONNTRACK_ZONES
	nf_ct_extend_unregister(&nf_ct_zone_extend);
err_extend:
#endif
	nf_conntrack_seqadj_fini();
err_seqadj:
	nf_conntrack_labels_fini();
err_labels:
	nf_conntrack_helper_fini();
err_helper:
	nf_conntrack_timeout_fini();
err_timeout:
	nf_conntrack_ecache_fini();
err_ecache:
	nf_conntrack_tstamp_fini();
err_tstamp:
	nf_conntrack_acct_fini();
err_acct:
	nf_conntrack_expect_fini();
err_expect:
	return ret;
}

void nf_conntrack_init_end(void)
{
	/* For use by REJECT target */
	RCU_INIT_POINTER(ip_ct_attach, nf_conntrack_attach);
	RCU_INIT_POINTER(nf_ct_destroy, destroy_conntrack);
}

/*
 * We need to use special "null" values, not used in hash table
 */
#define UNCONFIRMED_NULLS_VAL	((1<<30)+0)
#define DYING_NULLS_VAL		((1<<30)+1)
#define TEMPLATE_NULLS_VAL	((1<<30)+2)

int nf_conntrack_init_net(struct net *net)
{
	int ret = -ENOMEM;
	int cpu;

	atomic_set(&net->ct.count, 0);
	seqcount_init(&net->ct.generation);

	net->ct.pcpu_lists = alloc_percpu(struct ct_pcpu);
	if (!net->ct.pcpu_lists)
		goto err_stat;

	for_each_possible_cpu(cpu) {
		struct ct_pcpu *pcpu = per_cpu_ptr(net->ct.pcpu_lists, cpu);

		spin_lock_init(&pcpu->lock);
		INIT_HLIST_NULLS_HEAD(&pcpu->unconfirmed, UNCONFIRMED_NULLS_VAL);
		INIT_HLIST_NULLS_HEAD(&pcpu->dying, DYING_NULLS_VAL);
		INIT_HLIST_NULLS_HEAD(&pcpu->tmpl, TEMPLATE_NULLS_VAL);
	}

	net->ct.stat = alloc_percpu(struct ip_conntrack_stat);
	if (!net->ct.stat)
		goto err_pcpu_lists;

	net->ct.slabname = kasprintf(GFP_KERNEL, "nf_conntrack_%p", net);
	if (!net->ct.slabname)
		goto err_slabname;

	net->ct.nf_conntrack_cachep = kmem_cache_create(net->ct.slabname,
							sizeof(struct nf_conn), 0,
							SLAB_DESTROY_BY_RCU, NULL);
	if (!net->ct.nf_conntrack_cachep) {
		printk(KERN_ERR "Unable to create nf_conn slab cache\n");
		goto err_cache;
	}

	net->ct.htable_size = nf_conntrack_htable_size;
	net->ct.hash = nf_ct_alloc_hashtable(&net->ct.htable_size, 1);
	if (!net->ct.hash) {
		printk(KERN_ERR "Unable to create nf_conntrack_hash\n");
		goto err_hash;
	}
	ret = nf_conntrack_expect_pernet_init(net);
	if (ret < 0)
		goto err_expect;
	ret = nf_conntrack_acct_pernet_init(net);
	if (ret < 0)
		goto err_acct;
	ret = nf_conntrack_tstamp_pernet_init(net);
	if (ret < 0)
		goto err_tstamp;
	ret = nf_conntrack_ecache_pernet_init(net);
	if (ret < 0)
		goto err_ecache;
	ret = nf_conntrack_helper_pernet_init(net);
	if (ret < 0)
		goto err_helper;
	ret = nf_conntrack_proto_pernet_init(net);
	if (ret < 0)
		goto err_proto;
	return 0;

err_proto:
	nf_conntrack_helper_pernet_fini(net);
err_helper:
	nf_conntrack_ecache_pernet_fini(net);
err_ecache:
	nf_conntrack_tstamp_pernet_fini(net);
err_tstamp:
	nf_conntrack_acct_pernet_fini(net);
err_acct:
	nf_conntrack_expect_pernet_fini(net);
err_expect:
	nf_ct_free_hashtable(net->ct.hash, net->ct.htable_size);
err_hash:
	kmem_cache_destroy(net->ct.nf_conntrack_cachep);
err_cache:
	kfree(net->ct.slabname);
err_slabname:
	free_percpu(net->ct.stat);
err_pcpu_lists:
	free_percpu(net->ct.pcpu_lists);
err_stat:
	return ret;
}
