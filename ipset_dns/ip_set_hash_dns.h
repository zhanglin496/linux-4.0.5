/* Copyright (C) 2013 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _IP_SET_HASH_GEN_H
#define _IP_SET_HASH_GEN_H

#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <linux/netfilter/ipset/ip_set_timeout.h>
#include <linux/list.h>
#ifndef rcu_dereference_bh
#define rcu_dereference_bh(p)	rcu_dereference(p)
#endif

#define CONCAT(a, b)		a##b
#define TOKEN(a, b)		CONCAT(a, b)

/* Hashing which uses arrays to resolve clashing. The hash table is resized
 * (doubled) when searching becomes too long.
 * Internally jhash is used with the assumption that the size of the
 * stored data is a multiple of sizeof(u32). If storage supports timeout,
 * the timeout field must be the last one in the data structure - that field
 * is ignored when computing the hash key.
 *
 * Readers and resizing
 *
 * Resizing can be triggered by userspace command only, and those
 * are serialized by the nfnl mutex. During resizing the set is
 * read-locked, so the only possible concurrent operations are
 * the kernel side readers. Those must be protected by proper RCU locking.
 */

/* Number of elements to store in an initial array block */
#define AHASH_INIT_SIZE			4
/* Max number of elements to store in an array block */
#define AHASH_MAX_SIZE			(3*AHASH_INIT_SIZE)

#define AHASH_MAX(h)			AHASH_MAX_SIZE
#define TUNE_AHASH_MAX(h, multi)

/* The hash table: the table size stored here in order to make resizing easy */
struct htable {
	u32 htable_size;
	u32 elements_size;
	struct hlist_head bucket[0];
};

#define hbucket(h, i)		(&((h)->bucket[i]))

#define NETS_LENGTH(family)	0

#define ext_timeout(e, h)	\
(unsigned long *)(((void *)(e)) + (h)->offset[IPSET_OFFSET_TIMEOUT])
#define ext_counter(e, h)	\
(struct ip_set_counter *)(((void *)(e)) + (h)->offset[IPSET_OFFSET_COUNTER])

#endif /* _IP_SET_HASH_GEN_H */


/* Family dependent templates */

#undef ahash_data
#undef mtype_data_equal
#undef mtype_do_data_match
#undef mtype_data_set_flags
#undef mtype_data_reset_flags
#undef mtype_data_netmask
#undef mtype_data_list
#undef mtype_data_next
#undef mtype_elem

#undef mtype_add_cidr
#undef mtype_del_cidr
#undef mtype_ahash_memsize
#undef mtype_flush
#undef mtype_destroy
#undef mtype_gc_init
#undef mtype_same_set
#undef mtype_kadt
#undef mtype_uadt
#undef mtype

#undef mtype_add
#undef mtype_del
#undef mtype_test_cidrs
#undef mtype_test
#undef mtype_expire
#undef mtype_resize
#undef mtype_head
#undef mtype_list
#undef mtype_gc
#undef mtype_gc_init
#undef mtype_variant
#undef mtype_data_match

#undef HKEY

#define mtype_data_equal	TOKEN(MTYPE, _data_equal)
#define mtype_do_data_match	TOKEN(MTYPE, _do_data_match)
#define mtype_data_set_flags	TOKEN(MTYPE, _data_set_flags)
#define mtype_data_reset_flags	TOKEN(MTYPE, _data_reset_flags)
#define mtype_data_netmask	TOKEN(MTYPE, _data_netmask)
#define mtype_data_list		TOKEN(MTYPE, _data_list)
#define mtype_data_next		TOKEN(MTYPE, _data_next)
#define mtype_elem		TOKEN(MTYPE, _elem)
#define mtype_add_cidr		TOKEN(MTYPE, _add_cidr)
#define mtype_del_cidr		TOKEN(MTYPE, _del_cidr)
#define mtype_ahash_memsize	TOKEN(MTYPE, _ahash_memsize)
#define mtype_flush		TOKEN(MTYPE, _flush)
#define mtype_destroy		TOKEN(MTYPE, _destroy)
#define mtype_gc_init		TOKEN(MTYPE, _gc_init)
#define mtype_same_set		TOKEN(MTYPE, _same_set)
#define mtype_kadt		TOKEN(MTYPE, _kadt)
#define mtype_uadt		TOKEN(MTYPE, _uadt)
#define mtype			MTYPE

#define mtype_elem		TOKEN(MTYPE, _elem)
#define mtype_add		TOKEN(MTYPE, _add)
#define mtype_del		TOKEN(MTYPE, _del)
#define mtype_test_cidrs	TOKEN(MTYPE, _test_cidrs)
#define mtype_test		TOKEN(MTYPE, _test)
#define mtype_expire		TOKEN(MTYPE, _expire)
#define mtype_resize		TOKEN(MTYPE, _resize)
#define mtype_head		TOKEN(MTYPE, _head)
#define mtype_list		TOKEN(MTYPE, _list)
#define mtype_gc		TOKEN(MTYPE, _gc)
#define mtype_variant		TOKEN(MTYPE, _variant)
#define mtype_data_match	TOKEN(MTYPE, _data_match)

#ifndef HKEY_DATALEN
#define HKEY_DATALEN		sizeof(struct mtype_elem)
#endif

#define HKEY(d, h, htable_size)			\
(jhash((void *)d + d->offset, d->len, h->initval) & (htable_size - 1))

#ifndef htype
#define htype			HTYPE

/* The generic hash structure */
struct htype {
	struct htable *table;	/* the hash table */
	u32 maxelem;		/* max elements in the hash */
	u32 elements;		/* current element (vs timeout) */
	u32 initval;		/* random jhash init value */
	u32 timeout;		/* timeout value, if enabled */
	size_t dsize;		/* data struct size */
	size_t offset[IPSET_OFFSET_MAX]; /* Offsets to extensions */
	struct timer_list gc;	/* garbage collection when timeout enabled */
};
#endif

/* Destroy the hashtable part of the set */
static void
ahash_destroy(struct htable *t)
{
	struct hlist_head *n;
	struct hlist_node *tmp;
	struct mtype_elem *e;
	u32 i;

	for (i = 0; i < t->htable_size; i++) {
		n = hbucket(t, i);
		hlist_for_each_entry_safe(e, tmp, n, node) {
			hlist_del(&e->node);
			kfree(e);
		}
	}

	ip_set_free(t);
}

/* Calculate the actual memory size of the set data */
static size_t
mtype_ahash_memsize(const struct htype *h, u8 nets_length)
{
	struct htable *t = h->table;
	size_t memsize = sizeof(*h)
			 + sizeof(*t)
			 + sizeof(struct hlist_head) * t->htable_size;

	return memsize + t->elements_size;
}

/* Flush a hash type of set: destroy all elements */
static void
mtype_flush(struct ip_set *set)
{
	struct htype *h = set->data;
	struct htable *t = h->table;
	struct hlist_head *n;
	struct hlist_node *tmp;
	struct mtype_elem *e;
	u32 i;

	for (i = 0; i < t->htable_size; i++) {
		n = hbucket(t, i);
		hlist_for_each_entry_safe(e, tmp, n, node) {
			hlist_del(&e->node);
			kfree(e);
		}
	}
	t->elements_size = 0;
	h->elements = 0;
}

/* Destroy a hash type of set */
static void
mtype_destroy(struct ip_set *set)
{
	struct htype *h = set->data;

	if (set->extensions & IPSET_EXT_TIMEOUT)
		del_timer_sync(&h->gc);

	ahash_destroy(h->table);
	kfree(h);

	set->data = NULL;
}

static void
mtype_gc_init(struct ip_set *set, void (*gc)(unsigned long ul_set))
{
	struct htype *h = set->data;

	init_timer(&h->gc);
	h->gc.data = (unsigned long) set;
	h->gc.function = gc;
	h->gc.expires = jiffies + IPSET_GC_PERIOD(h->timeout) < 30 ? 30 * HZ : IPSET_GC_PERIOD(h->timeout) * HZ;
	add_timer(&h->gc);
	pr_debug("gc initialized, run in every %u\n",
		 IPSET_GC_PERIOD(h->timeout));
}

static bool
mtype_same_set(const struct ip_set *a, const struct ip_set *b)
{
	const struct htype *x = a->data;
	const struct htype *y = b->data;

	/* Resizing changes htable_bits, so we ignore it */
	return x->maxelem == y->maxelem &&
	       x->timeout == y->timeout &&
	       a->extensions == b->extensions;
}

/* Get the ith element from the array block n */
#define ahash_data(n, i, dsize)	\
	((struct mtype_elem *)((n)->value + ((i) * (dsize))))

/* Delete expired elements from the hashtable */
static void
mtype_expire(struct htype *h, u8 nets_length, size_t dsize)
{
	struct htable *t = h->table;
	struct hlist_head *n;
	struct hlist_node *tmp;
	struct mtype_elem *data;
	u32 i;

	for (i = 0; i < t->htable_size; i++) {
		n = hbucket(t, i);
		hlist_for_each_entry_safe(data, tmp, n, node) {
			if (ip_set_timeout_expired(ext_timeout(data, h))) {
				hlist_del(&data->node);
				h->elements--;
				t->elements_size -= h->dsize + data->len + data->free;
				kfree(data);
			}
		}
	}
}

static void
mtype_gc(unsigned long ul_set)
{
	struct ip_set *set = (struct ip_set *) ul_set;
	struct htype *h = set->data;

	pr_debug("called\n");
	write_lock_bh(&set->lock);
	mtype_expire(h, NETS_LENGTH(set->family), h->dsize);
	write_unlock_bh(&set->lock);

	h->gc.expires = jiffies + IPSET_GC_PERIOD(h->timeout) * HZ;
	add_timer(&h->gc);
}

/* Resize a hash: create a new hash table with doubling the hashsize
 * and inserting the elements to it. Repeat until we succeed or
 * fail due to memory pressures. */
static int
mtype_resize(struct ip_set *set, bool retried)
{
	return -1;
}

/* Add an element to a hash and update the internal counters when succeeded,
 * otherwise report the proper error code. */
static int
mtype_add(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t;
	struct mtype_elem *d = value;
	struct mtype_elem *data;
	struct hlist_head *n;
	struct hlist_node *tmp;
	int ret = 0;
	bool flag_exist = flags & IPSET_FLAG_EXIST;
	bool new_elem = true;
	u32 key, multi = 0;

	if (SET_WITH_TIMEOUT(set) && h->elements >= h->maxelem)
		/* FIXME: when set is full, we slow down here */
		mtype_expire(h, NETS_LENGTH(set->family), h->dsize);

	if (h->elements >= h->maxelem) {
		if (net_ratelimit())
			pr_warning("Set %s is full, maxelem %u reached\n",
				   set->name, h->maxelem);
		return -IPSET_ERR_HASH_FULL;
	}

	rcu_read_lock_bh();
	t = rcu_dereference_bh(h->table);
	d->len--;
	key = HKEY(d, h, t->htable_size);
	n = hbucket(t, key);

	hlist_for_each_entry_safe(data, tmp, n, node) {
		if (mtype_data_equal(d, data, &multi)) {
			if (flag_exist ||
			    (SET_WITH_TIMEOUT(set) &&
				ip_set_timeout_expired(ext_timeout(data, h)))) {
				new_elem = false;
				break;
			} else {
				ret = -IPSET_ERR_EXIST;
				goto out;
			}
		} else if (SET_WITH_TIMEOUT(set) &&
				ip_set_timeout_expired(ext_timeout(data, h))) {
			hlist_del(&data->node);
			/*free the timeout node */
			t->elements_size -= h->dsize + data->len + data->free;
			h->elements--;
			kfree(data);
			#if 0
			// must check the same node is eexist, so can't reuse the node
			hlist_del(&data->node);
			if (d->len <= data->len + data->free) {
				/*reuse the node */
				memcpy((void *)data + data->offset, (void *)d + d->offset, d->len);				
				data->free = data->len + data->free - d->len;
				data->len = d->len;
				((uint8_t *)data)[data->offset+data->len] = '\0';
				new_elem = true;
				break;
			} else {
				/*free the timeout node */
				t->elements_size -= h->dsize + data->len + data->free;
				h->elements--;
				kfree(data);
			}
			#endif
		}
	}

	if (new_elem) {
		data = kzalloc(h->dsize + d->len + 1, GFP_ATOMIC);
		if (!data) {
			ret = -ENOMEM;
			goto out;
		}
		data->len = d->len;
		data->offset = h->dsize;
		memcpy((void *)data + data->offset, (void *)d + d->offset, d->len);		
		t->elements_size += h->dsize + d->len;
		h->elements++;
	}

	data->dns_match = d->dns_match;
	mtype_data_set_flags(data, flags);

	if (SET_WITH_TIMEOUT(set))
		ip_set_timeout_set(ext_timeout(data, h), ext->timeout);
	if (SET_WITH_COUNTER(set))
		ip_set_init_counter(ext_counter(data, h), ext);
	if (new_elem) {
		key = HKEY(data, h, t->htable_size);
		n = hbucket(t, key);
		hlist_add_head(&data->node, n);
	}

out:
	rcu_read_unlock_bh();
	return ret;
}

/* Delete an element from the hash: swap it with the last element
 * and free up space if possible.
 */
static int
mtype_del(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	  struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t = h->table;
	struct mtype_elem *d = value;
	struct mtype_elem *data;
	struct hlist_head *n;
	u32 key, multi = 0;

	d->len--;
	key = HKEY(d, h, t->htable_size);
	n = hbucket(t, key);

	hlist_for_each_entry(data, n, node) {
		if (!mtype_data_equal(d, data, &multi))
			continue;		
		if (SET_WITH_TIMEOUT(set) &&
		    ip_set_timeout_expired(ext_timeout(data, h)))
			return -IPSET_ERR_EXIST;
		hlist_del(&data->node);
		kfree(data);
		return 0;
	}

	return -IPSET_ERR_EXIST;
}

static inline int
mtype_data_match(struct mtype_elem *data, const struct ip_set_ext *ext,
		 struct ip_set_ext *mext, struct ip_set *set, u32 flags)
{
	if (SET_WITH_COUNTER(set))
		ip_set_update_counter(ext_counter(data,
						  (struct htype *)(set->data)),
				      ext, mext, flags);
	return mtype_do_data_match(data);
}

#if 0
/* Test whether the element is added to the set */
static int
mtype_test(struct ip_set *set, void *value, const struct ip_set_ext *ext,
	   struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t = h->table;
	struct mtype_elem *d = value;
	struct hlist_head *n;
	struct mtype_elem *data;
	u32 key, multi = 0;

	key = HKEY(d, h, t->htable_size);
	n = hbucket(t, key);

	hlist_for_each_entry(data, n, node) {
		if (mtype_data_equal(d, data, &multi) &&
		    !(SET_WITH_TIMEOUT(set) &&
		      ip_set_timeout_expired(ext_timeout(data, h))))
			return mtype_data_match(data, ext, mext, set, flags);		
	}

	return 0;
}
#endif

#define mtype_test_wildcard mtype_test
/* Test whether the element is added to the set */
static int
mtype_test_wildcard(struct ip_set *set, void *value, const struct ip_set_ext *ext,
           struct ip_set_ext *mext, u32 flags)
{
	struct htype *h = set->data;
	struct htable *t = h->table;
	struct mtype_elem *d = value;
	struct hlist_head *n;
	struct mtype_elem *data, *data2 = NULL;
	u32 key, multi = 0;
	uint8_t len;
	int i;
	size_t offset = d->offset;
	u32 dlen = d->len - 1;
	int ret = 0;

	d->dns_match = DNS_COMPLETE_MATCH;
	for (i = 0; i < dlen; i++) {
		d->offset = offset + i;
		d->len = dlen - i;
		key = HKEY(d, h, t->htable_size);
		n = hbucket(t, key);

		hlist_for_each_entry(data, n, node) {
			if (mtype_data_equal(d, data, &multi) &&
				!(SET_WITH_TIMEOUT(set) &&
				ip_set_timeout_expired(ext_timeout(data, h)))) {			
				return mtype_data_match(data, ext, mext, set, flags);
			}
		}
		len = ((uint8_t *)d)[d->offset];;
		if (!len || len > 63)
			return 0;
		if (!i)
			d->dns_match = DNS_PREFIX_MATCH;
		i += len;
	}

	d->offset = offset;
	d->len = dlen;
	d->dns_match = DNS_SUFFIX_MATCH;
	for (i = 0; i < dlen;) {
		len = ((uint8_t *)d)[d->offset + i];;
		if (!len || len > 63)
			break;
		i += len + 1;
		d->len = i;
		if (d->len > dlen)
			break;
		key = HKEY(d, h, t->htable_size);
		n = hbucket(t, key);

		hlist_for_each_entry(data, n, node) {
			if (mtype_data_equal(d, data, &multi) &&
				!(SET_WITH_TIMEOUT(set) &&
				ip_set_timeout_expired(ext_timeout(data, h)))) {
				data2 = data;
				//ret = mtype_data_match(data, ext, mext, set, flags);
				break;
			}
		}
	}

	if (data2)
		ret = mtype_data_match(data2, ext, mext, set, flags);
	return ret;
}

/* Reply a HEADER request: fill out the header part of the set */
static int
mtype_head(struct ip_set *set, struct sk_buff *skb)
{
	const struct htype *h = set->data;
	struct nlattr *nested;
	size_t memsize;

	read_lock_bh(&set->lock);
	memsize = mtype_ahash_memsize(h, NETS_LENGTH(set->family));
	read_unlock_bh(&set->lock);

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	if (nla_put_net32(skb, IPSET_ATTR_HASHSIZE,
			  htonl(h->table->htable_size)) ||
	    nla_put_net32(skb, IPSET_ATTR_MAXELEM, htonl(h->maxelem)))
		goto nla_put_failure;

	if (nla_put_net32(skb, IPSET_ATTR_REFERENCES, htonl(set->ref - 1)) ||
	    nla_put_net32(skb, IPSET_ATTR_MEMSIZE, htonl(memsize)) ||
	    ((set->extensions & IPSET_EXT_TIMEOUT) &&
	     nla_put_net32(skb, IPSET_ATTR_TIMEOUT, htonl(h->timeout))) ||
	    ((set->extensions & IPSET_EXT_COUNTER) &&
	     nla_put_net32(skb, IPSET_ATTR_CADT_FLAGS,
			   htonl(IPSET_FLAG_WITH_COUNTERS))))
		goto nla_put_failure;
	ipset_nest_end(skb, nested);

	return 0;
nla_put_failure:
	return -EMSGSIZE;
}

/* Reply a LIST/SAVE request: dump the elements of the specified set */
static int
mtype_list(const struct ip_set *set,
	   struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct htype *h = set->data;
	const struct htable *t = h->table;
	struct nlattr *atd, *nested;
	const struct hlist_head *n;
	const struct mtype_elem *e;
	u32 first = cb->args[2];
	/* We assume that one hash bucket fills into one page */
	void *incomplete;

	atd = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!atd)
		return -EMSGSIZE;
	pr_debug("list hash set %s\n", set->name);

	for (; cb->args[2] < t->htable_size; cb->args[2]++) {
		incomplete = skb_tail_pointer(skb);
		n = hbucket(t, cb->args[2]);
		pr_debug("cb->args[2]: %lu, t %p n %p\n", cb->args[2], t, n);

		hlist_for_each_entry(e, n, node) {
			if (SET_WITH_TIMEOUT(set) &&
				ip_set_timeout_expired(ext_timeout(e, h)))
				continue;
			nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
			if (!nested) {
				if (cb->args[2] == first) {
					nla_nest_cancel(skb, atd);
					return -EMSGSIZE;
				} else
					goto nla_put_failure;
			}
			if (mtype_data_list(skb, e))
				goto nla_put_failure;
			if (SET_WITH_TIMEOUT(set) &&
				nla_put_net32(skb, IPSET_ATTR_TIMEOUT,
					  htonl(ip_set_timeout_get(
						ext_timeout(e, h)))))
				goto nla_put_failure;
			if (SET_WITH_COUNTER(set) &&
				ip_set_put_counter(skb, ext_counter(e, h)))
				goto nla_put_failure;
			ipset_nest_end(skb, nested);
		}
	}
	ipset_nest_end(skb, atd);
	/* Set listing finished */
	cb->args[2] = 0;

	return 0;

nla_put_failure:
	nlmsg_trim(skb, incomplete);
	ipset_nest_end(skb, atd);
	if (unlikely(first == cb->args[2])) {
		pr_warning("Can't list set %s: one bucket does not fit into "
			   "a message. Please report it!\n", set->name);
		cb->args[2] = 0;
		return -EMSGSIZE;
	}
	return 0;
}

static int
TOKEN(MTYPE, _kadt)(struct ip_set *set, const struct sk_buff *skb,
	      const struct xt_action_param *par,
	      enum ipset_adt adt, struct ip_set_adt_opt *opt);

static int
TOKEN(MTYPE, _uadt)(struct ip_set *set, struct nlattr *tb[],
	      enum ipset_adt adt, u32 *lineno, u32 flags, bool retried);

static const struct ip_set_type_variant mtype_variant = {
	.kadt	= mtype_kadt,
	.uadt	= mtype_uadt,
	.adt	= {
		[IPSET_ADD] = mtype_add,
		[IPSET_DEL] = mtype_del,
		[IPSET_TEST] = mtype_test,
	},
	.destroy = mtype_destroy,
	.flush	= mtype_flush,
	.head	= mtype_head,
	.list	= mtype_list,
	.resize	= mtype_resize,
	.same_set = mtype_same_set,
};

static int
TOKEN(HTYPE, _create)(struct ip_set *set, struct nlattr *tb[], u32 flags)
{
	u32 hashsize = IPSET_DEFAULT_HASHSIZE, maxelem = IPSET_DEFAULT_MAXELEM;
	u32 cadt_flags = 0;
	u32 i;
	size_t hsize;
	struct HTYPE *h;

	if (!(set->family == NFPROTO_IPV4 || set->family == NFPROTO_IPV6))
		return -IPSET_ERR_INVALID_FAMILY;

	if (unlikely(!ip_set_optattr_netorder(tb, IPSET_ATTR_HASHSIZE) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_MAXELEM) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS)))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_HASHSIZE]) {
		hashsize = ip_set_get_h32(tb[IPSET_ATTR_HASHSIZE]);
		if (hashsize < IPSET_MIMINAL_HASHSIZE)
			hashsize = IPSET_MIMINAL_HASHSIZE;
	}

	if (tb[IPSET_ATTR_MAXELEM])
		maxelem = ip_set_get_h32(tb[IPSET_ATTR_MAXELEM]);

	hsize = sizeof(*h);
	h = kzalloc(hsize, GFP_KERNEL);
	if (!h)
		return -ENOMEM;

	h->maxelem = maxelem;
	get_random_bytes(&h->initval, sizeof(h->initval));
	h->timeout = IPSET_NO_TIMEOUT;

	h->table = kzalloc(sizeof(*h->table) + hashsize * sizeof(struct hlist_head), GFP_KERNEL);
	if (!h->table) {
		kfree(h);
		return -ENOMEM;
	}

	for (i = 0; i < hashsize; i++)
		INIT_HLIST_HEAD(&h->table->bucket[i]);

	h->table->htable_size = hashsize;
	h->table->elements_size = 0;
	set->data = h;
	set->variant = &TOKEN(HTYPE, _variant);

	if (tb[IPSET_ATTR_CADT_FLAGS])
		cadt_flags = ip_set_get_h32(tb[IPSET_ATTR_CADT_FLAGS]);

	h->dsize = sizeof(struct TOKEN(HTYPE, _elem));

	if (cadt_flags & IPSET_FLAG_WITH_COUNTERS) {
		set->extensions |= IPSET_EXT_COUNTER;
		h->offset[IPSET_OFFSET_COUNTER] = h->dsize;
		h->dsize += ALIGN(sizeof(struct ip_set_counter), __alignof__(struct ip_set_counter));
	}

 	if (tb[IPSET_ATTR_TIMEOUT]) {
		h->timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
		set->extensions |= IPSET_EXT_TIMEOUT;
		h->offset[IPSET_OFFSET_TIMEOUT] = h->dsize;
		h->dsize += ALIGN(sizeof(unsigned long), __alignof__(unsigned long));
		TOKEN(HTYPE, _gc_init)(set, TOKEN(HTYPE, _gc));
	}
	h->dsize = ALIGN(h->dsize, __alignof__(unsigned long));

	pr_debug("create %s hashsize %u maxelem %u: %p(%p)\n",
		 set->name, h->table->htable_size,
 			h->maxelem, set->data, h->table);

	return 0;
}
