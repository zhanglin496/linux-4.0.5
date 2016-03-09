/* Structure dynamic extension infrastructure
 * Copyright (C) 2004 Rusty Russell IBM Corporation
 * Copyright (C) 2007 Netfilter Core Team <coreteam@netfilter.org>
 * Copyright (C) 2007 USAGI/WIDE Project <http://www.linux-ipv6.org>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack_extend.h>

static struct nf_ct_ext_type __rcu *nf_ct_ext_types[NF_CT_EXT_NUM];
static DEFINE_MUTEX(nf_ct_ext_type_mutex);

void __nf_ct_ext_destroy(struct nf_conn *ct)
{
	unsigned int i;
	struct nf_ct_ext_type *t;
	struct nf_ct_ext *ext = ct->ext;

	for (i = 0; i < NF_CT_EXT_NUM; i++) {
		if (!__nf_ct_ext_exist(ext, i))
			continue;

		rcu_read_lock();
		t = rcu_dereference(nf_ct_ext_types[i]);

		/* Here the nf_ct_ext_type might have been unregisterd.
		 * I.e., it has responsible to cleanup private
		 * area in all conntracks when it is unregisterd.
		 */
		 
		//如果ext在调用__nf_ct_ext_destroy之前被注销，则由注销操作来释放所有
		//conntrack跟扩展相关的资源，在大量conntrack的情况下
		//实际上最好不要动态注销，否则需要遍历所有的conntrack
		//但是如果该扩展的destroy函数和move函数为空的情况下
		//动态注销没有问题
		if (t && t->destroy)
			t->destroy(ct);
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(__nf_ct_ext_destroy);

static void *
nf_ct_ext_create(struct nf_ct_ext **ext, enum nf_ct_ext_id id,
		 size_t var_alloc_len, gfp_t gfp)
{
	unsigned int off, len;
	struct nf_ct_ext_type *t;
	size_t alloc_size;

	rcu_read_lock();
	t = rcu_dereference(nf_ct_ext_types[id]);
	BUG_ON(t == NULL);
	off = ALIGN(sizeof(struct nf_ct_ext), t->align);
	len = off + t->len + var_alloc_len;
	alloc_size = t->alloc_size + var_alloc_len;
	rcu_read_unlock();

	*ext = kzalloc(alloc_size, gfp);
	if (!*ext)
		return NULL;

	(*ext)->offset[id] = off;
	(*ext)->len = len;

	return (void *)(*ext) + off;
}

void *__nf_ct_ext_add_length(struct nf_conn *ct, enum nf_ct_ext_id id,
			     size_t var_alloc_len, gfp_t gfp)
{
	struct nf_ct_ext *old, *new;
	int i, newlen, newoff;
	struct nf_ct_ext_type *t;

	/* Conntrack must not be confirmed to avoid races on reallocation. */
	NF_CT_ASSERT(!nf_ct_is_confirmed(ct));

	old = ct->ext;
	if (!old)
		return nf_ct_ext_create(&ct->ext, id, var_alloc_len, gfp);

	if (__nf_ct_ext_exist(old, id))
		return NULL;

	rcu_read_lock();
	t = rcu_dereference(nf_ct_ext_types[id]);
	BUG_ON(t == NULL);

	newoff = ALIGN(old->len, t->align);
	newlen = newoff + t->len + var_alloc_len;
	rcu_read_unlock();

	new = __krealloc(old, newlen, gfp);
	if (!new)
		return NULL;

	if (new != old) {
		for (i = 0; i < NF_CT_EXT_NUM; i++) {
			if (!__nf_ct_ext_exist(old, i))
				continue;

			rcu_read_lock();
			t = rcu_dereference(nf_ct_ext_types[i]);
			if (t && t->move)
				t->move((void *)new + new->offset[i],
					(void *)old + old->offset[i]);
			rcu_read_unlock();
		}
		kfree_rcu(old, rcu);
		ct->ext = new;
	}

	new->offset[id] = newoff;
	new->len = newlen;
	//清零新分配的扩展区
	memset((void *)new + newoff, 0, newlen - newoff);
	return (void *)new + newoff;
}
EXPORT_SYMBOL(__nf_ct_ext_add_length);

static void update_alloc_size(struct nf_ct_ext_type *type)
{
	int i, j;
	struct nf_ct_ext_type *t1, *t2;
	enum nf_ct_ext_id min = 0, max = NF_CT_EXT_NUM - 1;

	/* unnecessary to update all types */
	//如果没指定NF_CT_EXT_F_PREALLOC
	//则不需要更新所有已经注册type的alloc_size大小，但是可能会更新自身的alloc_size，
	//因为之前注册的type可能设置了标志NF_CT_EXT_F_PREALLOC，所以需要重新计算大小
	//如果指定了标志NF_CT_EXT_F_PREALLOC，则会更新所有已注册type的alloc_size，在添加扩展的时候，
	//就会一次性分配包含NF_CT_EXT_F_PREALLOC标志type所需总的扩展空间，
	//这样添加扩展的时候就不需要再重新分配空间，因为空间已经提前分配好了，
	//好处是可以避免realloc，坏处是可能会浪费空间
	if ((type->flags & NF_CT_EXT_F_PREALLOC) == 0) {
		min = type->id;
		max = type->id;
	}

	/* This assumes that extended areas in conntrack for the types
	   whose NF_CT_EXT_F_PREALLOC bit set are allocated in order */
	for (i = min; i <= max; i++) {
		t1 = rcu_dereference_protected(nf_ct_ext_types[i],
				lockdep_is_held(&nf_ct_ext_type_mutex));
		//可能扩展类型还没有注册
		if (!t1)
			continue;

		t1->alloc_size = ALIGN(sizeof(struct nf_ct_ext), t1->align) +
				 t1->len;
				 
		//遍历所用已注册的扩展
		for (j = 0; j < NF_CT_EXT_NUM; j++) {
			t2 = rcu_dereference_protected(nf_ct_ext_types[j],
				lockdep_is_held(&nf_ct_ext_type_mutex));
			//t2没设置NF_CT_EXT_F_PREALLOC标志，就不会更新alloc_size
			//目前只有nat_extend设置了该标志
			//注意t2==t1的情况下是不能更新alloc_size
			//NF_CT_EXT_F_PREALLOC的目的是在分配其他类型的扩展时，把当前注册的空间包含进去
			//假设有t1、t2、t3三个类型，只有t3设置了NF_CT_EXT_F_PREALLOC，
			//那么分配t1或t2时会吧t3的空间包含进去，但是分配t3时只包含t3自身的大小
			//但是如果t1、t2也设置了NF_CT_EXT_F_PREALLOC，
			//则三个类型的alloc_size大小都为（t1+t2+t3）
			//如果t1、t2设置而t3没设置NF_CT_EXT_F_PREALLOC
			//那么t1=(t1+t2),t2=(t2+t1),t3=(t3+t1+t2)
			//也就是说扩展的alloc_size为自身加上其他设置了NF_CT_EXT_F_PREALLOC的扩展大小
			if (t2 == NULL || t2 == t1 ||
			    (t2->flags & NF_CT_EXT_F_PREALLOC) == 0)
				continue;
			//如果t2设置了NF_CT_EXT_F_PREALLOC标志，则需要更新t1的alloc_size
			//累计需要分配的总大小到t1中
			t1->alloc_size = ALIGN(t1->alloc_size, t2->align)
					 + t2->len;
		}
	}
}

/* This MUST be called in process context. */
int nf_ct_extend_register(struct nf_ct_ext_type *type)
{
	int ret = 0;

	mutex_lock(&nf_ct_ext_type_mutex);
	if (nf_ct_ext_types[type->id]) {
		ret = -EBUSY;
		goto out;
	}

	/* This ensures that nf_ct_ext_create() can allocate enough area
	   before updating alloc_size */
	type->alloc_size = ALIGN(sizeof(struct nf_ct_ext), type->align)
			   + type->len;
	rcu_assign_pointer(nf_ct_ext_types[type->id], type);
	update_alloc_size(type);
out:
	mutex_unlock(&nf_ct_ext_type_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_extend_register);

/* This MUST be called in process context. */
void nf_ct_extend_unregister(struct nf_ct_ext_type *type)
{
	mutex_lock(&nf_ct_ext_type_mutex);
	RCU_INIT_POINTER(nf_ct_ext_types[type->id], NULL);
	update_alloc_size(type);
	mutex_unlock(&nf_ct_ext_type_mutex);
	rcu_barrier(); /* Wait for completion of call_rcu()'s */
}
EXPORT_SYMBOL_GPL(nf_ct_extend_unregister);
