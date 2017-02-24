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
		 
		//Èç¹ûextÔÚµ÷ÓÃ__nf_ct_ext_destroyÖ®Ç°±»×¢Ïú£¬ÔòÓÉ×¢Ïú²Ù×÷À´ÊÍ·ÅËùÓÐ
		//conntrack¸úÀ©Õ¹Ïà¹ØµÄ×ÊÔ´£¬ÔÚ´óÁ¿conntrackµÄÇé¿öÏÂ
		//Êµ¼ÊÉÏ×îºÃ²»Òª¶¯Ì¬×¢Ïú£¬·ñÔòÐèÒª±éÀúËùÓÐµÄconntrack
		//µ«ÊÇÈç¹û¸ÃÀ©Õ¹µÄdestroyº¯ÊýºÍmoveº¯ÊýÎª¿ÕµÄÇé¿öÏÂ
		//¶¯Ì¬×¢ÏúÃ»ÓÐÎÊÌâ
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
	
	//Î´È·ÈÏ×´Ì¬Ê±
	//Ö»¿ÉÄÜÓÐÒ»¸öskbÒýÓÃÕß£¬²»»á³öÏÖ¾ºÕù
	//Èô¹ûconntrackÒÑ¾­±»È·ÈÏ£¬Ôò²»ÄÜÔÙÌí¼ÓÐÂµÄÀ©Õ¹Çø
	//ÒòÎª±ê×¼ÄÚºËÔÚ·ÖÅäÀ©Õ¹ÇøÊ±²¢Ã»ÓÐ¼ÓËø
	/* Conntrack must not be confirmed to avoid races on reallocation. */
	NF_CT_ASSERT(!nf_ct_is_confirmed(ct));
	
	//var_alloc_lenÖ¸¶¨ÔÚ¾²Ì¬×¢²áÊ±µÄ¹Ì¶¨³¤¶ÈµÄ»ù´¡ÉÏ
	//ÐèÒª·ÖÅäµÄ¶îÍâ³¤¶È£¬±ÈÈçnf_ct_helper_ext_addÓÃµ½ÁËÕâ¸ö¹¦ÄÜ
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
	//æ¸…é›¶æ–°åˆ†é…çš„æ‰©å±•åŒº
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
	//Èç¹ûÃ»Ö¸¶¨NF_CT_EXT_F_PREALLOC
	//Ôò²»ÐèÒª¸üÐÂËùÓÐÒÑ¾­×¢²átypeµÄalloc_size´óÐ¡£¬µ«ÊÇ¿ÉÄÜ»á¸üÐÂ×ÔÉíµÄalloc_size£¬
	//ÒòÎªÖ®Ç°×¢²áµÄtype¿ÉÄÜÉèÖÃÁË±êÖ¾NF_CT_EXT_F_PREALLOC£¬ËùÒÔÐèÒªÖØÐÂ¼ÆËã´óÐ¡
	//Èç¹ûÖ¸¶¨ÁË±êÖ¾NF_CT_EXT_F_PREALLOC£¬Ôò»á¸üÐÂËùÓÐÒÑ×¢²átypeµÄalloc_size£¬ÔÚÌí¼ÓÀ©Õ¹µÄÊ±ºò£¬
	//¾Í»áÒ»´ÎÐÔ·ÖÅä°üº¬NF_CT_EXT_F_PREALLOC±êÖ¾typeËùÐè×ÜµÄÀ©Õ¹¿Õ¼ä£¬
	//ÕâÑùÌí¼ÓÀ©Õ¹µÄÊ±ºò¾Í²»ÐèÒªÔÙÖØÐÂ·ÖÅä¿Õ¼ä£¬ÒòÎª¿Õ¼äÒÑ¾­ÌáÇ°·ÖÅäºÃÁË£¬
	//ºÃ´¦ÊÇ¿ÉÒÔ±ÜÃârealloc£¬»µ´¦ÊÇ¿ÉÄÜ»áÀË·Ñ¿Õ¼ä
	if ((type->flags & NF_CT_EXT_F_PREALLOC) == 0) {
		min = type->id;
		max = type->id;
	}

	/* This assumes that extended areas in conntrack for the types
	   whose NF_CT_EXT_F_PREALLOC bit set are allocated in order */
	for (i = min; i <= max; i++) {
		t1 = rcu_dereference_protected(nf_ct_ext_types[i],
				lockdep_is_held(&nf_ct_ext_type_mutex));
		//¿ÉÄÜÀ©Õ¹ÀàÐÍ»¹Ã»ÓÐ×¢²á
		if (!t1)
			continue;

		t1->alloc_size = ALIGN(sizeof(struct nf_ct_ext), t1->align) +
				 t1->len;
				 
		//±éÀúËùÓÃÒÑ×¢²áµÄÀ©Õ¹
		for (j = 0; j < NF_CT_EXT_NUM; j++) {
			t2 = rcu_dereference_protected(nf_ct_ext_types[j],
				lockdep_is_held(&nf_ct_ext_type_mutex));
			//t2Ã»ÉèÖÃNF_CT_EXT_F_PREALLOC±êÖ¾£¬¾Í²»»á¸üÐÂalloc_size
			//Ä¿Ç°Ö»ÓÐnat_extendÉèÖÃÁË¸Ã±êÖ¾
			//×¢Òât2==t1µÄÇé¿öÏÂÊÇ²»ÄÜ¸üÐÂalloc_size
			//NF_CT_EXT_F_PREALLOCµÄÄ¿µÄÊÇÔÚ·ÖÅäÆäËûÀàÐÍµÄÀ©Õ¹Ê±£¬°Ñµ±Ç°×¢²áµÄ¿Õ¼ä°üº¬½øÈ¥
			//¼ÙÉèÓÐt1¡¢t2¡¢t3Èý¸öÀàÐÍ£¬Ö»ÓÐt3ÉèÖÃÁËNF_CT_EXT_F_PREALLOC£¬
			//ÄÇÃ´·ÖÅät1»òt2Ê±»á°Ét3µÄ¿Õ¼ä°üº¬½øÈ¥£¬µ«ÊÇ·ÖÅät3Ê±Ö»°üº¬t3×ÔÉíµÄ´óÐ¡
			//µ«ÊÇÈç¹ût1¡¢t2Ò²ÉèÖÃÁËNF_CT_EXT_F_PREALLOC£¬
			//ÔòÈý¸öÀàÐÍµÄalloc_size´óÐ¡¶¼Îª£¨t1+t2+t3£©
			//Èç¹ût1¡¢t2ÉèÖÃ¶øt3Ã»ÉèÖÃNF_CT_EXT_F_PREALLOC
			//ÄÇÃ´t1=(t1+t2),t2=(t2+t1),t3=(t3+t1+t2)
			//Ò²¾ÍÊÇËµÀ©Õ¹µÄalloc_sizeÎª×ÔÉí¼ÓÉÏÆäËûÉèÖÃÁËNF_CT_EXT_F_PREALLOCµÄÀ©Õ¹´óÐ¡
			if (t2 == NULL || t2 == t1 ||
			    (t2->flags & NF_CT_EXT_F_PREALLOC) == 0)
				continue;
			//Èç¹ût2ÉèÖÃÁËNF_CT_EXT_F_PREALLOC±êÖ¾£¬ÔòÐèÒª¸üÐÂt1µÄalloc_size
			//ÀÛ¼ÆÐèÒª·ÖÅäµÄ×Ü´óÐ¡µ½t1ÖÐ
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
