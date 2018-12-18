/* Hash table implementation.
 *
 * This file implements in memory hash tables with insert/del/replace/find/
 * get-random-element operations. Hash tables will auto resize if needed
 * tables of power of two in size are used, collisions are handled by
 * chaining. See the source code for more information... :)
 *
 * Copyright (c) 2006-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <urcu/uatomic.h>
#include <urcu.h>
#include <urcu-qsbr.h>
#include <urcu/rcuhlist.h>
#include <urcu/ref.h>
#include <pthread.h>

#include "dict.h"

/* -------------------------- private prototypes ---------------------------- */

static int _dictExpandIfNeeded(dict *ht);
static unsigned long _dictNextPower(unsigned long size);
static int _dictKeyIndex(dict *ht, const void *key);
static int _dictInit(dict *ht, dictType *type, void *privDataPtr);
static dictEntry *dictFindRcu(dict *ht, const void *key);

/* -------------------------- hash functions -------------------------------- */

/* Generic hash function (a popular one from Bernstein).
 * I tested a few and this was the best. */
unsigned int dictGenHashFunction(const unsigned char *buf, int len)
{
	unsigned int hash = 5381;

	while (len--)
		hash = ((hash << 5) + hash) + (*buf++);	/* hash * 33 + c */
	return hash;
}

/* ----------------------------- API implementation ------------------------- */

/* Reset an hashtable already initialized with ht_init().
 * NOTE: This function should only called by ht_destroy(). */
static void _dictReset(dict *ht)
{
	ht->table = NULL;
	ht->size = 0;
	ht->sizemask = 0;
	uatomic_set(&ht->used, 0);
}

/* Create a new hash table */
dict *dictCreate(dictType *type, void *privDataPtr)
{
	int i;
	int hashsize;
	dict *ht = malloc(sizeof(*ht));
	if (!ht)
		return NULL;

	hashsize = type->hashsize;
	if (hashsize < DICT_HT_INITIAL_SIZE)
		hashsize = DICT_HT_INITIAL_SIZE;

	_dictInit(ht, type, privDataPtr);
	ht->table = malloc(sizeof(struct cds_hlist_head) * hashsize);
	if (!ht->table) {
		free(ht);
		return NULL;
	}
	ht->size = hashsize;
	ht->sizemask = hashsize - 1;
	for (i = 0; i < ht->size; i++)
		CDS_INIT_HLIST_HEAD(&ht->table[i]);
	pthread_spin_init(&ht->lock, 0);
	return ht;
}

/* Initialize the hash table */
static int _dictInit(dict *ht, dictType *type, void *privDataPtr)
{
	_dictReset(ht);
	ht->type = type;
	ht->privdata = privDataPtr;
	return DICT_OK;
}

/* Expand or create the hashtable */
static int dictExpand(dict *ht, unsigned long size)
{

#if 0
	dict n;			/* the new hashtable */
	unsigned long realsize = _dictNextPower(size), i;

	/* the size is invalid if it is smaller than the number of
	 * elements already inside the hashtable */
	if (atomic_read(&ht->used) > size)
		return DICT_ERR;

	_dictInit(&n, ht->type, ht->privdata);
	n.size = realsize;
	n.sizemask = realsize - 1;
	n.table = calloc(realsize, sizeof(dictEntry *));

	/* Copy all the elements from the old to the new table:
	 * note that if the old hash table is empty ht->size is zero,
	 * so dictExpand just creates an hash table. */
//	n.used = ht->used;
	atomic_set(&n.used, atomic_read(&ht->used));
	pthread_spin_lock(&ht->lock);
	for (i = 0; i < ht->size && ht->used > 0; i++) {
		dictEntry *he, *nextHe;

		if (ht->table[i] == NULL)
			continue;

		/* For each hash entry on this slot... */
		he = ht->table[i];
		while (he) {
			unsigned int h;

			nextHe = he->next;
			/* Get the new element index */
			h = dictHashKey(ht, he->key) & n.sizemask;
			he->next = n.table[h];
			n.table[h] = he;
			ht->used--;
			/* Pass to the next element */
			he = nextHe;
		}
	}
	free(ht->table);

	/* Remap the new hashtable in the old */
	*ht = n;
#endif
	return DICT_OK;
}

/* Add an element to the target hash table */
int dictAdd(dict *ht, void *key, void *val)
{
	int index;
	dictEntry *entry, *he;

	/* Get the index of the new element, or -1 if
	 * the element already exists. */
	if ((index = _dictKeyIndex(ht, key)) == -1)
		return DICT_ERR;

	/* Allocates the memory and stores key */
	entry = malloc(sizeof(*entry));
	if (!entry)
		return DICT_ERR;

	/* Set the hash entry fields. */
	dictSetHashKey(ht, entry, key);
	dictSetHashVal(ht, entry, val);
	urcu_ref_init(&entry->ref);
	entry->ht = ht;

	pthread_spin_lock(&ht->lock);
	if ((he = dictFindRcu(ht, key)))
		goto out;
	cds_hlist_add_head_rcu(&entry->node, &ht->table[index]);
	pthread_spin_unlock(&ht->lock);

	uatomic_inc(&ht->used);
	return DICT_OK;

out:
	pthread_spin_unlock(&ht->lock);
	dictPut(he);
	dictPut(entry);
	return DICT_ERR;
}

/* Add an element, discarding the old if the key already exists.
 * Return 1 if the key was added from scratch, 0 if there was already an
 * element with such key and dictReplace() just performed a value update
 * operation. */
int dictReplace(dict * ht, void *key, void *val)
{
	dictEntry *entry, auxentry;

	/* Try to add the element. If the key
	 * does not exists dictAdd will succeed. */
	if (dictAdd(ht, key, val) == DICT_OK)
		return DICT_OK;

	dictDelete(ht, key);
	if (dictAdd(ht, key, val) == DICT_OK)
		return DICT_OK;
	return DICT_ERR;
}

/* Search and remove an element */
int dictDelete(dict *ht, const void *key)
{
	unsigned int h;
	dictEntry *he, *tmp;

	h = dictHashKey(ht, key) & ht->sizemask;

	pthread_spin_lock(&ht->lock);
	cds_hlist_for_each_entry_rcu_2(he, &ht->table[h], node) {
		if (dictCompareHashKeys(ht, key, he->key)) {
			cds_hlist_del_rcu(&he->node);
			pthread_spin_unlock(&ht->lock);
			uatomic_dec(&ht->used);
			dictPut(he);
			return DICT_OK;
		}
	}
	pthread_spin_unlock(&ht->lock);
	return DICT_ERR;	/* not found */
}

/* Destroy an entire hash table */
static int _dictClear(dict *ht)
{
	unsigned long i;
	dictEntry *he;

	rcu_read_lock();
	pthread_spin_lock(&ht->lock);
	for (i = 0; i < ht->size; i++) {
		cds_hlist_for_each_entry_rcu_2(he, &ht->table[i], node) {
			cds_hlist_del_rcu(&he->node);
			dictPut(he);
		}
	}
	pthread_spin_unlock(&ht->lock);
	rcu_read_unlock();
	uatomic_set(&ht->used, 0);

	rcu_barrier();
	return DICT_OK;		/* never fails */
}

/* wrapper _dictClear */
int dictEmpty(dict *ht)
{
	return  _dictClear(ht);
}

/* Clear & Release the hash table */
void dictRelease(dict *ht)
{
	_dictClear(ht);
	free(ht->table);
	_dictReset(ht);
	pthread_spin_destroy(&ht->lock);
	free(ht);
}

static dictEntry *dictFindRcu(dict *ht, const void *key)
{
	dictEntry *he;
	unsigned int h;

	h = dictHashKey(ht, key) & ht->sizemask;

	cds_hlist_for_each_entry_rcu_2(he, &ht->table[h], node) {
		if (dictCompareHashKeys(ht, key, he->key) &&
				urcu_ref_get_unless_zero(&he->ref)) {
			return he;
		}
	}

	return NULL;
}

dictEntry *dictFind(dict *ht, const void *key)
{
	dictEntry *he;

	rcu_read_lock();
	he = dictFindRcu(ht, key);
	rcu_read_unlock();

	return he;
}

static void dict_entry_free_rcu(struct rcu_head *head)
{
	dictEntry *he = container_of(head, dictEntry, rcu);
	dictFreeEntryKey(he->ht, he);
	dictFreeEntryVal(he->ht, he);
	free(he);
}

static void dict_entry_release(struct urcu_ref *ref)
{
	dictEntry *he = container_of(ref, dictEntry, ref);
	call_rcu(&he->rcu, dict_entry_free_rcu);
}

void dictPut(dictEntry *he)
{
	if (he)
		urcu_ref_put(&he->ref, dict_entry_release);
}

#if 0
static dictIterator *dictGetIterator(dict * ht)
{
	dictIterator *iter = malloc(sizeof(*iter));

	iter->ht = ht;
	iter->index = -1;
	iter->entry = NULL;
	iter->nextEntry = NULL;
	return iter;
}


static dictEntry *dictNext(dictIterator * iter)
{
	while (1) {
		if (iter->entry == NULL) {
			iter->index++;
			if (iter->index >= (signed)iter->ht->size)
				break;
			iter->entry = iter->ht->table[iter->index];
		} else {
			iter->entry = iter->nextEntry;
		}
		if (iter->entry) {
			/* We need to save the 'next' here, the iterator user
			 * may delete the entry we are returning. */
			iter->nextEntry = iter->entry->next;
			return iter->entry;
		}
	}
	return NULL;
}

static void dictReleaseIterator(dictIterator * iter)
{
	free(iter);
}
#endif

/* ------------------------- private functions ------------------------------ */

/* Expand the hash table if needed */
static int _dictExpandIfNeeded(dict * ht)
{
	return DICT_OK;
#if 0
	/* If the hash table is empty expand it to the initial size,
	 * if the table is "full" dobule its size. */
	if (ht->size == 0)
		return dictExpand(ht, DICT_HT_INITIAL_SIZE);
	if (atomic_read(&ht->used) == ht->size)
		return dictExpand(ht, ht->size * 2);
	return DICT_OK;
#endif
}

/* Our hash table capability is a power of two */
static unsigned long _dictNextPower(unsigned long size)
{
	unsigned long i = DICT_HT_INITIAL_SIZE;

	if (size >= LONG_MAX)
		return LONG_MAX;
	while (1) {
		if (i >= size)
			return i;
		i *= 2;
	}
}

/* Returns the index of a free slot that can be populated with
 * an hash entry for the given 'key'.
 * If the key already exists, -1 is returned. */
static int _dictKeyIndex(dict *ht, const void *key)
{
	unsigned int h;
	dictEntry *he;

	/* Expand the hashtable if needed */
	if (_dictExpandIfNeeded(ht) == DICT_ERR)
		return -1;
	/* Compute the key hash value */
	h = dictHashKey(ht, key) & ht->sizemask;
	/* Search if this slot does not already contain the given key */
	rcu_read_lock();
	cds_hlist_for_each_entry_rcu_2(he, &ht->table[h], node) {
		if (dictCompareHashKeys(ht, key, he->key)) {
			rcu_read_unlock();
			return -1;
		}
	}
	rcu_read_unlock();
	return h;
}
