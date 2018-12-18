#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <urcu/uatomic.h>
#include <urcu.h>
#include <urcu-qsbr.h>
#include <urcu/rcuhlist.h>
#include <urcu/ref.h>

#include <linux/sched.h>
#include <pthread.h>

#include "dict.h"

dict *ht;

int keyCompare(void *privdata, const void *key1, const void *key2)
{
	return !strcmp(key1, key2);
}

void keyDestructor(void *privdata, void *key)
{
	printf("%s\n", __func__);
	free(key);
}

void valDestructor(void *privdata, void *obj)
{
	printf("%s\n", __func__);
	free(obj);
}

unsigned int hashFunction(const void *key)
{
	return dictGenHashFunction(key, strlen(key));
}

struct dictType rcu_test = {
	.hashFunction = hashFunction,
	.keyCompare = keyCompare,
	.keyDestructor = keyDestructor,
	.valDestructor = valDestructor,
	.hashsize = 1000000,
};

void *start_routine(void *arg)
{
	pthread_detach(pthread_self());
	dictEntry *he;
	int ref;
	rcu_register_thread();
	while (1) {
		rcu_read_lock();
		he = dictFind(ht, "123");
			printf("before he=%p, value=%s, ref=%d\n", he, he ? dictGetEntryVal(he) : "", 
			he? uatomic_read(&he->ref.refcount) : 0);
		dictPut(he);

		sleep(20);
		printf("after he=%p, value=%s, ref=%d\n", he, he ? dictGetEntryVal(he) : "",
			he? uatomic_read(&he->ref.refcount) : 0);
		rcu_read_unlock();
		rcu_quiescent_state();
	}
	 rcu_unregister_thread();
}

int main(void)
{
//	rcu_init();
	pthread_t tid;
	ht = dictCreate(&rcu_test, NULL);
	dictAdd(ht, strdup("123"), strdup("456"));
	makethread(SCHED_NORMAL, 0, &tid, start_routine);

	dictAdd(ht, strdup("123"), strdup("456"));
	dictAdd(ht, strdup("124"), strdup("456"));
	sleep(5);
	printf("delete 123\n");
	dictDelete(ht, "123");
	pause();
}
