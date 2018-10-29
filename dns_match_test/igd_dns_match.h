#ifndef __IGD_DNS_MATCH__
#define __IGD_DNS_MATCH__

#include "linux_list.h"
#include <stdint.h>
#include <stdlib.h>

typedef uint32_t __be32;


#define igd_strcpy(dst,src) do{\
	strncpy(dst, src, sizeof(dst) - 1);\
	dst[sizeof(dst) - 1] = '\0';\
}while(0)

#define sizelen(a) (sizeof(a) - 1)
#define likely
#define GFP_ATOMIC 0
#define EXPORT_SYMBOL(X)
#define kzalloc(size, flags) calloc(1, size)
 #define kfree(p) free(p)

#define DEBUG(fmt, args...) do {fprintf(stderr, "%s %d "fmt, __func__, __LINE__, ##args); } while (0)

#define IGD_KERNEL_MSG DEBUG
#define DNS_DEBUG DEBUG

 #define IGD_LIST_EACH_3(val,min,max) do{ \
 		int val;\
 		for (val = (max - 1); val >= (min); val--) {

 #define IGD_LIST_EACH_2(val,min,max) do{ \
 		int val;\
 		for (val = min; val < (max); val++) {

 #define IGD_LIST_EACH(min, max) do {\
 		int i;\
 		for (i = min; i < (max); i++) {

 #define IGD_LIST_EACH_END() }}while(0)

#define HTTP_URL_LEN 64
#define HTTP_URI_LEN 128
#define HTTP_COOKIE_LEN 128
#define HTTP_UA_LEN 64
struct nf_http_log {
	char suffix[16];
	char host[HTTP_URL_LEN];
	char uri[HTTP_URI_LEN];
	char refer[64];
	char cookie[HTTP_COOKIE_LEN];
	char ua[HTTP_UA_LEN];
	uint16_t host_len;
	uint16_t uri_len;
	uint16_t refer_len;
	uint16_t ua_len;
	uint16_t ck_len; /*  cookie len*/
	uint8_t suffix_len;
};

#define BITS_PER_LONG   32
#define BIT(nr)			(1UL << (nr))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE		8

#define DNS_HASH_MX 6

#define DNS_INDEX_MX	64
#define TREE_NOT_FREE 0
#define TREE_ROOT 	  1
#define TREE_ALL_MATCH 1
#define DNS_TREE_URI_WILDCARD_MATCH	2
#define TREE_URI_PART_MATCH         3
#define DNS_TREE_COMPLETE_MATCH 4

#define IGD_NAME_LEN 32
#define IGD_NAME_LEN_64 64
#define igd_min(a,b) (((a)<(b)) ? (a) : (b))

struct dns_tree_head {
	struct list_head node; /* node */
	unsigned long flags;
	struct dns_tree_head *parent;
	struct dns_tree_head *child[DNS_INDEX_MX];
	void *priv; /* used by url match */
	int cnt;
};


 struct igd_name_comm_k {
         char name[IGD_NAME_LEN];
         int len;
 };

struct igd_name_dns_k {
         char name[IGD_NAME_LEN_64];
         int len;
};


#define DNS_HEAD_BIT 0
#define DNS_TAIL_BIT 1

/* NOTE: change dns_tree must be change url_tree */
/* use ^ for head, use $ for end */
struct dns_tree {
	struct list_head list;
	struct igd_name_dns_k comm;
	unsigned long flags;
	int index;
};

struct url_tree {
	/* dns_tree is base class, these three members must be same as dns_tree
	*/
	struct list_head list;
	struct igd_name_dns_k comm;
	unsigned long flags;
//	int index;

	struct igd_name_comm_k uri;
};

struct dns_tree_rule {
	struct dns_tree dns;
	int id;
};

struct dns_tree_res {
	unsigned char *org;
	unsigned char *cur;
	int len;
	int match_len;
	int max_len;
	#define DNS_TREE_HOST_MATCH	(1<<0)
	int flags;
	int data_len;
	int (*match)(void *s1, void *s2, const int data_len);
	void *data; /* input args */
	void *dst; /* dns_tree if match */
};


static inline int test_bit(int nr,  unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}


static inline void set_bit(int nr,  unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p  |= mask;
}

/**
 * clear_bit - Clears a bit in memory
 * @nr: Bit to clear
 * @addr: Address to start counting from
 *
 * clear_bit() is atomic and may not be reordered.  However, it does
 * not contain a memory barrier, so if it is used for locking purposes,
 * you should call smp_mb__before_clear_bit() and/or smp_mb__after_clear_bit()
 * in order to ensure changes are visible on other processors.
 */
static inline void clear_bit(int nr,  unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p &= ~mask;
}

static inline void dns_tree_root_init(struct dns_tree_head *root)
{
	INIT_LIST_HEAD(&root->node);
	set_bit(TREE_NOT_FREE, &root->flags);
	set_bit(TREE_ROOT, &root->flags);
	return ;
}

static inline unsigned char *l7_str_str_2(unsigned char *str, int str_len, unsigned char *key, int key_len)
{
	while (likely(str_len >= key_len)) {
		if (!memcmp(str, key, key_len))
			return str;
		str_len--;
		str++;
	}
	return NULL;
}

static inline void str_split_url(const char *src, char *url, int url_len, char *uri, int uri_len)
{
	char *tmp = strchr(src, '/');

	if (!tmp) {
		strncpy(url, src, url_len - 1);
		return ;
	}
	if (tmp - src) 
		strncpy(url, src, igd_min(url_len - 1, tmp - src));
	if (*(tmp + 1))
		strncpy(uri, tmp + 1, uri_len - 1); /* skip '/' */
}


extern int str_2_dns(const unsigned char *str, unsigned char *dns, int dns_len);
extern void dns_2_lower(unsigned char *dns, int dns_len);
extern unsigned char *dns_2_str(const unsigned char *dns, unsigned char *dst, int len);
extern int dns_tree_add_root(struct dns_tree_head *root, struct dns_tree *entry);
extern void dns_tree_head_free(void *data);
extern void *text_replace_fnmatch_alg(const unsigned char *data,
		unsigned int data_len,
		const unsigned char *pattern,
		unsigned int pattern_len, unsigned int *match_len);
#endif
