#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "igd_dns_match.h"



struct url_item {
	struct url_tree url;
	struct list_head list;  /* link to group url_head */
};

static inline int dns_tree_hash(unsigned char *p, int len)
{
	int res = 0;
	switch (len) {
	case 0:
	case 1:
		res = *p;
		break;
	case 2:
		res = p[0] + p[1];
		break;
	case 3:
		res = p[0] + p[1] + p[2];
		break;
	default:
		res = p[0] + p[1] + p[2] + p[3];
		break;
	}
	return res % DNS_HASH_MX;
}

int str_2_dns(const unsigned char *str, unsigned char *dst, int dns_len)
{
	char *dot, *tmp, *prev_dot;
	int count = 0, index;
	char dns[150] = {0,};

	memset(dst, 0, dns_len);
	dns_len--;

	if (dns_len > 100)
		return -1;
	strncpy(&dns[1], str, dns_len);
	tmp = &dns[1];

	prev_dot = strchr(tmp, '.');
	if (!prev_dot) {
		dns[0] = strlen(tmp); /*  first dns part len */
		if (dns[0] >= DNS_INDEX_MX) 
			return -1;
		strncpy(dst, dns, dns_len);
		return 0;
	}

	dns[0] = prev_dot - tmp;
	tmp = prev_dot + 1;

	while (tmp - dns < dns_len) {
		dot = strchr(tmp, '.');
		if (!dot) {
			*prev_dot = strlen(tmp); /*  the last dot */
			if (*prev_dot > DNS_INDEX_MX) 
				return -1;
			break;
		}
		index = dot - prev_dot - 1;
		*prev_dot = index; /*  dns rfc  */
		prev_dot = dot;
		tmp = dot + 1;
		count++;
	}
	strncpy(dst, dns, dns_len);
	return count;
}

void dns_2_lower(unsigned char *dns, int dns_len)
{
	int i = 0;
	
	if (!dns)
		return;
	
	for (i = 0; i < dns_len; i++)
		dns[i] = tolower(dns[i]);
}

int check_dns_is_num(unsigned char *dns, int dns_len)
{
	char *tmp = NULL;
	int len = 0;
	int i = 0;
	int index = 0;

	if (!dns || (dns_len <= 0))
		return -1;

	tmp = dns;
	len = dns_len;
	while ((len -= index) > 0) {
		index = *tmp;
		if (!index || len < index)
			break;
		
		tmp++;
		for (i = 0; i < index; i++) {
			if ((*tmp < '0' || *tmp > '9') && (*tmp != ':'))
				return -1;
			tmp++;
		}
	}

	return 0;
}

static inline uint32_t igd_dns_ip_hash(__be32 ip, uint32_t nr)
{
	return ntohl(ip) % nr;
}

unsigned char *dns_2_str(const unsigned char *dns, unsigned char *dst, int len)
{
	static unsigned char tmp[100];
	int i = 0;
	int count = 0;

	if (!dst) {
		memset(tmp, 0, sizeof(tmp));
		dst = tmp;
		len = sizeof(tmp);
	}

	while (i < len - 1 && dns[i]) {
		if(isalnum(dns[i]))
			dst[count++] = dns[i];
		else if (i)
			dst[count++] = '.';
		i++;
	}
	dst[count] = 0;

	return dst;
}

static struct dns_tree *dns_tree_match(struct dns_tree_head *root, struct dns_tree_res *res, int level)
{
	struct dns_tree_head *next;
	struct dns_tree *r;
	int hash;
	int index;

	list_for_each_entry(r, &root->node, list) {
#ifdef NEW_DOMAIN_MATCH
		if (test_bit(DNS_TREE_COMPLETE_MATCH, &r->flags)) {
			if (level != 0 || res->match_len != r->comm.len ||
				memcmp(res->org, r->comm.name, r->comm.len))
				continue;
			DEBUG("res->org=%s\n", res->org);
		} else
#endif
		if (strncmp(res->org, r->comm.name, r->comm.len)) 
			continue;
		res->flags |= DNS_TREE_HOST_MATCH;
		if (res->match(r, res->data, res->data_len))
			continue;

		if (test_bit(TREE_ALL_MATCH , &r->flags) && level!=0) {
			continue;
		}

#ifdef NEW_DOMAIN_MATCH
		if (res->max_len < (int)r->comm.len) {
			DEBUG("res->max_len=%d, res->match_len=%d, r->comm.len=%d\n",res->max_len, res->match_len, r->comm.len);
			res->max_len = r->comm.len;
			DEBUG("res->max_len=%d, res->match_len=%d, r->comm.len=%d\n",res->max_len, res->match_len, r->comm.len);
			res->dst = r;
		}
		break;
#else
		return r;
#endif
	}

	index = *res->cur;
	if (index >= DNS_INDEX_MX)
		return NULL;
	/*  doesn't need check index=0, because root->child[0]=NULL*/
	if (!root->child[index]) {
		DEBUG("root->child[%d]== NULL, res len=%d\n", index, res->len);
#ifdef NEW_DOMAIN_MATCH
		return res->dst;
#else
		return NULL;
#endif
	}
	hash = dns_tree_hash(&res->cur[1], index);
	res->len -= index + 1;
	res->cur += index + 1;
	if (res->len < 0) {
		DEBUG("res len error\n");
		return NULL;
	}
	next = root->child[index];
	next = next + hash;

	return dns_tree_match(next, res, level);
}

/* return dns if match, or NULL */
void *__dns_match(struct dns_tree_head *root, struct dns_tree_res *res)
{
	struct dns_tree *r;
	int index = 0;
	int debug = 0;
	int len = res->len;
	int level = 0;

	res->dst = NULL;
	res->max_len = 0;

	if (len > 256) 
		len = 256;

	while ((len -= index) > 0) {
		res->org += index;
		index = *res->org;
		if (!index || len < index)
			break;
		if (index >= DNS_INDEX_MX) 
			goto next;
		if (debug++ > 10)
			break;
		res->cur = res->org;
		res->len = len;
		res->match_len = strlen(res->org);
		r = dns_tree_match(root, res, level++);
//		if (IS_ERR(r)) 
//			break;
		if (r) 
			return r;
next:
		index++;
	}
	return NULL;
}

inline static int dns_tree_extra_match(void *r, void *data, const int data_len)
{
	return 0;
}

/* support wildcard '*' and '?' */
void *text_replace_fnmatch_alg(const unsigned char *data, 
		unsigned int data_len,
		const unsigned char *pattern,
		unsigned int pattern_len, unsigned int *match_len)
{
	//record '*'
	unsigned int mark = 0;
	unsigned int d_len = 0, p_len = 0;
	const unsigned char *start = NULL;
	
	if (!data_len || !pattern_len)
		return NULL;
	
	while (d_len < data_len && p_len < pattern_len) {
		switch (pattern[p_len]) {
		case '?':
			if (!start)
				start = &data[d_len];
			d_len++;
			p_len++;
			break;
		case '*':
			if (!start)
				start = &data[d_len];
			p_len++;
	      		mark = p_len;
      			break;
		default:
			if (data[d_len] != pattern[p_len]) {
				d_len -= p_len - mark - 1;
				p_len = mark;
				if (start && pattern[p_len - 1] != '*')
					start = NULL;
  			} else {
  				if (!start)
					start = &data[d_len];
				d_len++;
				p_len++;
  			}
			break;
		}
	}

	if (!start)
		return NULL;
	
	if (p_len == pattern_len) {
		if (d_len == data_len || pattern[p_len - 1] == '*') {
			if (match_len)
				*match_len = data + data_len - start;
			return (void *)start;
		}
	}
	
	while (p_len < pattern_len) {
		/*	if the left patten is not '*',
		*	match failed
		*/
		if (pattern[p_len] != '*') 
			return NULL;
		p_len++;
	}

	if (match_len) {
		if (pattern[p_len - 1] == '*')
			*match_len = data + data_len - start;
		else
			*match_len = data + d_len - start;
	}
	return (void *)start;
}
EXPORT_SYMBOL(text_replace_fnmatch_alg);

static int url_tree_extra_match(void *r, void *data, const int data_len)
{
	struct url_tree *url = r;

	if (!url->uri.len)
		return 0;
	if (!data || !data_len)
		return 1;
	if (test_bit(DNS_TREE_URI_WILDCARD_MATCH, &url->flags)) {
		if (text_replace_fnmatch_alg(data, data_len, url->uri.name, url->uri.len, NULL))
			return 0;
	} if (test_bit(TREE_URI_PART_MATCH, &url->flags)) {
		if (l7_str_str_2(data, data_len, url->uri.name, url->uri.len))
			return 0;
	} else if (!memcmp(url->uri.name, data, url->uri.len))
		return 0;
	return -1;
}

void *url_tree_match(struct dns_tree_head *root, struct nf_http_log *log, int *flags)
{
	struct dns_tree_res res;
	struct url_tree *r;
	struct list_head *head = root->priv;
	unsigned char dns[IGD_NAME_LEN_64];
	void *start;

	str_2_dns(log->host, dns, sizeof(dns));
	dns_2_lower(dns, sizeof(dns));
	res.match = url_tree_extra_match;
	res.data = log->uri + 1;
	res.data_len = log->uri_len ? (log->uri_len - 1) : 0;
	res.org = dns;
	res.len = sizeof(dns);
	res.flags = 0;

	if (!head) 
		goto match;

	/* only match uri, ignore host */
	if (!check_dns_is_num(dns, sizeof(dns))) {
		list_for_each_entry(r, head, list) {
			if (test_bit(TREE_URI_PART_MATCH, &r->flags)) {
				if (!l7_str_str_2(res.data, res.data_len, r->uri.name, r->uri.len))
					continue;
			}
			else {
				if (strncmp(res.data, r->uri.name, r->uri.len)) 
					continue;
			}
			return r;
		}
	}
match:
	start = __dns_match(root, &res);
	if (flags)
		*flags = res.flags;
	return start;
}

void *url_tree_match2(struct dns_tree_head *root, unsigned char *host, char *uri)
{
	struct dns_tree_res res;
	struct url_tree *r;
	struct list_head *head = root->priv;
	unsigned char dns[32];

	str_2_dns(host, dns, sizeof(dns));	
	dns_2_lower(dns, sizeof(dns));
	res.match = url_tree_extra_match;
	res.data = uri;
	res.data_len = uri ? strlen(uri) : 0;
	res.org = dns;
	res.len = sizeof(dns);

	if (!head) 
		goto match;

	/* only match uri, ignore host */
	if (!check_dns_is_num(dns, sizeof(dns))) {
		list_for_each_entry(r, head, list) {
			if (test_bit(TREE_URI_PART_MATCH, &r->flags)) {
				if (!l7_str_str_2(res.data, res.data_len, r->uri.name, r->uri.len))
					continue;
			}
			else {
				if (strncmp(res.data, r->uri.name, r->uri.len)) 
					continue;
			}
			return r;
		}
	}
match:
	return __dns_match(root, &res);
}

static void dns_rule_tree_add_count(struct dns_tree_head *root)
{
	if (test_bit(TREE_ROOT, &root->flags)) 
		root->cnt++;
	else {
		if (root->parent)
			dns_rule_tree_add_count(root->parent);
	}
}

static void dns_rule_tree_del_count(struct dns_tree_head *root)
{
	if (test_bit(TREE_ROOT, &root->flags)) 
		root->cnt--;
	else {
		if (root->parent)
			dns_rule_tree_del_count(root->parent);
	}
}

static int __dns_rule_add_tree(struct dns_tree_head *root, struct dns_tree *dns_k, int offset)
{
	struct dns_tree_head *tree = root;
	struct dns_tree_head *next;
	unsigned char *org = dns_k->comm.name;
	int index = org[offset];

	if (!index) {
		list_add_tail(&dns_k->list, &tree->node);
		IGD_KERNEL_MSG("add dns index %p\n", dns_k);
		return 0;
	}

	if (index >= DNS_INDEX_MX || offset + index >= sizelen(dns_k->comm.name)) {
		IGD_KERNEL_MSG("dns index err:%d\n", index);
		return 0;
	}

	/* create child */
	if (!root->child[index]) {
		tree = kzalloc(DNS_HASH_MX * sizeof(*tree), GFP_ATOMIC);
		if (!tree) 
			return -1;
		IGD_LIST_EACH(0, DNS_HASH_MX) {
			next = tree + i;
			INIT_LIST_HEAD(&next->node);
			next->parent = root;
			set_bit(TREE_NOT_FREE, &next->flags);
		} IGD_LIST_EACH_END();
		root->child[index] = tree;
		clear_bit(TREE_NOT_FREE, &tree->flags);
		dns_rule_tree_add_count(root);
		DNS_DEBUG("add tree %p:%p\n", root, tree);
	}

	tree = root->child[index];
	next = tree + dns_tree_hash(&org[offset + 1], index);
	offset += index + 1;
	return __dns_rule_add_tree(next, dns_k, offset);
}

/*  return 0 when sucess, or -1 */
int dns_tree_add_root(struct dns_tree_head *root, struct dns_tree *entry)
{
	if (!entry->comm.name[0]) {
		IGD_KERNEL_MSG("dns len=0\n");
		return -1;
	}
	return __dns_rule_add_tree(root, entry, 0);
}

void dns_tree_head_free(void *data)
{
	struct dns_tree_head *root = data;

	IGD_LIST_EACH(0, DNS_INDEX_MX) {
		if (!root->child[i]) 
			continue;
		IGD_LIST_EACH_3(j, 0, DNS_HASH_MX) {
			dns_tree_head_free(root->child[i] + j);
		} IGD_LIST_EACH_END();
		root->child[i] = NULL;
	} IGD_LIST_EACH_END();

	if (test_bit(TREE_NOT_FREE, &root->flags)) 
		return ;
	DNS_DEBUG("free %p\n", root);
	dns_rule_tree_del_count(root);
	kfree(root);
	return ;
}

static struct dns_tree_head root;
static LIST_HEAD(url_head);

int add_url_item(const char *src_url, int ok)
{
	char url[32] = { 0, };
	char uri[32] = { 0, };
	struct url_item *item;
	item = kzalloc(sizeof(*item), GFP_ATOMIC);
	if (!item) 
		return -1;
	if (ok)
		set_bit(DNS_TREE_COMPLETE_MATCH, &item->url.flags);
	str_split_url(src_url, url, sizeof(url), uri, sizeof(uri));
	str_2_dns(url, item->url.comm.name, sizeof(item->url.comm.name));
	item->url.comm.len = strlen(item->url.comm.name);
	igd_strcpy(item->url.uri.name, uri);
	item->url.uri.len = strlen(item->url.uri.name);
	if (dns_tree_add_root(&root, (void *)&item->url) < 0) {
		kfree(item);
		return -1;
	}
	list_add_tail(&item->list, &url_head);
	DEBUG("add item=%p, url=%s\n", item, src_url);
	return 0;
}


int find_url_item(const char *src_url)
{
	char url[32] = { 0, };
	char uri[32] = { 0, };
	struct nf_http_log log;
	struct url_item *item;
	struct url_item item2;
	item = &item2;

	memset(&log, 0, sizeof(log));
	str_split_url(src_url, url, sizeof(url), uri, sizeof(uri));
	str_2_dns(url, item->url.comm.name, sizeof(item->url.comm.name));
	item->url.comm.len = strlen(item->url.comm.name);
	igd_strcpy(item->url.uri.name, uri);
	item->url.uri.len = strlen(item->url.uri.name);

	log.host_len = snprintf(log.host, sizeof(log.host),  "%s", url);
	log.uri_len = snprintf(log.uri, sizeof(log.uri), "%s", item->url.uri.name);

	if ((item = url_tree_match(&root, &log, NULL)))
		DEBUG("find item=%p, url=%s\n", item, src_url);
	else
		DEBUG("not find item=%p, url=%s\n", item, src_url);
	return 0;
}


int main(int argc, char **argv)
{
	dns_tree_root_init(&root);
//	add_url_item("www.baidu.com");
//	add_url_item("baidu", 0);
	add_url_item("baidu.com", 0);
	add_url_item("baidu.com.cn", 0);
	add_url_item("168.0.1", 0);
	add_url_item("weixin.qq.com", 0);
	add_url_item("weixin.qq.cam", 0);
	add_url_item("weixin.qq.cam", 0);
	add_url_item("weixin.qq.com.cn", 0);
	add_url_item("weixin.qq", 0);
	add_url_item("weixin", 0);
	add_url_item("weixin.cn.com", 0);
	add_url_item("weixin.cn.com.cn", 0);
	add_url_item("", 0);

//	find_url_item("www.baidu.com.cn");
	find_url_item("baidu.com");
	find_url_item("a.weixin.qq.com");
	find_url_item("weixin.qq.com");
	find_url_item("weixin.cn.com.cn");
	find_url_item("baidu.com.cn");
	find_url_item("192.168.0.1");

	dns_tree_head_free(&root);

	return 0;

}


