#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/ctype.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/genetlink.h>
#include <net/netfilter/nf_nat_helper.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_nat.h>

#include <linux/netfilter_ipv4/igd_filter/igd_filter.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/igd_filter/nc_netlink.h>

#include "nf_conntrack_text.h"

//#define AD_DEBUG
#ifdef AD_DEBUG
#define ad_debug(fmt, args...) \
	printk("text_replace: " fmt, ## args)
#else
#define ad_debug(fmt, ...)
#endif

#define MAX_EXTEND_NUM	 	2
#define MAX_EXTEND_SIZE	 	64

#define MAX_MATCH_RESULT	8

#define TEXT_GROUP_MAX 		128
#define TEXT_GROUP_NAME		16


enum {
	HTTP_FILTER_DISMATCH_BIT,
	HTTP_FILTER_ORIGINAL_MATCHED_BIT,
	HTTP_FILTER_REPLY_MATCHED_BIT,
	HTTP_FILTER_NON_REPLACE_BIT,
	HTTP_FILTER_PROXY_BIT,
	HTTP_FILTER_RESET_BIT,
	HTTP_FILTER_DROP_BIT,
	HTTP_FILTER_SEQ_ADJUST_BIT,
	HTTP_FILTER_MISS_HOST_BIT,
	HTTP_FILTER_OWN_HOST_BIT,
	HTTP_FILTER_MATCH_HOST_BIT,
};

struct text_replace_group {
	struct list_head list;
	struct list_head url_head;
	int16_t priority;
	uint16_t id;
	pid_t tgid;
	char name[TEXT_GROUP_NAME];
	struct dns_tree_head root;
};

struct url_item {
	struct url_tree url;
	uint16_t mode;
	uint16_t code;	/* HTTP status code */
	uint32_t flags;
	uint32_t private_size;
	uint32_t id;
	void *private;
	struct list_head list;  /* link to group url_head */
	struct list_head option_head[IP_CT_DIR_MAX]; /* link match option */
};

struct match_option;
struct match_result {
	uint16_t type;
	uint16_t flags;
	uint16_t match_len;
	uint16_t match_offset;
	uint16_t rep_len;
	unsigned char *rep_data;
};

struct match_param {
	bool hotdrop;
	unsigned int rep_len;
	unsigned int match_len;
	unsigned char *next;
	
	/* record extend number */
	int extend;
	/* recode index of res */
	int i;
	/* record already processed number by target func */
	int finished;
	
	/*  only extend packet is need record in res */
	struct match_result res[MAX_MATCH_RESULT];
};

struct match_ops {
	const char *name;
	uint16_t type;
	bool (*match)(struct sk_buff *skb, struct match_option *opt, struct match_param *param);
	/* return NF_ACCEPT ,NF_STOP,NF_REPEAT
	*  NF_STOP:stop match packet
	*/
	int (*target)(struct sk_buff *skb, struct match_option *opt, struct match_param *param);
	struct list_head list;
};

struct match_option {
	struct list_head list;
	struct match_ops *ops;
	struct k_text_option opt[0];
};

static int white_num = 0;
static int black_num = 0;
module_param(white_num, int, 0444);
module_param(black_num, int, 0444);

static DECLARE_BITMAP(text_group, TEXT_GROUP_MAX);

/* we use global lock, so need optimization in SMP */
static DEFINE_SPINLOCK(g_lock);
static LIST_HEAD(grp_list);
static struct list_head __rcu *grp_entry = NULL;
static atomic_t ad_rule_id = ATOMIC_INIT(0);
static atomic_t white_rule_num = ATOMIC_INIT(0);
static atomic_t black_rule_num = ATOMIC_INIT(0);
static LIST_HEAD(ops_list);

static DEFINE_PER_CPU(struct match_param, param);

#define HTTP_RESPONCE_MAX 256
struct http_response {
	char data[HTTP_RESPONCE_MAX];
};

static DEFINE_PER_CPU(struct http_response, http_response);

struct match_ops *find_match_ops_by_type(int type);

/* the netlink family */
static struct genl_family text_replace_fam = {
	.id = GENL_ID_GENERATE,	/* don't bother with a hardcoded ID */
	.name = GENL_HTTP_FILTER_NAME,	/* have users key off the name instead */
	.hdrsize = 0,		/* no private header */
	.version = 1,		/* no particular meaning now */
	.maxattr = HTTP_FILTER_ATTR_MAX,
};

static struct genl_multicast_group text_replace_mcgrp = {
	.name = TEXT_REPLACE_GENL_MCAST_GROUP_NAME,
};

static int text_replace_mc_event(const unsigned char *mac, char *dns, uint32_t id, uint16_t gid)
{
	struct sk_buff *nskb;
	void *hdr;
	char buf[64];
	int err = 0;
	
	/*plus 256 for header */
	nskb = nlmsg_new(256, GFP_ATOMIC);
	if (nskb == NULL) {
		err = -ENOMEM;
		goto out;
	}

	hdr = genlmsg_put(nskb, 0, 1, &text_replace_fam, 0, HTTP_FILTER_CMD_REPORT_STATIS);
	if (hdr == NULL) {	
		err = -ENOMEM;
		goto out;
	}
	
	dns_2_str(dns, buf, sizeof(buf));
	NLA_PUT(nskb, HTTP_FILTER_ATTR_URL, strlen(buf) + 1, buf);
	NLA_PUT(nskb, HTTP_FILTER_ATTR_HOST_MAC, ETH_ALEN, mac);
	NLA_PUT_U32(nskb, HTTP_FILTER_ATTR_AD_ID, id);
	NLA_PUT_U16(nskb, HTTP_FILTER_ATTR_GROUP_ID, gid);
	
	genlmsg_end(nskb, hdr);
	genlmsg_multicast(nskb, 0, text_replace_mcgrp.id, GFP_ATOMIC);
	return 0;

nla_put_failure:
	err = -ENOMEM;
out:
	if (nskb)
		nlmsg_free(nskb);
	return err;
}

static inline int get_current_rule_id(void)
{
	return atomic_read(&ad_rule_id);
}

static inline bool rule_is_expired(struct nf_text_replace *ad)
{
	return ad->rule_id != get_current_rule_id();
}

static inline void flush_rule_id(void)
{
	atomic_inc(&ad_rule_id);
}

static void group_lock(void)
{
	spin_lock_bh(&g_lock);
}

static void group_unlock(void)
{
	spin_unlock_bh(&g_lock);
}

static void free_match_option(struct url_item *u_item)
{
	struct match_option *option, *n;
	int i;
	for (i = 0; i < IP_CT_DIR_MAX; i++) {
		list_for_each_entry_safe(option, n, &u_item->option_head[i], list) {
			list_del(&option->list);
			kfree(option);
		}
	}
}

static inline void free_url_item(struct url_item *u_item)
{
	free_match_option(u_item);
	if (u_item->private)
		kfree(u_item->private);
	kfree(u_item);
}

static inline void free_text_replace_group(struct text_replace_group *grp)
{
	struct url_item *item, *n;
	list_for_each_entry_safe(item, n, &grp->url_head, list) {
		list_del(&item->list);
		if (item->mode == HTTP_FILTER_ACCEPT_MODE) {
			white_num--;
			atomic_dec(&white_rule_num);
		} else {
			black_num--;
			atomic_dec(&black_rule_num);
		}
		free_url_item(item);
	}
	dns_tree_head_free(&grp->root);
	kfree(grp);
}

static struct text_replace_group *find_group_by_name(const char *name)
{
	struct text_replace_group *grp;

	list_for_each_entry_rcu(grp, &grp_list, list) {
		if (!strcmp(grp->name, name) && current->tgid == grp->tgid)
			return grp;
	}
	return NULL;
}

static struct text_replace_group *find_group_by_id(uint16_t id)
{
	struct text_replace_group *grp;

	list_for_each_entry_rcu(grp, &grp_list, list) {
		if (grp->id == id && current->tgid == grp->tgid)
			return grp;
	}
	return NULL;
}

static int register_text_replace_group(struct text_replace_group *reg)
{
	struct text_replace_group *grp;
	int err = 0;
	int id;
	
	group_lock();
	if (find_group_by_name(reg->name)) {
		err = -EEXIST;
		goto out;
	}
	
	id = find_first_zero_bit(text_group, TEXT_GROUP_MAX);
	if (id >= TEXT_GROUP_MAX) {
		err = -ENOMEM;
		goto out;
	}
	
	list_for_each_entry_rcu(grp, &grp_list, list) {
		if (reg->priority < grp->priority)
			break;
	}
	
	err = reg->id = id;
	set_bit(id, text_group);
	list_add_rcu(&reg->list, grp->list.prev);
out:
	group_unlock();
	return err;
}

static void unregister_text_replace_group(struct text_replace_group *reg)
{
	list_del_rcu(&reg->list);
	clear_bit(reg->id, text_group);
}

static int text_replace_delete_group_by_id(uint16_t id)
{
	struct text_replace_group *grp;
	int err = 0;

	group_lock();
	grp = find_group_by_id(id);
	if (!grp) {
		err = -EINVAL;
		group_unlock();
		goto out;
	}
	unregister_text_replace_group(grp);
	group_unlock();

	/* we must be wait rcu, because conntrack cached the url_item pointer */
	rcu_assign_pointer(grp_entry, NULL);
	synchronize_rcu();
	/* invalid the url_item pointer of conntrack  */
	flush_rule_id();

	/* now it is safe free group */
	free_text_replace_group(grp);

	/* reactivate the entry point of group */
	rcu_assign_pointer(grp_entry, &grp_list);
out:
	return err;
}

static int text_replace_mc_get_id(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *nskb;
	void *hdr;
	int err = 0;
	
	/*plus 256 for header */
	nskb = nlmsg_new(128, GFP_ATOMIC);
	if (nskb == NULL) {
		err = -ENOMEM;
		goto out;
	}

	hdr = genlmsg_put(nskb, 0, 1, &text_replace_fam, 0, HTTP_FILTER_CMD_GET_MC_ID);
	if (hdr == NULL) {	
		err = -ENOMEM;
		goto out;
	}
	NLA_PUT_U32(nskb, HTTP_FILTER_ATTR_MC_ID, text_replace_mcgrp.id);
	
	genlmsg_end(nskb, hdr);
	return genlmsg_reply(nskb, info);
	
nla_put_failure:
	err = -ENOMEM;
out:
	if (nskb)
		nlmsg_free(nskb);
	return err;
}


static int send_group_id(struct genl_info *info, uint16_t id)
{
	struct sk_buff *skb;
	void *hdr;
	int err = 0;
	
	skb = nlmsg_new(512, GFP_KERNEL);
	if (skb == NULL) {
		err = -ENOMEM;
		goto out;
	}

	hdr = genlmsg_put(skb, info->snd_pid, info->snd_seq, &text_replace_fam, 0, HTTP_FILTER_CMD_NEW_GROUP);
	if (hdr == NULL) {	
		err = -ENOMEM;
		goto out;
	}

	NLA_PUT_U16(skb, HTTP_FILTER_ATTR_GROUP_ID, id);
	genlmsg_end(skb, hdr);
	return genlmsg_reply(skb, info);
	
nla_put_failure:
	err = -ENOMEM;
out:
	if (skb)
		nlmsg_free(skb);
	return err;
}

static inline void update_match_offset(struct match_param *par, int index, 
			uint16_t match_offset, const int offset)
{
	if (!offset)
		return;
	for (; index < par->i; index++) {
		if (par->res[index].match_offset >= match_offset)
			par->res[index].match_offset += offset;
	}
}

static int text_replace_send_client_ack(struct sk_buff *skb)
{
	struct tcphdr otcph, *oth;
	struct iphdr *iph;
	int len;

	iph = ip_hdr(skb);
	oth = skb_header_pointer(skb, iph->ihl * 4,
				 sizeof(otcph), &otcph);
	if (!oth)
		return -1;

	len = skb->len - iph->ihl * 4 - oth->doff * 4;
	if (oth->fin || (oth->ack && len > 0))
		text_replace_send_tcp(skb, NF_INET_FORWARD, 1, oth->fin ? TCP_FLAG_FIN : 0, 0, NULL);
	return 0;
}

static const char *get_reason_phase_by_code(uint16_t status_code)
{
	switch (status_code) {
	case 200:
		return "OK";
	case 400:
		return "Bad Request";
	case 401:
		return "Unauthorized";
	case 403:
		return "Forbidden";
	case 404:
		return "Not Found";
	case 501:
		return "Not Implemented";
	case 503:
		return "Service Unavailable";
	default:
		return "Unkonwn";
	}
}

static inline int text_replace_send_client_rst(struct sk_buff *skb)
{
	return text_replace_send_tcp(skb, NF_INET_FORWARD, 1, TCP_FLAG_RST, 0, NULL);
}

static int text_replace_send_client_http_200(struct sk_buff *skb)
{
	int len;
	static const char data[] = "HTTP/1.1 200 OK\r\n"
	"Content-Length: 9\r\n"
	"Connection: close\r\n"
	"Server: nginx/1.8.0\r\n"
	"Content-Type: text/html\r\n"
	"Pragma: no-cache\r\n"
	"Cache-Control: no-cache\r\n\r\n<!--//-->";

	len = sizeof(data) - 1;
	text_replace_send_tcp(skb, NF_INET_FORWARD, 1, 0, len, data);
	return 0;
}

static int text_replace_send_client_http_403(struct sk_buff *skb)
{
	int len;
	static const char data[] = "HTTP/1.1 403 Forbidden\r\n"
	"Content-Length: 0\r\n"
	"Connection: close\r\n"
	"Server: nginx/1.8.0\r\n"
	"Content-Type: image/gif\r\n"
	"Pragma: no-cache\r\n"
	"Cache-Control: no-cache\r\n\r\n";

	len = sizeof(data) - 1;
	text_replace_send_tcp(skb, NF_INET_FORWARD, 1, 0, len, data);
	return 0;
}

//not use in process context 
static int text_replace_send_client_http_response(struct sk_buff *skb, struct url_item *item)
{
	struct http_response *resp;
	int len;
	if (item->private)
		return text_replace_send_tcp(skb, NF_INET_FORWARD, 1, 0, item->private_size, item->private);

	if (item->code == 200)
		return text_replace_send_client_http_200(skb);
	else if (item->code == 403)
		return text_replace_send_client_http_403(skb);

	resp = this_cpu_ptr(&http_response);

	len = snprintf(resp->data, HTTP_RESPONCE_MAX, "HTTP/1.1 %hu %s\r\n"
	"Content-Length: 0\r\n"
	"Connection: close\r\n"
	"Server: nginx/1.8.0\r\n"
	"Content-Type: image/gif\r\n"
	"Pragma: no-cache\r\n"
	"Cache-Control: no-cache\r\n\r\n", item->code, get_reason_phase_by_code(item->code));
	
	return text_replace_send_tcp(skb, NF_INET_FORWARD, 1, 0, len, resp->data);
}

int text_replace_proxy(struct sk_buff *skb)
{
	struct nf_conn *ct;
	struct nf_text_replace *ad;
	enum ip_conntrack_info ctinfo;
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_DROP;
	ad = nfct_text_replace(ct);
	if (!ad)
		return NF_DROP;

	/* drop the server packet */
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		return NF_DROP;

	if (test_bit(HTTP_FILTER_RESET_BIT, &ad->status))
		//send rst again ?
		text_replace_send_client_rst(skb);
	else if (test_bit(HTTP_FILTER_PROXY_BIT, &ad->status))
		text_replace_send_client_ack(skb);
	//else DROP it only
	
	return NF_DROP;
}

static int copy_uri(struct nf_http_log *log, int data_len, unsigned char *data)
{
	if (data_len >= 3 && !strncasecmp(data, "GET", 3)) {
			data_len -= 3;
			data += 3;
	} else if (data_len >= 4 && !strncasecmp(data, "POST", 4)) {
			data_len -= 4;
			data += 4;
	} else
		return 0;
	if (data_len) {
		while (data_len > 0 && isspace(*data)) {
			data_len--;
			data++;
		}
		if (!data_len)
			return 0;
		
		if (log->uri_len && !memcmp(data, log->uri, min((int)data_len, (int)log->uri_len)))
			return log->uri_len;
		
		data_len = min((int)data_len, (int)(sizeof(log->uri) - 1));
		
		log->uri_len = __igd_strcpy_end(log->uri, data, data_len, ' ');
		return log->uri_len;
	}
	return 0;
}

static bool generic_match(struct sk_buff *skb, struct match_option *opt, 
			struct match_param *par)
{
	struct match_result *res;
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned char *data, *match, *start;
	int i;
	uint16_t len;
	unsigned int match_len;

	iph = ip_hdr(skb);
	tcph = (void *)iph + iph->ihl*4;
	data = (void *)tcph + tcph->doff*4;
	match = data;
	
	if (par->next && (opt->opt->flags & HTTP_FILTER_MATCH_REPEAT))
		match = par->next;
	
	len = GET_MATCH_LEN(opt->opt);
	if (!len || par->i == MAX_MATCH_RESULT)
		return false;
	
	/* 	match data alg
	*	support wildcard '*' and '?'
	*/
	start = text_replace_fnmatch_alg(match, skb_tail_pointer(skb) - match, GET_MATCH_DATA(opt->opt), len, &match_len);
	if (!start)
		return false;
	
	res = &par->res[par->i];
	res->type = opt->opt->type;
	res->flags = opt->opt->flags;
	res->match_len = match_len;
	res->match_offset = start - data;
	res->rep_len = GET_REPLACE_LEN(opt->opt);
	res->rep_data = GET_REPLACE_DATA(opt->opt);
		
	for (i = 0; i < par->i; i++) {
		if (res->match_offset + res->match_len <= par->res[i].match_offset
			|| res->match_offset >= par->res[i].match_offset + 
			par->res[i].match_len) {
			continue;
		} else {
			/* matched area is overlap, can't process */
			//param->hotdrop = true;
			printk(KERN_ERR "Warning: matched area is overlap, can't process\n");
			return false; 
		}
	}

	return true;
}

static int generic_target(struct sk_buff *skb, struct match_option *opt, 
			struct match_param *par)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned char *data;
	struct match_result *res;
	int offset = 0;
	iph = ip_hdr(skb);
	tcph = (void *)iph + iph->ihl*4;
	data = (void *)tcph + tcph->doff*4;
	res = &par->res[par->i];

	/* mangle tcp data */
	if (res->rep_len <= res->match_len ||
		res->rep_len - res->match_len <= skb_tailroom(skb)) {
		if (!skb_make_writable(skb, skb->len))
			return NF_STOP;
	process:
		iph = ip_hdr(skb);
		tcph = (void *)iph + iph->ihl*4;
		data = (void *)tcph + tcph->doff*4;
		if (res->rep_len != res->match_len)
			memmove(data + res->match_offset + res->rep_len,
				data + res->match_offset + res->match_len,
				skb_tail_pointer(skb) - (data + res->match_offset + res->match_len));
		if (res->rep_len)
			memcpy(data + res->match_offset, res->rep_data, res->rep_len);
		
		if (res->rep_len > res->match_len) {
			ad_debug("%s: Extending packet by "
				 "%u from %u bytes\n", __func__, res->rep_len - res->match_len, skb->len);
			skb_put(skb, res->rep_len - res->match_len);
		} else {
			ad_debug("%s: Shrinking packet from "
				 "%u from %u bytes\n", __func__, res->match_len - res->rep_len, skb->len);
			__skb_trim(skb, skb->len + res->rep_len - res->match_len);
		}

		offset = (int)res->rep_len - (int)res->match_len;
		update_match_offset(par, 0, res->match_offset, offset);		
		par->finished++;
	} else if (par->extend < MAX_EXTEND_NUM) {
		/* try expand room  */
		par->extend++;
		if (!skb_make_writable(skb, skb->len))
			return NF_STOP;
		if (skb->len + res->rep_len - res->match_len > 65535)
			return NF_STOP;
		if (pskb_expand_head(skb, 0, res->rep_len - res->match_len + MAX_EXTEND_SIZE, GFP_ATOMIC))
			return NF_STOP;
		goto process;
	} else {
		/*	badly! record matched result 
		*  	and realloc room later
		*/
		par->rep_len += res->rep_len;
		par->match_len += res->match_len;
		par->i++;
	}
	
	/* skip the matched area and match left data */
	if (res->flags & HTTP_FILTER_MATCH_REPEAT) {
		par->next = data + res->match_offset + res->match_len + offset;
		return NF_REPEAT;
	}
	return NF_ACCEPT;
}

static int insert_target(struct sk_buff *skb, struct match_option *opt, 
			struct match_param *par)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned char *data;
	struct match_result *res;
	int offset = 0;
	iph = ip_hdr(skb);
	tcph = (void *)iph + iph->ihl*4;
	data = (void *)tcph + tcph->doff*4;
	res = &par->res[par->i];

	if (res->rep_len <= skb_tailroom(skb)) {
		if (!skb_make_writable(skb, skb->len))
			return NF_STOP;
	process:
		iph = ip_hdr(skb);
		tcph = (void *)iph + iph->ihl*4;
		data = (void *)tcph + tcph->doff*4;
		if (res->flags & HTTP_FILTER_MATCH_INSERT_BEFORE)
			offset = 0; 		/* insert before */
		else
			offset = res->match_len; /* insert after */
		
		memmove(data + res->match_offset + res->rep_len + offset,
			data + res->match_offset + offset,
			skb_tail_pointer(skb) - (data + res->match_offset + offset));
		memcpy(data + res->match_offset + offset, res->rep_data, res->rep_len);
		
		ad_debug("%s: Extending packet by "
				 "%u from %u bytes\n", __func__, res->rep_len, skb->len);
		
		skb_put(skb, res->rep_len);
		/* update offset */
		offset = res->rep_len;
		update_match_offset(par, 0, res->match_offset, offset);		
		par->finished++;
	} else if (par->extend < MAX_EXTEND_NUM) {
		par->extend++;
		if (!skb_make_writable(skb, skb->len))
			return NF_STOP;
		if (skb->len + res->rep_len > 65535)
			return NF_STOP;
		if (pskb_expand_head(skb, 0, res->rep_len + MAX_EXTEND_SIZE, GFP_ATOMIC))
			return NF_STOP;
		goto process;
	} else {
		/*	badly! record matched result 
		*  	and realloc room later
		*/
		par->rep_len += res->rep_len;
		par->i++;
	}
	
	/* skip the matched area and match left data */
	if (res->flags & HTTP_FILTER_MATCH_REPEAT) {
		par->next = data + res->match_offset + res->match_len + offset;
		return NF_REPEAT;
	}
	return NF_ACCEPT;	
}

static inline void match_param_init(struct match_param *par)
{
	par->hotdrop = false;
	par->rep_len = par->match_len = 0;
	par->next = NULL;
	par->extend = 0;
	par->i = par->finished = 0;
}

static int text_replace_match_option(unsigned int hooknum, struct sk_buff *skb, 
			struct nf_conn *ct, struct nf_text_replace *ad, 
			struct url_item *u_item, enum ip_conntrack_info ctinfo)
{
	struct match_option *op;
	struct match_result *res;
 	unsigned char *data;
	struct iphdr *iph;
	struct tcphdr *tcph;
	unsigned int oldlen, newlen;
	struct match_param *par;
	int i;
	int len;
	int offset;
	int verdict = NF_ACCEPT;
	
	
	if (skb_is_nonlinear(skb) || unlikely(skb_shared(skb)))
		goto dismatch;
	
	iph = ip_hdr(skb);
	tcph = (void *)iph + iph->ihl*4;
	/* record old len , because target function maybe mangle tcp data */
	oldlen = skb->len - iph->ihl*4 - tcph->doff*4;

	/* lock-free */
	par = this_cpu_ptr(&param);

	match_param_init(par);	
	/* match the packet  */
	list_for_each_entry(op, &u_item->option_head[CTINFO2DIR(ctinfo)], list) {
 	repeat:
		if (op->ops->match(skb, op, par)) {
			verdict = op->ops->target(skb, op, par);
			if (verdict != NF_ACCEPT) {
				if (verdict == NF_REPEAT) {
					verdict = NF_ACCEPT;
					if (par->i == MAX_MATCH_RESULT)
						break;
					goto repeat;
				}
				break;
			}
		}
		if (par->hotdrop)
			break;
		if (par->i == MAX_MATCH_RESULT)
			break;
		par->next = NULL;
	}
	
	/*	set NF_ACCEPT
	*	target func direct drop packet not permited 
	*
	*/
	verdict = NF_ACCEPT;
 	if (par->i == 0 && par->finished == 0)
		goto next_match;

	
	/*	sure the skb is linear
	*	sure alloc new skb data if skb is cloned
	*/
	if (!skb_make_writable(skb, skb->len))
		goto drop;
	
	len = par->rep_len - par->match_len;
	if (len > 0 && skb->len + len > 65535)
		goto drop;
	
	/* reload ptr */
	iph = ip_hdr(skb);
	tcph = (void *)iph + iph->ihl*4;
	data = (void *)tcph + tcph->doff*4;
	if (len > skb_tailroom(skb)) {
		if (pskb_expand_head(skb, 0, len - skb_tailroom(skb) + 16, GFP_ATOMIC))
			goto drop;
		/* reload ptr */
		iph = ip_hdr(skb);
		tcph = (void *)iph + iph->ihl*4;
		data = (void *)tcph + tcph->doff*4;
	}

	for (i = 0; i < par->i; i++) {
		res = &par->res[i];
		switch (res->type) {
		case HTTP_FILTER_TYPE_REPLACE:
			/*	get here
			*	the res->rep_len > res->match_len
			*/
			memmove(data + res->match_offset + res->rep_len,
				data + res->match_offset + res->match_len,
				skb_tail_pointer(skb) - (data + res->match_offset + res->match_len));
			
			update_match_offset(par, i + 1, res->match_offset,
				(int)res->rep_len - (int)res->match_len);
			
			if (res->rep_len > res->match_len) {
				ad_debug("%s: Extending packet by "
					 "%u from %u bytes\n", __func__, res->rep_len - res->match_len, skb->len);
				skb_put(skb, res->rep_len - res->match_len);
			} else {
				ad_debug("%s: Shrinking packet from "
					 "%u from %u bytes\n", __func__, res->match_len - res->rep_len, skb->len);
				__skb_trim(skb, skb->len + res->rep_len - res->match_len);
			}
			break;
		case HTTP_FILTER_TYPE_DELETE:
			/* delete data is already processed by target func */
			break;
		case HTTP_FILTER_TYPE_INSERT:
			if (res->flags & HTTP_FILTER_MATCH_INSERT_BEFORE)
				offset = 0; 	/* insert before */
			else
				offset = res->match_len; /* insert after */
			
			memmove(data + res->match_offset + res->rep_len + offset,
				data + res->match_offset + offset,
				skb_tail_pointer(skb) - (data + res->match_offset + offset));
			memcpy(data + res->match_offset + offset, res->rep_data, res->rep_len);
			
			ad_debug("%s: Extending packet by "
					 "%u from %u bytes\n", __func__, res->rep_len, skb->len);
			skb_put(skb, res->rep_len);
			update_match_offset(par, i + 1, res->match_offset, res->rep_len);
			break;
		default:
			break;
		}
	}

	/* MTU check , plus 8 for pppoe */
	if (skb->len + 8 > dst_mtu(skb_dst(skb)) && iph->frag_off & htons(IP_DF))
		iph->frag_off &= ~htons(IP_DF);

	/* NOT think about tcp window */
	
	/* adjust checksum .. */
	iph->tot_len = htons(skb->len);
	ip_send_check(iph);
	tcph->check = 0;
	tcph->check = tcp_v4_check(skb->len - iph->ihl*4,
			iph->saddr, iph->daddr,
			csum_partial((char *)tcph, skb->len - iph->ihl*4, 0));
	/* seq adjust  */
	newlen = skb->len - iph->ihl*4 - tcph->doff*4;
	if (newlen != oldlen && nfct_nat(ct)) {
		nf_nat_set_seq_adjust(ct, ctinfo, tcph->seq,
				      (int)newlen - (int)oldlen);
		clear_bit(IPS_SEQ_ADJUST_BIT, &ct->status);
		set_bit(HTTP_FILTER_SEQ_ADJUST_BIT, &ad->status);
	}

next_match:
	clear_bit(IGD_MATCH_URL_BW_BIT, ct_igdflag(ct));
	return verdict;
drop:
	verdict = NF_DROP;
dismatch:
	set_bit(HTTP_FILTER_DISMATCH_BIT, &ad->status);
	return verdict;
}

static bool http_pre_process(struct nf_conn *ct, struct nf_text_replace *ad, 
			struct nf_http_log *log, int data_len, unsigned char *data,
			enum ip_conntrack_dir dir)
{
	int len;
	unsigned char *start;

	if (test_bit(HTTP_FILTER_OWN_HOST_BIT, &ad->status))
		return true;
	else if (test_bit(HTTP_FILTER_MISS_HOST_BIT, &ad->status)) {
		if (dir == IP_CT_DIR_REPLY)
			return false;
		start = strnstr(data, "Host:", data_len);
		if (!start) {
			start = strnstr(data, "\r\n\r", data_len);
			/* miss HTTP request  */
			if (start)
				set_bit(HTTP_FILTER_DISMATCH_BIT, &ad->status);
			return false;
		}
		start += strlen("Host:");
		len = data_len - (start - data);
		while (len > 0 && isspace(*start)) {
			len--;
			start++;
		}
		if (!len) {
			set_bit(HTTP_FILTER_DISMATCH_BIT, &ad->status);
			return false;
		}
		
		len = min((int)len, (int)(sizeof(log->host) - 1));
		spin_lock(&ct->lock);
		log->host_len = __igd_strcpy_end(log->host, start, len, '\r');
		spin_unlock(&ct->lock);
		
		clear_bit(HTTP_FILTER_MISS_HOST_BIT, &ad->status);
		set_bit(HTTP_FILTER_OWN_HOST_BIT, &ad->status);
		return true;
	}
	
	spin_lock(&ct->lock);
	if (!log->host_len) {
		set_bit(HTTP_FILTER_MISS_HOST_BIT, &ad->status);
		if (!log->uri_len)
			copy_uri(log, data_len, data);
		spin_unlock(&ct->lock);
		return false;
	} else
		set_bit(HTTP_FILTER_OWN_HOST_BIT, &ad->status);
	spin_unlock(&ct->lock);
	return true;
}

static bool url_need_rematch(struct nf_conn *ct, struct nf_text_replace *ad,
			struct nf_http_log *log, int data_len, unsigned char *data,
			enum ip_conntrack_dir dir)
{
	int len;
	
	if (dir == IP_CT_DIR_REPLY)
		return false;	
	if (test_bit(HTTP_FILTER_MATCH_HOST_BIT, &ad->status)) {
		spin_lock(&ct->lock);
		len = copy_uri(log, data_len, data);
		spin_unlock(&ct->lock);
		if (len) {
			clear_bit(HTTP_FILTER_MATCH_HOST_BIT, &ad->status);
			return true;
		}
		return false;
	}
	return true;
}

static struct url_item *text_replace_for_each_group(struct nf_conn *ct,
				struct nf_text_replace *ad, struct nf_http_log *log)
{
	struct text_replace_group *grp;
	struct list_head *entry;
	struct igd_filter_connect_k *conn;
	int flags = 0;
	struct url_item *item = NULL;
	
	entry = rcu_dereference(grp_entry);
	if (!entry)
		return NULL;
	
	conn = ct_conn(ct);
	spin_lock(&ct->lock);
	if (ad->item) {
		item = ad->item;
		goto unlock;
	}
	if (test_bit(HTTP_FILTER_DISMATCH_BIT, &ad->status))
		goto unlock;

	group_lock();
	list_for_each_entry_rcu(grp, entry, list) {
		item = (void *)url_tree_match(&grp->root, log, &flags);
		if (!item) {
			if (flags & DNS_TREE_HOST_MATCH)
				set_bit(HTTP_FILTER_MATCH_HOST_BIT, &ad->status);
		} else {
			clear_bit(HTTP_FILTER_MATCH_HOST_BIT, &ad->status);
			ad->item = item;
			break;
		}
	}
	group_unlock();
	if (conn && conn->host && item)
		text_replace_mc_event(conn->host->key.mac, item->url.comm.name, item->id, grp->id);
unlock:
	spin_unlock(&ct->lock);
	return item;
}

static int text_replace_match_rule(unsigned int hooknum, struct sk_buff *skb)
{
	int ret;
	struct nf_text_replace *ad;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	enum ip_conntrack_dir dir;
	struct nf_http_log *log;
	struct iphdr *iph;
	struct tcphdr otcph, *oth;
	unsigned char *data;
	struct url_item *item;
	int len;
	
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || nf_ct_is_untracked(ct))
		return NF_ACCEPT;
	
	dir = CTINFO2DIR(ctinfo);
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	
	oth = skb_header_pointer(skb, iph->ihl*4,
                               sizeof(otcph), &otcph);
	/* only proccess tcp port 80 data */
	if (!oth || dir == IP_CT_DIR_ORIGINAL ?
		oth->dest != htons(80) : oth->source != htons(80))
		return NF_ACCEPT;
	
	ad = nfct_text_replace(ct);
	if (!ad) {
		if (nf_ct_is_confirmed(ct))
			return NF_ACCEPT;
		ad = nf_ct_text_replace_add(ct, GFP_ATOMIC);
		if (!ad)
			return NF_ACCEPT;
		ad->rule_id = get_current_rule_id();
	}
	
	if (test_bit(HTTP_FILTER_DISMATCH_BIT, &ad->status)) {
		return NF_ACCEPT;
	} else if (test_bit(HTTP_FILTER_NON_REPLACE_BIT, &ad->status)) {
		clear_bit(IGD_MATCH_URL_BW_BIT, ct_igdflag(ct));
		return text_replace_proxy(skb);
	} else if (test_bit(IPS_NET_PASS_BIT, &ct->status)) {
		goto dismatch;
	} else if (dir == IP_CT_DIR_ORIGINAL ? test_bit(HTTP_FILTER_ORIGINAL_MATCHED_BIT, &ad->status) : 
			test_bit(HTTP_FILTER_REPLY_MATCHED_BIT, &ad->status)) {
		goto next_match;
	}

	if (!rcu_dereference(grp_entry))
		goto dismatch;
	
	if (oth->syn)
		goto next_match;
	if (oth->rst)
		goto dismatch;
	
	len = skb->len - iph->ihl*4 - oth->doff*4;
	if (len <= 0)
		goto next_match;
	if (unlikely(skb_is_nonlinear(skb)))
		goto dismatch;

	data = skb_network_header(skb) + iph->ihl*4 + oth->doff*4;

	log = skb_get_http_log(skb);
	/* non http data */
	if (!log)
		goto dismatch;
	
	if (!http_pre_process(ct, ad, log, len, data, dir)) {
		ad_debug("miss host=%s, uri=%s\n", log->host, log->uri);
		goto next_match;
	}
	if (rule_is_expired(ad)) {
		ad->item = NULL;
		/* rematch it ??? */
		goto dismatch;
	}
	
	do {
		/* 	NOTE: 
		*	host is not change in the same http connection,
		*	if uri changed, we not process now
		*/
		/* need lock ??? */
		item = ad->item;
		if (item)
			break;
		if (dir != IP_CT_DIR_ORIGINAL)
			goto next_match;
		if (!url_need_rematch(ct, ad, log, len, data, dir))
			goto next_match;
		if ((atomic_read(&white_rule_num) || atomic_read(&black_rule_num)) && 
			(item = text_replace_for_each_group(ct, ad, log))) {
			if (item->mode != HTTP_FILTER_REPLACE_MODE)
				break;
			if (list_empty(&item->option_head[IP_CT_DIR_ORIGINAL])) {
				set_bit(HTTP_FILTER_ORIGINAL_MATCHED_BIT, &ad->status);
				if (dir == IP_CT_DIR_ORIGINAL)
					goto next_match;
			} else if (list_empty(&item->option_head[IP_CT_DIR_REPLY])) {
				set_bit(HTTP_FILTER_REPLY_MATCHED_BIT, &ad->status);
				if (dir == IP_CT_DIR_REPLY)
					goto next_match;
			}
			break;
		}
		/* if host mathed, we update uri and remtach it later */
		if (test_bit(HTTP_FILTER_MATCH_HOST_BIT, &ad->status))
			goto next_match;
		goto dismatch;
	} while (0);
	
	ret = NF_DROP;
	switch (item->mode) {
	case HTTP_FILTER_RESET_MODE:
		set_bit(HTTP_FILTER_RESET_BIT, &ad->status);
		set_bit(HTTP_FILTER_NON_REPLACE_BIT, &ad->status);
		clear_bit(IGD_MATCH_URL_BW_BIT, ct_igdflag(ct));
		text_replace_send_client_rst(skb);
		break;
	case HTTP_FILTER_PROXY_MODE:
		set_bit(HTTP_FILTER_PROXY_BIT, &ad->status);
		set_bit(HTTP_FILTER_NON_REPLACE_BIT, &ad->status);
		clear_bit(IGD_MATCH_URL_BW_BIT, ct_igdflag(ct));
		text_replace_send_client_ack(skb);
		break;
	case HTTP_FILTER_HTTP_200_MODE:
		set_bit(HTTP_FILTER_PROXY_BIT, &ad->status);
		set_bit(HTTP_FILTER_NON_REPLACE_BIT, &ad->status);
		clear_bit(IGD_MATCH_URL_BW_BIT, ct_igdflag(ct));
		text_replace_send_client_http_200(skb);
		break;
	case HTTP_FILTER_REPLACE_MODE:
		ret = text_replace_match_option(hooknum, skb, ct, ad, item, ctinfo);
		break;
	case HTTP_FILTER_DROP_MODE:
		set_bit(HTTP_FILTER_DROP_BIT, &ad->status);
		set_bit(HTTP_FILTER_NON_REPLACE_BIT, &ad->status);
		clear_bit(IGD_MATCH_URL_BW_BIT, ct_igdflag(ct));
		break;
	default:
	case HTTP_FILTER_ACCEPT_MODE:
		goto dismatch;
	case HTTP_FILTER_FAKE_RESPONSE_MODE:
		set_bit(HTTP_FILTER_PROXY_BIT, &ad->status);
		set_bit(HTTP_FILTER_NON_REPLACE_BIT, &ad->status);
		clear_bit(IGD_MATCH_URL_BW_BIT, ct_igdflag(ct));
		text_replace_send_client_http_response(skb, item);
		break;
	}
	
	return ret;
	
next_match:
	clear_bit(IGD_MATCH_URL_BW_BIT, ct_igdflag(ct));
	return NF_ACCEPT;
dismatch:
	set_bit(HTTP_FILTER_DISMATCH_BIT, &ad->status);
	return NF_ACCEPT;
}

static unsigned int text_replace_seq_adj(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct nf_text_replace *ad;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || nf_ct_is_untracked(ct))
		return NF_ACCEPT;
	
	ad = nfct_text_replace(ct);
	if (!ad)
		return NF_ACCEPT;
	
	if (test_bit(HTTP_FILTER_SEQ_ADJUST_BIT, &ad->status))
               	nf_nat_seq_adjust(skb, ct, ctinfo);
	
	return NF_ACCEPT;
}

static unsigned int text_replace_filter(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	int ret;
	rcu_read_lock();
	ret = text_replace_match_rule(hooknum, skb);
	rcu_read_unlock();

	return ret;
}

static bool policy_check(struct nlattr *nla)
{
	struct k_text_option *opt;
	int type;
	int len;
	void *data;
	type = nla_type(nla);
	len = nla_len(nla);
	data = nla_data(nla);

	switch (type) {
	case HTTP_FILTER_ATTR_URL:
	case HTTP_FILTER_ATTR_GROUP_NAME:
	case HTTP_FILTER_ATTR_CUSTOM_HTTP_RESPONSE:
		if (len < 2 || !memchr(data, '\0', len))
			return false;
		break;
	case HTTP_FILTER_ATTR_MODE:
	case HTTP_FILTER_ATTR_GROUP_ID:
	case HTTP_FILTER_ATTR_GROUP_PRIO:
	case HTTP_FILTER_ATTR_STATUS_CODE:
		if (len != 2)
			return false;
		break;
	case HTTP_FILTER_ATTR_TXT_MATCH:
		opt = (struct k_text_option *)data;
		if (len <= sizeof(struct k_text_option) + 2 * sizeof(HTTP_FILTER_LEN_TYPE))
			return false;
		len -= HTTP_FILTER_ALIGN(GET_MATCH_LEN(opt)) + sizeof(HTTP_FILTER_LEN_TYPE);
		if  (len < (int)sizeof(HTTP_FILTER_LEN_TYPE))
			return false;
		len -= HTTP_FILTER_ALIGN(GET_REPLACE_LEN(opt)) + sizeof(HTTP_FILTER_LEN_TYPE);
		if (len < 0)
			return false;
		break;
	case HTTP_FILTER_ATTR_FLAGS:
	case HTTP_FILTER_ATTR_AD_ID:
		if (len != 4)
			return false;
		break;
	default:
		break;
	}
	return true;
}

static int text_replace_delete_group(struct sk_buff *skb, struct genl_info *info)
{
	int err = 0;
	uint16_t id;
	
	if (!info->attrs[HTTP_FILTER_ATTR_GROUP_ID]) {
		err = -EINVAL;
		goto out;
	}
	if (!policy_check(info->attrs[HTTP_FILTER_ATTR_GROUP_ID])) {
		err = -EINVAL;
		goto out;
	}
	
	id = nla_get_u16(info->attrs[HTTP_FILTER_ATTR_GROUP_ID]);
	err = text_replace_delete_group_by_id(id);
	
out:
	return err;
}

static int text_replace_new_group(struct sk_buff *skb, struct genl_info *info)
{
	struct text_replace_group *grp = NULL;
	int err = 0;
	int id;

	if (!info->attrs[HTTP_FILTER_ATTR_GROUP_NAME] || !info->attrs[HTTP_FILTER_ATTR_GROUP_PRIO]) {
		err = -EINVAL;
		goto out;
	}

	if (!policy_check(info->attrs[HTTP_FILTER_ATTR_GROUP_NAME]) ||
		!policy_check(info->attrs[HTTP_FILTER_ATTR_GROUP_PRIO])) {
		err = -EINVAL;
		goto out;
	}
	
	grp = kzalloc(sizeof(struct text_replace_group), GFP_ATOMIC);
	if (!grp) {
		err = -ENOMEM;
		goto out;
	}
	INIT_LIST_HEAD(&grp->list);
	INIT_LIST_HEAD(&grp->url_head);
	dns_tree_root_init(&grp->root);
		
	snprintf(grp->name, TEXT_GROUP_NAME, "%s", (char *)nla_data(info->attrs[HTTP_FILTER_ATTR_GROUP_NAME]));
	grp->priority = nla_get_u16(info->attrs[HTTP_FILTER_ATTR_GROUP_PRIO]);
	grp->tgid = current->tgid;
	
	id = register_text_replace_group(grp);
	if (id < 0) {
		err = id;
		goto out;
	}

	err = send_group_id(info, id);
	if (err < 0)
		text_replace_delete_group_by_id(id);
	return err;
out:
	if (grp)
		kfree(grp);
	return err;
}

static void text_replace_delete_all_group(void)
{
	struct text_replace_group *grp, *next;
	rcu_assign_pointer(grp_entry, NULL);
	synchronize_rcu();
	flush_rule_id();

	group_lock();
	list_for_each_entry_safe(grp, next, &grp_list, list) {
		unregister_text_replace_group(grp);
		free_text_replace_group(grp);
	}
	atomic_set(&white_rule_num, 0);
	atomic_set(&black_rule_num, 0);
	white_num = 0;
	black_num = 0;
	group_unlock();
	
	/* reactivate the entry point of group */
	rcu_assign_pointer(grp_entry, &grp_list);
}

static int text_replace_add_rule(struct sk_buff *skb, struct genl_info *info)
{
	int err = -EINVAL;
	struct nlattr *nla;
	int nla_rem;
	struct url_item *item = NULL;
	struct match_option *option;
	struct match_ops *ops;
	struct text_replace_group *grp;
	uint16_t id;
	char url[32] = { 0, };
	char uri[32] = { 0, };


	if (!info->attrs[HTTP_FILTER_ATTR_URL] ||
		!info->attrs[HTTP_FILTER_ATTR_MODE] || !info->attrs[HTTP_FILTER_ATTR_GROUP_ID])
		return err;
	
	if (!policy_check(info->attrs[HTTP_FILTER_ATTR_URL])
		 || !policy_check(info->attrs[HTTP_FILTER_ATTR_MODE])
		 || !policy_check(info->attrs[HTTP_FILTER_ATTR_GROUP_ID]))
		return err;
	
	if (info->attrs[HTTP_FILTER_ATTR_FLAGS])
		if (!policy_check(info->attrs[HTTP_FILTER_ATTR_FLAGS]))
			return err;
	if (info->attrs[HTTP_FILTER_ATTR_AD_ID])
		if (!policy_check(info->attrs[HTTP_FILTER_ATTR_AD_ID]))
			return err;
		
	item = kzalloc(sizeof(*item), GFP_ATOMIC);
	if (!item) 
		goto error;
	if (info->attrs[HTTP_FILTER_ATTR_AD_ID])
		item->id = nla_get_u32(info->attrs[HTTP_FILTER_ATTR_AD_ID]);
	
	str_split_url(nla_data(info->attrs[HTTP_FILTER_ATTR_URL]), url, sizeof(url), uri, sizeof(uri));
	str_2_dns(url, item->url.comm.name, sizeof(item->url.comm.name));
	item->url.comm.len = strlen(item->url.comm.name);
	igd_strcpy(item->url.uri.name, uri);
	item->url.uri.len = strlen(item->url.uri.name);
	
	item->mode = nla_get_u16(info->attrs[HTTP_FILTER_ATTR_MODE]);
	item->flags = info->attrs[HTTP_FILTER_ATTR_FLAGS] ? nla_get_u32(info->attrs[HTTP_FILTER_ATTR_FLAGS]) : 0;
	INIT_LIST_HEAD(&item->list);
	INIT_LIST_HEAD(&item->option_head[IP_CT_DIR_ORIGINAL]);
	INIT_LIST_HEAD(&item->option_head[IP_CT_DIR_REPLY]);

	if (item->mode == HTTP_FILTER_REPLACE_MODE && info->attrs[HTTP_FILTER_ATTR_TXT_ORIGINAL_NEST]) {
		nla_for_each_nested(nla, info->attrs[HTTP_FILTER_ATTR_TXT_ORIGINAL_NEST], nla_rem) {
			switch (nla_type(nla)) {
			case HTTP_FILTER_ATTR_TXT_MATCH:
				if (!policy_check(nla))
					goto error;
				option = kmalloc(sizeof(struct match_option) + nla_len(nla), GFP_ATOMIC);
				if (!option)
					goto error;
				memcpy(option->opt, nla_data(nla), nla_len(nla));
				if (option->opt->type == HTTP_FILTER_TYPE_DELETE)
					list_add(&option->list, &item->option_head[IP_CT_DIR_ORIGINAL]);
				else
					list_add_tail(&option->list, &item->option_head[IP_CT_DIR_ORIGINAL]);
				ops = find_match_ops_by_type(option->opt->type);
				if (!ops)
					goto error;
				option->ops = ops;
			default:
				break;
			}
		}
	}
	
	if (item->mode == HTTP_FILTER_REPLACE_MODE && info->attrs[HTTP_FILTER_ATTR_TXT_REPLY_NEST]) {
		nla_for_each_nested(nla, info->attrs[HTTP_FILTER_ATTR_TXT_REPLY_NEST], nla_rem) {
			switch (nla_type(nla)) {
			case HTTP_FILTER_ATTR_TXT_MATCH:
				if (!policy_check(nla))
					goto error;
				option = kmalloc(sizeof(struct match_option) + nla_len(nla), GFP_ATOMIC);
				if (!option)
					goto error;
				memcpy(option->opt, nla_data(nla), nla_len(nla));
				if (option->opt->type == HTTP_FILTER_TYPE_DELETE)
					list_add(&option->list, &item->option_head[IP_CT_DIR_REPLY]);
				else
					list_add_tail(&option->list, &item->option_head[IP_CT_DIR_REPLY]);
				ops = find_match_ops_by_type(option->opt->type);
				if (!ops)
					goto error;
				option->ops = ops;
			default:
				break;
			}
		}
	}

	if (item->mode == HTTP_FILTER_REPLACE_MODE && 
		list_empty(&item->option_head[IP_CT_DIR_ORIGINAL]) &&
		list_empty(&item->option_head[IP_CT_DIR_REPLY]))
		goto error;
	if (item->mode == HTTP_FILTER_FAKE_RESPONSE_MODE) {
		if (!info->attrs[HTTP_FILTER_ATTR_STATUS_CODE] ||
			!policy_check(info->attrs[HTTP_FILTER_ATTR_STATUS_CODE]))
			goto error;
		item->code = nla_get_u16(info->attrs[HTTP_FILTER_ATTR_STATUS_CODE]);
		if (info->attrs[HTTP_FILTER_ATTR_CUSTOM_HTTP_RESPONSE]) {
			if (!policy_check(info->attrs[HTTP_FILTER_ATTR_CUSTOM_HTTP_RESPONSE]))
				goto error;
			item->private_size = nla_len(info->attrs[HTTP_FILTER_ATTR_CUSTOM_HTTP_RESPONSE]) - 1;
			item->private = kmalloc(item->private_size, GFP_ATOMIC);
			if (!item->private)
				goto error;
			memcpy(item->private, nla_data(info->attrs[HTTP_FILTER_ATTR_CUSTOM_HTTP_RESPONSE]),
					 item->private_size);
		}
 	}

	if (item->flags & HTTP_FILTER_URI_WILDCARD_MATCH)
		set_bit(DNS_TREE_URI_WILDCARD_MATCH, &item->url.flags);

	id = nla_get_u16(info->attrs[HTTP_FILTER_ATTR_GROUP_ID]);
	
	group_lock();
	grp = find_group_by_id(id);
	if (!grp) {
		group_unlock();
		goto error;
	}
	
	if (item->mode == HTTP_FILTER_ACCEPT_MODE) {
		atomic_inc(&white_rule_num);
		white_num++;	
	} else {
		atomic_inc(&black_rule_num);
		black_num++;
	}
	dns_tree_add_root(&grp->root, (void *)&item->url);
	list_add_tail(&item->list, &grp->url_head);
	group_unlock();

	return 0;
error:
	if (item)
		free_url_item(item);
	return err;
}

static struct match_ops text_replace_match_ops[] = {
	{
		.name = "replace",
		.type = HTTP_FILTER_TYPE_REPLACE,
		.match = generic_match,
		.target = generic_target,
	},
	{
		.name = "delete",
		.type = HTTP_FILTER_TYPE_DELETE,
		.match = generic_match,
		.target = generic_target,
	},
	{
		.name = "insert",
		.type = HTTP_FILTER_TYPE_INSERT,
		.match = generic_match,
		.target = insert_target,
	}
};

struct match_ops *find_match_ops_by_type(int type)
{
	struct match_ops *ops;
	list_for_each_entry(ops, &ops_list, list) {
		if (ops->type == type)
			return ops;
	}
	return NULL;
}

void unregister_match_ops(struct match_ops *ops, unsigned int n)
{
	unsigned int i;
	for (i = 0; i < n; i++)
		list_del(&ops[i].list);
}

int register_match_ops(struct match_ops *ops, unsigned int n)
{
	unsigned int i;
	int err = 0;
	struct match_ops *ops_tmp;
	for (i = 0; i < n; i++) {
		ops_tmp = find_match_ops_by_type(ops[i].type);	
		if (ops_tmp) {
			err = -EEXIST;
			goto errout;
		}
		list_add(&ops[i].list, &ops_list);
	}
	return err;
	
errout:
	if (i > 0)
		unregister_match_ops(ops, i);
	return err;
}

int match_ops_init(void)
{
	return register_match_ops(text_replace_match_ops, ARRAY_SIZE(text_replace_match_ops));
}

void match_ops_exit(void)
{
	unregister_match_ops(text_replace_match_ops, ARRAY_SIZE(text_replace_match_ops));
}

#ifdef CONFIG_PROC_FS
struct dns_parse_iter_state {
	struct hlist_head *head;
	unsigned int bucket;
	char buf[128];
};

static struct hlist_node *dns_parse_get_first(struct seq_file *seq)
{
	struct dns_parse_iter_state *st = seq->private;
	struct hlist_node *n;

	for (st->bucket = 0;
	     st->bucket < DNS_IP_HSIZE;
	     st->bucket++) {
		n = rcu_dereference(st->head[st->bucket].first);
		if (n)
			return n;
	}
	return NULL;
}

static struct hlist_node *dns_parse_get_next(struct seq_file *seq,
				      struct hlist_node *head)
{
	struct dns_parse_iter_state *st = seq->private;

	head = rcu_dereference(head->next);
	while (!head) {
		if (++st->bucket >= DNS_IP_HSIZE)
			return NULL;
		head = rcu_dereference(st->head[st->bucket].first);
	}
	return head;
}

static struct hlist_node *dns_parse_get_idx(struct seq_file *seq, loff_t pos)
{
	struct hlist_node *head = dns_parse_get_first(seq);

	if (head)
		while (pos && (head = dns_parse_get_next(seq, head)))
			pos--;
	return pos ? NULL : head;
}

static void *dns_parse_seq_start(struct seq_file *seq, loff_t *pos)
{
	rcu_read_lock();
	return dns_parse_get_idx(seq, *pos);
}

static void *dns_parse_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	(*pos)++;
	return dns_parse_get_next(s, v);
}

static void dns_parse_seq_stop(struct seq_file *s, void *v)
{
	rcu_read_unlock();
}

#undef MAC_FMT
#undef MAC_ARG
#define MAC_FMT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]

static int dns_parse_seq_show(struct seq_file *s, void *v)
{
	struct dns_parse_iter_state *st = s->private;
	struct hlist_node *n = v;
	struct dns_ip_cache *ip_cache = container_of(n, struct dns_ip_cache, hlist);
	if (seq_printf(s, "dns:%s,"NIPQUAD_FMT"\n", dns_2_str(ip_cache->name, st->buf, sizeof(st->buf)),
		NIPQUAD(ip_cache->ip)) != 0)
		return -ENOSPC;
	return 0;
}

static const struct seq_operations dns_parse_seq_ops = {
	.start = dns_parse_seq_start,
	.next = dns_parse_seq_next,
	.stop = dns_parse_seq_stop,
	.show = dns_parse_seq_show,
};

static int dns_parse_ip_proc_open(struct inode *i, struct file *file)
{
	int ret = seq_open_private(file, &dns_parse_seq_ops, sizeof(struct dns_parse_iter_state));
	if (!ret) {
		struct seq_file *seq = file->private_data;
		struct dns_parse_iter_state *st = seq->private;
		st->head =dns_ip_hash;
	}
	return ret;
}

static LIST_HEAD(subsys_list);
static LIST_HEAD(opener_list);
static MUTEX_LOCK(subsys_lock);


int register_subsys_resource(struct subsys_resource *resource)
{
	
}

int unregister_subsys_resource(struct subsys_resource *resource)
{
	
}

//global unique id 
#define TEXT_REPLACE_SUBSYS_NAME  "text_replace"
#define SUBSYS_NAMESIZ	32
//resource manage base process
struct subsys_module  {
	struct list_head list;
	char name[SUBSYS_NAMESIZ];
	int (*open)(const struct task_struct *tsk); //  bind resource to specified task 
	void (*release)(const struct task_struct *tsk);
	struct module *module;
};

struct tgid_opener {
	struct list_head list;
	int subsys;
	pid_t tgid;
};

static struct subsys_module *find_subsys_module(const char *name)
{
	struct subsys_module *res;

	list_for_each_entry(res, &subsys_list, list) {
		if (!strcmp(res->name, name)) {
			return res;
		}
	}
	return NULL;
}

static bool subsys_module_is_alive(const char *name)
{
	return !!find_subsys_module(name);
}


static int do_tag_open(void)
{
	struct file *fp;
	int fd;
	int retval;

	fd = get_unused_fd();
	if (fd >= 0) {
		fp = filp_open("/dev/null", O_RDONLY, 0);
		retval = PTR_ERR(fp);
		if (IS_ERR(fp)) {
			put_unused_fd(fd);
			return PTR_ERR(retval);
		}
		fp->f_op->release = ;
		fsnotify_open(fp);
		fd_install(fd, fp);
	}
	return fd;
}

static struct tgid_opener *find_opener(void)
{
	struct tgid_opener *opener;
	list_for_each_entry(opener, opener_list, list)
		if (current->tgid == opener->tgid)
			return opener;
	return NULL;
}

static bool opener_is_exist(void)
{
	return !!find_opener();
}

static struct tgid_opener *add_new_opener(void)
{
	struct tgid_opener *opener;

	if (opener_is_exist())
		return ERR_PTR(-EEXIST);
	opener = kmalloc(sizeof(*opener), GFP_KERNEL);
	if (!opener)
		return ERR_PTR(-ENOMEM);
	opener->tgid = current->tgid;
	list_add_tail(&opener->list, &opener_list);
	return opener;
}

static int text_replace_lock_proc_open(struct inode *i, struct file *file)
{
	struct tgid_opener *opener;

	config_lock();
	opener = add_new_opener();
	if (IS_ERR(opener)) {
		config_unlock();
		return PTR_ERR(opener);
	}
	config_unlock();
	return 0;
}

static int text_replace_lock_proc_release(struct inode *i, struct file *file)
{
	config_lock();
	if (dev_config.hooks_link) {
		nf_unregister_hooks(dns_parse_hooks, ARRAY_SIZE(dns_parse_hooks));
		fastpath_unregister_hooks(nf_dns_fastpath_hook, ARRAY_SIZE(nf_dns_fastpath_hook));
		dev_config.hooks_link = 0;
		sysctl_enable_dns_parse = 0;
	}
	config_unlock();
	destroy_hash_table();
	return 0;
}

const struct file_operations text_replace_group_proc_fops = {
	.owner = THIS_MODULE,
	.open = dns_parse_ip_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};

const struct file_operations text_replace_lock_proc_fops = {
	.owner = THIS_MODULE,
	.open = text_replace_lock_proc_open,
	.release = text_replace_lock_proc_release,
};

static struct proc_dir_entry *text_replace_proc_dir;
static int register_text_replace_procs(void)
{
	struct proc_dir_entry *res_proc;
	text_replace_proc_dir = proc_mkdir("text_replace", NULL);
	if (!text_replace_proc_dir)
		return -ENOMEM;

	res_proc = proc_create("groups", 0444, text_replace_proc_dir,
				&text_replace_group_proc_fops);
	if (!res_proc)
		goto err_nf_groups_proc;

	res_proc = proc_create("locks", 0444, text_replace_proc_dir,
				&text_replace_lock_proc_fops);
	if (!res_proc)
		goto err_nf_locks_proc;

	return 0;

err_nf_locks_proc:
	remove_proc_entry("groups", text_replace_proc_dir);
err_nf_groups_proc:
	remove_proc_entry("locks", NULL);
	return -ENOMEM;
}

static void unregister_replace_procs(void)
{
	remove_proc_entry("locks", text_replace_proc_dir);
	remove_proc_entry("groups", text_replace_proc_dir);
	remove_proc_entry("text_replace", NULL);
}
#else
static inline int register_text_replace_procs(void)
{
	return 0;
}
static inline void unregister_replace_procs(void)
{
}
#endif

static struct nf_hook_ops text_replace_filter_hook[] = {
	{
		.hook	= text_replace_filter,
		.owner	= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_FORWARD,
//		.priority	= NF_IP_PRI_IGD_FASTPATH_FORWARD - 2,
		.priority	= NF_IP_PRI_IGD_HOST_FORWARD + 1,
	},
	{
		.hook	= text_replace_seq_adj,
		.owner	= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_POST_ROUTING,
//		.priority	= NF_IP_PRI_IGD_FASTPATH_FORWARD - 1,
		.priority	= NF_IP_PRI_IGD_IOBOUND_POST_ROUTING - 1,
	}
};

static struct genl_ops text_replace_ops[] = {
	{
		.cmd = HTTP_FILTER_CMD_ADD_RULE,
		.doit = text_replace_add_rule,
	},
	{
		.cmd = HTTP_FILTER_CMD_NEW_GROUP,
		.doit = text_replace_new_group,
	},
	{
		.cmd = HTTP_FILTER_CMD_DELETE_GROUP,
		.doit = text_replace_delete_group,
	},
	{
		.cmd = HTTP_FILTER_CMD_GET_MC_ID,
		.doit = text_replace_mc_get_id,
	}
};

static __init int text_replace_init(void)
{
	int err;
	
	err = nf_text_replace_init();
	if (err < 0)
		goto err_nf_ad;
	err = match_ops_init();
	if (err < 0)
		goto err_nf_ops;
	err = genl_register_family_with_ops(&text_replace_fam,
			text_replace_ops, ARRAY_SIZE(text_replace_ops));
	if (err < 0)
		goto err_nf_genl;
	err = genl_register_mc_group(&text_replace_fam, &text_replace_mcgrp);
	if (err < 0)
		goto err_nf_mc_genl;

	err = nf_register_hooks(text_replace_filter_hook, ARRAY_SIZE(text_replace_filter_hook));
	if (err < 0)
		goto err_nf_hook;
	
	rcu_assign_pointer(grp_entry, &grp_list);
	return 0;

err_nf_hook:
	genl_unregister_mc_group(&text_replace_fam, &text_replace_mcgrp);
err_nf_mc_genl:
	genl_unregister_family(&text_replace_fam);
err_nf_genl:
	match_ops_exit();
err_nf_ops:
	nf_text_replace_exit();
err_nf_ad:
	printk(KERN_ERR "Error: load text replace  module failed\n");
	return err;
}

static void text_replace_exit(void)
{
	nf_unregister_hooks(text_replace_filter_hook, ARRAY_SIZE(text_replace_filter_hook));
	genl_unregister_family(&text_replace_fam);
	text_replace_delete_all_group();
	match_ops_exit();
	nf_text_replace_exit();
}

module_init(text_replace_init);
module_exit(text_replace_exit);


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HTTP_FILTER v1.0");
