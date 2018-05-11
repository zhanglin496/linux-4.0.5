/* Copyright (C) 2003-2013 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module implementing an IP set type: the hash:dns type */

#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <linux/ctype.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter/ipset/pfxlen.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_hash.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/ip_set_dns_hdr.h>

#define REVISION_MIN	0
#define REVISION_MAX	0	/* Counters support */


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lin Zhang <zhanglin@ifenglian.com >");
IP_SET_MODULE_DESC("hash:dns", REVISION_MIN, REVISION_MAX);
MODULE_ALIAS("ip_set_hash:dns");

#define DNS_COMPLETE_MATCH 0
#define DNS_PREFIX_MATCH	1
#define DNS_SUFFIX_MATCH	2

/* Implementation  limit */
#define IPSET_DNS_MAXLEN	256

/* Type specific function prefix */
#define HTYPE		hash_dns

/* IPv4 variants */

struct hash_dns_elem {
	struct hlist_node node;	
	size_t offset;
	u16 len;
	u8 free;
	u8 nomatch: 1,
		dns_match : 2;
	char data[0];
	/*
	*	unsigned long timeout;
	*	struct ip_set_counter counter;
	*	dns data 
	*/
};

/* declare a elem template */
#define HASH_ELEM_TMPL_DECLARE(x) \
	char x##_data[sizeof(struct hash_dns_elem)+IPSET_DNS_MAXLEN]__attribute__ ((aligned(__alignof__(struct hash_dns_elem)))); \
	struct hash_dns_elem *x = (void *)x##_data; \
	memset(x, 0, offsetof(struct hash_dns_elem, data)); \
	x->offset = offsetof(struct hash_dns_elem, data)


/* Common functions */

/* 	
*	1. example.com.cn, complete match only match "example.com.cn"
*	2. *.example.com.cn or .example.com.cn, prefix widcard match, include "example.com.cn"
*	3. example.com.cn.* or example.com.cn., suffix widcard match, include "example.com.cn"
*	4. match order:
*		first complete match, then prefix match, then suffix match
*	5. ignore case
*	6. '*' only premit appear once.
*/

static int str2dns(const char *str, char *dns, int dns_len)
{
	uint8_t *dot;
	uint8_t sublen;
	int len;
	int i;
	int j = 0;
	int ret = DNS_COMPLETE_MATCH;

	len = strlen(str);
	if (len < 2)
		return -EINVAL;

	if (dns_len < len + 2)
		return -EINVAL;

	for (i = 0; i < len; i++) {
		if (str[i] == '*')
			j++;
	}
	if (j > 1)
		return -EINVAL;

	i = 0;
	/* prefix wildcard high priority */
	if (str[i] == '*' && str[i+1] == '.') {
		str += 2;	
		len -= 2;
		ret = DNS_PREFIX_MATCH;
	} else if (str[i] == '.') {
		str += 1;
		len -= 1;
		ret = DNS_PREFIX_MATCH;
	/* 	suffix wildcard
	* 	convert example.com.cn.* to example.com.cn 
	*/
	} else if (str[len - 2] == '.' && str[len - 1] == '*') {
		len -= 2;
		ret = DNS_SUFFIX_MATCH;
	} else if (str[len - 1] == '.') {
		len -= 1;		
		ret = DNS_SUFFIX_MATCH;
	}

	/* reserved one byte for fill */	
	memcpy(dns + 1, str, len);
	dns[++len] = '\0';

	dot = (uint8_t *)dns;
	for (i = 1; i <= len; i++) {
		if (dns[i] == '.' || dns[i] == '\0') {
			sublen = (uint8_t)((uint8_t *)dns + i - dot - 1);
			if (!sublen || sublen > 63)
				return -EINVAL;			
			*dot = sublen;
			dot = (uint8_t *)(dns + i);
		}
	}

	return ret;
}

static int dns2str(const char *dns, char *str, int len)
{
	int i = 0;
	int slen = strlen(dns);
	if (slen <= 1 || len < slen)
		return -EINVAL;

	memcpy(str, dns + 1, slen);
	slen = (uint8_t)dns[i];
	i+= slen;

	for (; i < len && str[i]; i++) {
		slen = (uint8_t)str[i];
		str[i] = '.';
		i += slen;
	}
	return 0;
}

static inline bool
hash_dns_data_equal(const struct hash_dns_elem *e1,
		    const struct hash_dns_elem *e2,
		    u32 *multi)
{
	return e1->dns_match == e2->dns_match && 
			!strncmp((void *)e1 + e1->offset, (void *)e2 + e2->offset, e2->len);
}

static inline bool
hash_dns_data_list(struct sk_buff *skb, const struct hash_dns_elem *e)
{
	char *p;
	int len;
	char data[IPSET_DNS_MAXLEN];
	switch (e->dns_match) {
	case DNS_COMPLETE_MATCH:
		p = data;
		len = sizeof(data);
		break;
	case DNS_PREFIX_MATCH:
		p = data + 2;
		len = sizeof(data) - 2;
		strcpy(data, "*.");
		break;
	case DNS_SUFFIX_MATCH:
		p = data;
		len = sizeof(data) - 2;
		break;
	default:
		goto nla_put_failure;
	}

	if (dns2str((void *)e + e->offset, p, len) < 0)
		goto nla_put_failure;
	if (e->dns_match == DNS_SUFFIX_MATCH)
		strcat(p, ".*");
	if (nla_put_string(skb, IPSET_ATTR_DNS, data))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return 1;
}

static inline int
hash_dns_do_data_match(const struct hash_dns_elem *elem)
{
	return elem->nomatch ? -ENOTEMPTY : 1;
}

static inline void
hash_dns_data_set_flags(struct hash_dns_elem *elem, u32 flags)
{
	elem->nomatch = !!((flags >> 16) & IPSET_FLAG_NOMATCH);
}

static inline void
hash_dns_data_reset_flags(struct hash_dns_elem *elem, u8 *flags)
{
	swap(*flags, elem->nomatch);
}


#define MTYPE		hash_dns
#define PF		4
#include "ip_set_hash_dns.h"

static int copy_dns(struct dnshdr *dnsh, 
		const unsigned char *end, struct hash_dns_elem *e)
{	
	unsigned char *begin, *data;
	u16 dns_len;	
	u16 num_qus = ntohs(dnsh->number_questions);

	if (num_qus < 1)
		return -1;

	data = (char *)(dnsh + 1);

	/* skip 1 null byte and 2 bytes type and 2 bytes class */
	#define DNS_NAME_SKIP_BYTES 5
	/* parse query dns name */
	while (num_qus--) {
		begin = data;
		/* lookup dns name string */
		while (data < end && *data != 0)
			data++;

		if (data + DNS_NAME_SKIP_BYTES > end || *data != 0)
			goto out;
		/* type A , class IP , ignore NS query */
		if (ntohs(*(unsigned short *)(data + 1)) != DNS_QUERYTYPE_A
			 || ntohs(*((unsigned short *)(data + 3))) != DNS_QUERYCLASS_IP) {
			data += DNS_NAME_SKIP_BYTES; /* next question */
			continue;
		}

		/* plus 1 for '\0' */
		dns_len = data - begin + 1;
		if (dns_len > IPSET_DNS_MAXLEN)
			goto out;
		memcpy(e->data, begin, dns_len);
		e->len = dns_len;
		return 0;
	}
	#undef DNS_NAME_SKIP_BYTES

out:
	return -1;
}

static int parse_dns_ipv4(const struct sk_buff *skb1, struct hash_dns_elem *e,
		struct ip_set_adt_opt *opt)
{
	int len;
	int ret = -EINVAL;
	struct dnshdr *dnsh;
	struct udphdr *udph, oudph;
	const unsigned char *end;
	struct sk_buff *skb = (void *)skb1;
	struct iphdr *iph = ip_hdr(skb);

	if (iph->protocol != IPPROTO_UDP)
		goto out;

	if (skb->len < iph->ihl*4 + sizeof(*udph))
		goto out;

	udph = skb_header_pointer(skb, iph->ihl*4,
							sizeof(oudph), &oudph);
	if (!udph)
		goto out;

	len = ntohs(udph->len);
	if (skb->len < iph->ihl*4 + len  || 
		len <= sizeof(struct udphdr) + sizeof(struct dnshdr))
		goto out;

	if (skb_is_nonlinear(skb)) {
		skb = skb_copy(skb, GFP_ATOMIC);
		if (!skb)
			goto out;
		if (skb_linearize(skb))
			goto out;	
		iph = ip_hdr(skb);
		udph = (void *)((void *)iph + iph->ihl*4);
	}

	end = skb_tail_pointer(skb);
	dnsh = (struct dnshdr *)(udph + 1);
	if (opt->flags & IPSET_DIM_ONE_SRC) {
		/* check request packet */
		if (!(ntohs(dnsh->flag) >> 9)) {
			ret = copy_dns(dnsh, end, e);
		}
	} else {
		/* check response packet  */
		if ((ntohs(dnsh->flag) >> 15 & DNS_QRFLAG_RESPONSE) && 
			!((ntohs(dnsh->flag) >> 9 & DNS_QRFLAG_RESPONSE)) &&
			((ntohs(dnsh->flag) & 0x0f) == DNS_RCODEFLAG_NOERROR)) {				
			ret = copy_dns(dnsh, end, e);
		}
	}

out:
	if (skb != skb1)
		kfree_skb(skb);
	return ret;
}

static int skb_dns_extract(const struct sk_buff *skb, struct hash_dns_elem *e,
		struct ip_set_adt_opt *opt)
{
	int ret = -EINVAL;
	switch (opt->family) {
	case NFPROTO_IPV4:
		ret = parse_dns_ipv4(skb, e, opt);
		break;
	case NFPROTO_IPV6:
		/* not support now */
		break;
	default:
		break;
	}
	return ret;
}

static int
hash_dns_kadt(struct ip_set *set, const struct sk_buff *skb,
	      const struct xt_action_param *par,
	      enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	int i;
	const struct hash_dns *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];	
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, h);
	HASH_ELEM_TMPL_DECLARE(e);
#if 0
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	/* 	need conntrack support for safe ?
	*	upper application responsible for this
	*/
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || nf_ct_is_untracked(ct))
		return -EINVAL;
	if (!(opt->flags & IPSET_DIM_ONE_SRC) && !test_bit(IPS_SEEN_REPLY_BIT, &ct->status))
		return -EINVAL;
#endif

	switch (adt) {
	case IPSET_TEST:
		if (skb_dns_extract(skb, e, opt) < 0)
			return -EINVAL;
		for (i = 0; i < e->len; i++)
			e->data[i] = tolower(e->data[i]);
		break;
	default:
		return -EINVAL;
	}
	return adtfn(set, e, &ext, &opt->ext, opt->cmdflags);
}

static int
hash_dns_uadt(struct ip_set *set, struct nlattr *tb[],
	      enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	int ret;
	int i;
	const struct hash_dns *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct ip_set_ext ext = IP_SET_INIT_UEXT(h);
	HASH_ELEM_TMPL_DECLARE(e);

	if (unlikely(!tb[IPSET_ATTR_DNS] ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PACKETS) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_BYTES)))
		return -IPSET_ERR_PROTOCOL;

	ret = str2dns(nla_data(tb[IPSET_ATTR_DNS]), e->data, IPSET_DNS_MAXLEN);
	if (ret < 0)
		return -EINVAL;

	e->dns_match = ret;
	e->len = strlen(e->data) + 1;
	/* dns is not case sensitive */
	for (i = 0; i < e->len; i++)
		e->data[i] = tolower(e->data[i]);

	ret = ip_set_get_extensions(set, tb, &ext);
	if (ret)
		return ret;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	if (tb[IPSET_ATTR_CADT_FLAGS]) {
		u32 cadt_flags = ip_set_get_h32(tb[IPSET_ATTR_CADT_FLAGS]);
		if (cadt_flags & IPSET_FLAG_NOMATCH)
			flags |= (IPSET_FLAG_NOMATCH << 16);
	}

	if (adt == IPSET_TEST) {
		ret = adtfn(set, e, &ext, &ext, flags);
		return ip_set_enomatch(ret, flags, adt) ? 1 :
		       ip_set_eexist(ret, flags) ? 0 : ret;
	}

	ret = adtfn(set, e, &ext, &ext, flags);

	if (ret && !ip_set_eexist(ret, flags))
		return ret;
	else
		ret = 0;
	return ret;
}

static struct ip_set_type hash_dns_type __read_mostly = {
	.name		= "hash:dns",
	.protocol	= IPSET_PROTOCOL,
	.features	= IPSET_TYPE_IP | IPSET_TYPE_NOMATCH,
	.dimension	= IPSET_DIM_ONE,
	.family		= NFPROTO_UNSPEC,
	.revision_min	= REVISION_MIN,
	.revision_max	= REVISION_MAX,
	.create		= hash_dns_create,
	.create_policy	= {
		[IPSET_ATTR_HASHSIZE]	= { .type = NLA_U32 },
		[IPSET_ATTR_MAXELEM]	= { .type = NLA_U32 },
		[IPSET_ATTR_PROBES]	= { .type = NLA_U8 },
		[IPSET_ATTR_RESIZE]	= { .type = NLA_U8  },
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_CADT_FLAGS]	= { .type = NLA_U32 },
	},
	.adt_policy	= {
		[IPSET_ATTR_DNS] = { .type = NLA_NUL_STRING, .len = IPSET_DNS_MAXLEN - 1 },
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
	},
	.me		= THIS_MODULE,
};

static int __init
hash_dns_init(void)
{
	return ip_set_type_register(&hash_dns_type);
}

static void __exit
hash_dns_fini(void)
{
	ip_set_type_unregister(&hash_dns_type);
}

module_init(hash_dns_init);
module_exit(hash_dns_fini);
