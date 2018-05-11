/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 *                         Martin Josefsson <gandalf@wlug.westbo.se>
 * Copyright (C) 2003-2013 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module which implements the set match and SET target
 * for netfilter/iptables. */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/ip.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_set.h>
#include <linux/netfilter/ipset/ip_set_timeout.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/ip_set_dns_hdr.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
MODULE_DESCRIPTION("Xtables: IP set match and target module");
MODULE_ALIAS("xt_SET");
MODULE_ALIAS("ipt_set");
MODULE_ALIAS("ip6t_set");
MODULE_ALIAS("ipt_SET");
MODULE_ALIAS("ip6t_SET");


static DEFINE_PER_CPU(struct sk_buff *, fake_skb);

static inline int
match_set(ip_set_id_t index, const struct sk_buff *skb,
	  const struct xt_action_param *par,
	  struct ip_set_adt_opt *opt, int inv)
{
	if (ip_set_test(index, skb, par, opt))
		inv = !inv;
	return inv;
}

#define ADT_OPT(n, f, d, fs, cfs, t)	\
struct ip_set_adt_opt n = {		\
	.family	= f,			\
	.dim = d,			\
	.flags = fs,			\
	.cmdflags = cfs,		\
	.ext.timeout = t,		\
}

/* Revision 0 interface: backward compatible with netfilter/iptables */

static bool
set_match_v0(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_set_info_match_v0 *info = par->matchinfo;
	ADT_OPT(opt, par->family, info->match_set.u.compat.dim,
		info->match_set.u.compat.flags, 0, UINT_MAX);

	return match_set(info->match_set.index, skb, par, &opt,
			 info->match_set.u.compat.flags & IPSET_INV_MATCH);
}

static void
compat_flags(struct xt_set_info_v0 *info)
{
	u_int8_t i;

	/* Fill out compatibility data according to enum ip_set_kopt */
	info->u.compat.dim = IPSET_DIM_ZERO;
	if (info->u.flags[0] & IPSET_MATCH_INV)
		info->u.compat.flags |= IPSET_INV_MATCH;
	for (i = 0; i < IPSET_DIM_MAX-1 && info->u.flags[i]; i++) {
		info->u.compat.dim++;
		if (info->u.flags[i] & IPSET_SRC)
			info->u.compat.flags |= (1<<info->u.compat.dim);
	}
}

static int
set_match_v0_checkentry(const struct xt_mtchk_param *par)
{
	struct xt_set_info_match_v0 *info = par->matchinfo;
	ip_set_id_t index;

	index = ip_set_nfnl_get_byindex(info->match_set.index);

	if (index == IPSET_INVALID_ID) {
		pr_warning("Cannot find set indentified by id %u to match\n",
			   info->match_set.index);
		return -ENOENT;
	}
	if (info->match_set.u.flags[IPSET_DIM_MAX-1] != 0) {
		pr_warning("Protocol error: set match dimension "
			   "is over the limit!\n");
		ip_set_nfnl_put(info->match_set.index);
		return -ERANGE;
	}

	/* Fill out compatibility data */
	compat_flags(&info->match_set);

	return 0;
}

static void
set_match_v0_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_set_info_match_v0 *info = par->matchinfo;

	ip_set_nfnl_put(info->match_set.index);
}

static unsigned int
set_target_v0(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_set_info_target_v0 *info = par->targinfo;
	ADT_OPT(add_opt, par->family, info->add_set.u.compat.dim,
		info->add_set.u.compat.flags, 0, UINT_MAX);
	ADT_OPT(del_opt, par->family, info->del_set.u.compat.dim,
		info->del_set.u.compat.flags, 0, UINT_MAX);

	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_add(info->add_set.index, skb, par, &add_opt);
	if (info->del_set.index != IPSET_INVALID_ID)
		ip_set_del(info->del_set.index, skb, par, &del_opt);

	return XT_CONTINUE;
}

static int
set_target_v0_checkentry(const struct xt_tgchk_param *par)
{
	struct xt_set_info_target_v0 *info = par->targinfo;
	ip_set_id_t index;

	if (info->add_set.index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(info->add_set.index);
		if (index == IPSET_INVALID_ID) {
			pr_warning("Cannot find add_set index %u as target\n",
				   info->add_set.index);
			return -ENOENT;
		}
	}

	if (info->del_set.index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(info->del_set.index);
		if (index == IPSET_INVALID_ID) {
			pr_warning("Cannot find del_set index %u as target\n",
				   info->del_set.index);
			if (info->add_set.index != IPSET_INVALID_ID)
				ip_set_nfnl_put(info->add_set.index);
			return -ENOENT;
		}
	}
	if (info->add_set.u.flags[IPSET_DIM_MAX-1] != 0 ||
	    info->del_set.u.flags[IPSET_DIM_MAX-1] != 0) {
		pr_warning("Protocol error: SET target dimension "
			   "is over the limit!\n");
		if (info->add_set.index != IPSET_INVALID_ID)
			ip_set_nfnl_put(info->add_set.index);
		if (info->del_set.index != IPSET_INVALID_ID)
			ip_set_nfnl_put(info->del_set.index);
		return -ERANGE;
	}

	/* Fill out compatibility data */
	compat_flags(&info->add_set);
	compat_flags(&info->del_set);

	return 0;
}

static void
set_target_v0_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_set_info_target_v0 *info = par->targinfo;

	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(info->add_set.index);
	if (info->del_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(info->del_set.index);
}

/* Revision 1 match and target */

static bool
set_match_v1(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_set_info_match_v1 *info = par->matchinfo;
	ADT_OPT(opt, par->family, info->match_set.dim,
		info->match_set.flags, 0, UINT_MAX);

	if (opt.flags & IPSET_RETURN_NOMATCH)
		opt.cmdflags |= IPSET_FLAG_RETURN_NOMATCH;

	return match_set(info->match_set.index, skb, par, &opt,
			 info->match_set.flags & IPSET_INV_MATCH);
}

static int
set_match_v1_checkentry(const struct xt_mtchk_param *par)
{
	struct xt_set_info_match_v1 *info = par->matchinfo;
	ip_set_id_t index;

	index = ip_set_nfnl_get_byindex(info->match_set.index);

	if (index == IPSET_INVALID_ID) {
		pr_warning("Cannot find set indentified by id %u to match\n",
			   info->match_set.index);
		return -ENOENT;
	}
	if (info->match_set.dim > IPSET_DIM_MAX) {
		pr_warning("Protocol error: set match dimension "
			   "is over the limit!\n");
		ip_set_nfnl_put(info->match_set.index);
		return -ERANGE;
	}

	return 0;
}

static void
set_match_v1_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_set_info_match_v1 *info = par->matchinfo;

	ip_set_nfnl_put(info->match_set.index);
}

static unsigned int
set_target_v1(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_set_info_target_v1 *info = par->targinfo;
	ADT_OPT(add_opt, par->family, info->add_set.dim,
		info->add_set.flags, 0, UINT_MAX);
	ADT_OPT(del_opt, par->family, info->del_set.dim,
		info->del_set.flags, 0, UINT_MAX);

	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_add(info->add_set.index, skb, par, &add_opt);
	if (info->del_set.index != IPSET_INVALID_ID)
		ip_set_del(info->del_set.index, skb, par, &del_opt);

	return XT_CONTINUE;
}

static int
set_target_v1_checkentry(const struct xt_tgchk_param *par)
{
	const struct xt_set_info_target_v1 *info = par->targinfo;
	ip_set_id_t index;

	if (info->add_set.index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(info->add_set.index);
		if (index == IPSET_INVALID_ID) {
			pr_warning("Cannot find add_set index %u as target\n",
				   info->add_set.index);
			return -ENOENT;
		}
	}

	if (info->del_set.index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(info->del_set.index);
		if (index == IPSET_INVALID_ID) {
			pr_warning("Cannot find del_set index %u as target\n",
				   info->del_set.index);
			if (info->add_set.index != IPSET_INVALID_ID)
				ip_set_nfnl_put(info->add_set.index);
			return -ENOENT;
		}
	}
	if (info->add_set.dim > IPSET_DIM_MAX ||
	    info->del_set.dim > IPSET_DIM_MAX) {
		pr_warning("Protocol error: SET target dimension "
			   "is over the limit!\n");
		if (info->add_set.index != IPSET_INVALID_ID)
			ip_set_nfnl_put(info->add_set.index);
		if (info->del_set.index != IPSET_INVALID_ID)
			ip_set_nfnl_put(info->del_set.index);
		return -ERANGE;
	}

	return 0;
}

static void
set_target_v1_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_set_info_target_v1 *info = par->targinfo;

	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(info->add_set.index);
	if (info->del_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(info->del_set.index);
}

/* Revision 2 target */

static unsigned int
set_target_v2(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_set_info_target_v2 *info = par->targinfo;
	ADT_OPT(add_opt, par->family, info->add_set.dim,
		info->add_set.flags, info->flags, info->timeout);
	ADT_OPT(del_opt, par->family, info->del_set.dim,
		info->del_set.flags, 0, UINT_MAX);

	/* Normalize to fit into jiffies */
	if (add_opt.ext.timeout != IPSET_NO_TIMEOUT &&
	    add_opt.ext.timeout > UINT_MAX/MSEC_PER_SEC)
		add_opt.ext.timeout = UINT_MAX/MSEC_PER_SEC;
	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_add(info->add_set.index, skb, par, &add_opt);
	if (info->del_set.index != IPSET_INVALID_ID)
		ip_set_del(info->del_set.index, skb, par, &del_opt);

	return XT_CONTINUE;
}

#define set_target_v2_checkentry	set_target_v1_checkentry
#define set_target_v2_destroy		set_target_v1_destroy

/* Revision 3 match */

static bool
match_counter(u64 counter, const struct ip_set_counter_match *info)
{
	switch (info->op) {
	case IPSET_COUNTER_NONE:
		return true;
	case IPSET_COUNTER_EQ:
		return counter == info->value;
	case IPSET_COUNTER_NE:
		return counter != info->value;
	case IPSET_COUNTER_LT:
		return counter < info->value;
	case IPSET_COUNTER_GT:
		return counter > info->value;
	}
	return false;
}

static bool
set_match_v3(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_set_info_match_v3 *info = par->matchinfo;
	ADT_OPT(opt, par->family, info->match_set.dim,
		info->match_set.flags, info->flags, UINT_MAX);
	int ret;

	if (info->packets.op != IPSET_COUNTER_NONE ||
	    info->bytes.op != IPSET_COUNTER_NONE)
		opt.cmdflags |= IPSET_FLAG_MATCH_COUNTERS;

	ret = match_set(info->match_set.index, skb, par, &opt,
			info->match_set.flags & IPSET_INV_MATCH);

	if (!(ret && opt.cmdflags & IPSET_FLAG_MATCH_COUNTERS))
		return ret;

	if (!match_counter(opt.ext.packets, &info->packets))
		return 0;
	return match_counter(opt.ext.bytes, &info->bytes);
}

#define set_match_v3_checkentry	set_match_v1_checkentry
#define set_match_v3_destroy	set_match_v1_destroy

struct dns_set_ops {
	int (*ct_dump)(struct sk_buff *skb,
			       const struct nf_conntrack_tuple *t);
	int (*dns_dump)(struct sk_buff *skb, const char *dns);
	int (*ip_dump)(struct sk_buff *skb, __be32 ip);
	int (*dns_ip_set_add)(const struct xt_dns_set_info_target_v1 *info, 
			const struct xt_action_param *par, __be32 ip, __be32 timeout);
};

struct dns_dump_control {
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct nf_conn *ct;
	int type;
	int group;
};

#if defined(CONFIG_NETFILTER_NETLINK_MODULE) || defined(CONFIG_NETFILTER_NETLINK)
static int dns_ctnetlink_event(struct nf_conn *ct, const char *name, const struct dns_set_ops *ops)
{
	struct net *net;
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfmsg;
	struct sk_buff *skb;
	struct nlattr *nest_parms;
	unsigned int type;
	unsigned int flags = 0, group = NFNLGRP_CONNTRACK_DNS_NEW;
	int err;

	net = nf_ct_net(ct);
	if (!nfnetlink_has_listeners(net, group))
		goto errout;

	/* 512 is a guess value */
	type = IPCTNL_MSG_CT_DNS_REQUEST;
	skb = nlmsg_new(512, GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	type |= NFNL_SUBSYS_CTNETLINK << 8;
	nlh = nlmsg_put(skb, 0, 0, type, sizeof(*nfmsg), flags);
	if (nlh == NULL)
		goto nlmsg_failure;

	nfmsg = nlmsg_data(nlh);
	nfmsg->nfgen_family = nf_ct_l3num(ct);
	nfmsg->version	= NFNETLINK_V0;
	nfmsg->res_id	= 0;

	rcu_read_lock();
	nest_parms = nla_nest_start(skb, CTA_TUPLE_ORIG | NLA_F_NESTED);
	if (!nest_parms)
		goto nla_put_failure;
	if (ops->ct_dump(skb, nf_ct_tuple(ct, IP_CT_DIR_ORIGINAL)) < 0)
		goto nla_put_failure;
	nla_nest_end(skb, nest_parms);

	if (ops->dns_dump(skb, name) < 0)
		goto nla_put_failure;	
	rcu_read_unlock();

	nlmsg_end(skb, nlh);
	err = nfnetlink_send(skb, net, 0, group, 0,
			     GFP_ATOMIC);
	if (err == -ENOBUFS || err == -EAGAIN)
		return -ENOBUFS;

	return 0;

nla_put_failure:
	rcu_read_unlock();
	nlmsg_cancel(skb, nlh);
nlmsg_failure:
	kfree_skb(skb);
errout:
	return -1;
}

static struct sk_buff *init_dns_log_msg(struct dns_dump_control *ctl)
{
	struct net *net;
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfmsg;
	struct sk_buff *skb;
	unsigned int type;
	unsigned int flags = 0;

	net = nf_ct_net(ctl->ct);
	if (!nfnetlink_has_listeners(net, ctl->group))
		goto errout;

	/* 512 is a guess value */
	type = ctl->type;
	skb = nlmsg_new(512, GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	type |= NFNL_SUBSYS_CTNETLINK << 8;
	nlh = nlmsg_put(skb, 0, 0, type, sizeof(*nfmsg), flags);
	if (nlh == NULL)
		goto nlmsg_failure;

	nfmsg = nlmsg_data(nlh);
	nfmsg->nfgen_family = nf_ct_l3num(ctl->ct);
	nfmsg->version	= NFNETLINK_V0;
	nfmsg->res_id	= 0;
	ctl->skb = skb;
	ctl->nlh = nlh;
	return skb;

nlmsg_failure:
	kfree_skb(skb);
errout:
	return NULL;
}
#else
static inline int dns_ctnetlink_event(struct nf_conn *ct, const char *name, const struct dns_set_ops *ops)
{
	return 0;
}
static inline struct sk_buff *init_dns_log_msg(struct dns_dump_control *ctl)
{
	return NULL;
}
#endif

static int parse_dns_ipv4_reply(struct sk_buff *skb, struct nf_conn *ct, 
			struct dnshdr *dnsh, const unsigned char *end, const struct xt_dns_set_info_target_v1 *info,
			const struct xt_action_param *par, const struct dns_set_ops *ops)
{	
	unsigned char *begin, *data;
	struct dnsansip *ansip;
	struct nlattr *nest_parms;
	struct dns_dump_control ctl;
	__be32 ttl;
	u16 dns_len;	
	u16 match_len = 0;	
	char *name = NULL;
	u16 num_qus = ntohs(dnsh->number_questions);
	u16 num_ans  = ntohs(dnsh->number_answers);

	if (num_qus != 1 || num_ans < 1)
		return -1;

	ctl.skb = NULL;
	if (info->flags & IPSET_DNS_SET_LOG) {
		ctl.ct = ct;
		ctl.type = IPCTNL_MSG_CT_DNS_REPLY;
		ctl.group = NFNLGRP_CONNTRACK_DNS_NEW;
		ctl.skb = init_dns_log_msg(&ctl);
	}

	if (ctl.skb) {
		rcu_read_lock();
		nest_parms = nla_nest_start(ctl.skb, CTA_TUPLE_ORIG | NLA_F_NESTED);
		if (!nest_parms || ops->ct_dump(ctl.skb, nf_ct_tuple(ct, IP_CT_DIR_ORIGINAL)) < 0) {
			rcu_read_unlock();
			goto out;
		}
		rcu_read_unlock();
		nla_nest_end(ctl.skb, nest_parms);
	}

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
		if (!match_len) {
			match_len = (char *)begin - (char *)dnsh;
			name = begin;
			if (ctl.skb)
				ops->dns_dump(ctl.skb, name);
		}
		/* next question */
		data += DNS_NAME_SKIP_BYTES; 
	}
	#undef DNS_NAME_SKIP_BYTES

	/* no right answers */
	if (!match_len || !name)
		goto out;

	if (ctl.skb) {
		nest_parms = nla_nest_start(ctl.skb, CTA_DNS_IP | NLA_F_NESTED);
		if (!nest_parms)
			goto out;
	}

	while (num_ans-- && (data + sizeof(struct dnsansip) <= end)) {
		ansip = (struct dnsansip *)data;
		/* we not process non pointer offset from dns answers */
		if ((ntohs(ansip->dns_hd) >> DNS_PTR_OFFSET) != DNS_PTR_FLAG)
			break;

		switch (ntohs(ansip->dns_type)) {
		case DNS_QUERYTYPE_A:
			if ((ntohs(ansip->data_len) == 4) &&
				((ntohs(ansip->dns_hd) & DNS_PTR_MASK) == match_len)) {
				if (ipv4_is_multicast(ansip->addr) || ipv4_is_loopback(ansip->addr) ||
					ipv4_is_lbcast(ansip->addr) || ansip->addr == 0)
					break;
				if (ctl.skb)
					ops->ip_dump(ctl.skb, ansip->addr);
				if (info->add_set.index != IPSET_INVALID_ID && ops->dns_ip_set_add) {
					memcpy(&ttl, &ansip->dns_ttl1, sizeof(ttl));
					ops->dns_ip_set_add(info, par, ansip->addr, ttl);
				}
			}
			break;
		case DNS_QUERYTYPE_CNAME:
			if ((ntohs(ansip->dns_hd) & DNS_PTR_MASK) == match_len)
				match_len = (char *)data + offsetof(struct dnsansip, addr)
						- (char *)dnsh;
			break;
		default:
			break;
		}
		/* next answer  */
		data += ntohs(ansip->data_len) + offsetof(struct dnsansip, addr);
	}

	if (ctl.skb) {
		nla_nest_end(ctl.skb, nest_parms);
		nlmsg_end(ctl.skb, ctl.nlh);
		nfnetlink_send(ctl.skb, nf_ct_net(ct), 0, ctl.group, 0,
					 GFP_ATOMIC);
	}
	return 0;

out:
	if (ctl.skb)
		kfree_skb(ctl.skb);
	return -1;
}

static int parse_dns_ipv4_request(struct sk_buff *skb, struct nf_conn *ct, 
			struct dnshdr *dnsh, const unsigned char *end, const struct xt_dns_set_info_target_v1 *info,
			const struct xt_action_param *par, const struct dns_set_ops *ops)
{	
	unsigned char *begin, *data;	
	u16 dns_len;	
	char *name = NULL;
	int match_len = 0;
	u16 num_qus = ntohs(dnsh->number_questions);

	if (num_qus != 1)
		return -1;

	if (!(info->flags & IPSET_DNS_SET_LOG))
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
		if (!match_len) {
			match_len = (char *)begin - (char *)dnsh;
			name = begin;
			dns_ctnetlink_event(ct, name, ops);
			break;
		}
		/* next question */
		data += DNS_NAME_SKIP_BYTES; 
	}
	#undef DNS_NAME_SKIP_BYTES

	/* no right answers */
	if (!match_len || !name)
		goto out;
	return 0;
out:
	return -1;
}


static int ipv4_tuple_to_nlattr(struct sk_buff *skb,
				const struct nf_conntrack_tuple *tuple)
{
	if (nla_put_net32(skb, CTA_IP_V4_SRC, tuple->src.u3.ip) ||
	    nla_put_net32(skb, CTA_IP_V4_DST, tuple->dst.u3.ip))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -1;
}

static int ipv4_dns_to_nlattr(struct sk_buff *skb,
				const char *dns)
{
	if (nla_put_string(skb, CTA_IP_V4_DNS, dns))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -1;
}

static int ipv4_to_nlattr(struct sk_buff *skb,
				__be32 ip)
{
	if (nla_put_net32(skb, CTA_IP_V4_SRC, ip))
		goto nla_put_failure;
	return 0;

nla_put_failure:
	return -1;
}

#define DNS_MAX_TTL (12*3600)

static uint32_t adjust_ttl_time(__be32 timeout)
{
	uint32_t seed;
	get_random_bytes(&seed, sizeof(seed));
	seed &= 1200;
	if (seed < 600)
		seed = 600;

	timeout = ntohl(timeout);
	if (timeout > DNS_MAX_TTL) {
		timeout = DNS_MAX_TTL;
	} else if (!timeout) {
		timeout = seed;
	} else 
		timeout += seed;
	return timeout;
}

static int ipv4_dns_add(const struct xt_dns_set_info_target_v1 *info, const struct xt_action_param *par, 
		__be32 ip, __be32 timeout)
{
	struct iphdr *iph;
	struct sk_buff *skb;
	uint32_t ttl = adjust_ttl_time(timeout);
	ADT_OPT(add_opt, par->family, info->add_set.dim,
		info->add_set.flags, info->cmdflags, ttl);
	skb = __get_cpu_var(fake_skb);
	iph = ip_hdr(skb);
	iph->saddr = iph->daddr = ip;

	/* Normalize to fit into jiffies */
	if (add_opt.ext.timeout != IPSET_NO_TIMEOUT &&
	    add_opt.ext.timeout > UINT_MAX/MSEC_PER_SEC)
		add_opt.ext.timeout = UINT_MAX/MSEC_PER_SEC;

	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_add(info->add_set.index, skb, par, &add_opt);

	return 0;
}

static const struct dns_set_ops ipv4_dns_ops =  {
	.ct_dump = ipv4_tuple_to_nlattr,
	.dns_dump = ipv4_dns_to_nlattr,
	.ip_dump = ipv4_to_nlattr,
	.dns_ip_set_add = ipv4_dns_add,
};

static int process_dns_v4_packet(struct sk_buff *skb, const struct xt_dns_set_info_target_v1 *info,
		const struct xt_action_param *par)
{
	int ret = -1;
	struct nf_conn *ct;
	struct dnshdr *dnsh;
	struct udphdr *udph;
	enum ip_conntrack_info ctinfo;
	const unsigned char *end;
	struct iphdr *iph;
	u16 len;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || nf_ct_is_untracked(ct))
		goto out;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		goto out;

	if (skb_linearize(skb))
		goto out;

	iph = ip_hdr(skb);
	if (!pskb_may_pull(skb, iph->ihl*4 + sizeof(*udph)))
		goto out;

	udph = (void *)((char *)iph + iph->ihl*4);
	len = ntohs(udph->len);
	if (skb->len < iph->ihl*4 + len  || 
		len <= sizeof(struct udphdr) + sizeof(struct dnshdr))
		goto out;

	end = skb_tail_pointer(skb);
	dnsh = (struct dnshdr *)(udph + 1);

	/* check request packet */
	if (!(ntohs(dnsh->flag) >> 9)) {
		ret = parse_dns_ipv4_request(skb, ct, dnsh, end, info, par, &ipv4_dns_ops);
	} else if ((ntohs(dnsh->flag) >> 15 & DNS_QRFLAG_RESPONSE) && 
		!((ntohs(dnsh->flag) >> 9 & DNS_QRFLAG_RESPONSE)) &&
		((ntohs(dnsh->flag) & 0x0f) == DNS_RCODEFLAG_NOERROR)) {
		ret = parse_dns_ipv4_reply(skb, ct, dnsh, end, info, par, &ipv4_dns_ops);
	}

out:
	return ret;
}

static unsigned int
dns_set_target_v1(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_dns_set_info_target_v1 *info = par->targinfo;
	if (info->flags || info->add_set.index != IPSET_INVALID_ID)
		process_dns_v4_packet(skb, info, par);

	return XT_CONTINUE;
}

static bool ip_set_is_compat(ip_set_id_t index)
{
	bool ret = true;
	struct ip_set *set;

	rcu_read_lock();
	set = __ip_set_get_by_rcu(index);
	if (!(set->type->features & IPSET_TYPE_IP)) {
		ret = false;
		goto out;
	}
	if (set->type->features & (IPSET_TYPE_MAC | IPSET_TYPE_IFACE |
		IPSET_TYPE_PORT)) {
		ret = false;
		goto out;
	}
out:
	rcu_read_unlock();
	return ret;
}

static int dns_set_target_v1_checkentry(const struct xt_tgchk_param *par)
{
	struct xt_dns_set_info_target_v1 *info = par->targinfo;
	ip_set_id_t index;
	struct ip_set *set;

	if (info->add_set.index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(info->add_set.index);
		if (index == IPSET_INVALID_ID) {
			printk("Cannot find add_set index %u as target\n",
				   info->add_set.index);
			return -ENOENT;
		}
		if (!ip_set_is_compat(index))
			return -EINVAL;
	}

	if (info->add_set.dim > IPSET_DIM_MAX) {
		pr_warning("Protocol error: SET target dimension "
			   "is over the limit!\n");
		if (info->add_set.index != IPSET_INVALID_ID)
			ip_set_nfnl_put(info->add_set.index);
		return -ERANGE;
	}

	if (info->add_set.index == IPSET_INVALID_ID &&
		!(info->flags & IPSET_DNS_SET_LOG))
		return -EINVAL;

	return 0;
}

static void
dns_set_target_v1_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_dns_set_info_target_v1 *info = par->targinfo;
	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(info->add_set.index);
}

static struct xt_match set_matches[] __read_mostly = {
	{
		.name		= "set",
		.family		= NFPROTO_IPV4,
		.revision	= 0,
		.match		= set_match_v0,
		.matchsize	= sizeof(struct xt_set_info_match_v0),
		.checkentry	= set_match_v0_checkentry,
		.destroy	= set_match_v0_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "set",
		.family		= NFPROTO_IPV4,
		.revision	= 1,
		.match		= set_match_v1,
		.matchsize	= sizeof(struct xt_set_info_match_v1),
		.checkentry	= set_match_v1_checkentry,
		.destroy	= set_match_v1_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "set",
		.family		= NFPROTO_IPV6,
		.revision	= 1,
		.match		= set_match_v1,
		.matchsize	= sizeof(struct xt_set_info_match_v1),
		.checkentry	= set_match_v1_checkentry,
		.destroy	= set_match_v1_destroy,
		.me		= THIS_MODULE
	},
	/* --return-nomatch flag support */
	{
		.name		= "set",
		.family		= NFPROTO_IPV4,
		.revision	= 2,
		.match		= set_match_v1,
		.matchsize	= sizeof(struct xt_set_info_match_v1),
		.checkentry	= set_match_v1_checkentry,
		.destroy	= set_match_v1_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "set",
		.family		= NFPROTO_IPV6,
		.revision	= 2,
		.match		= set_match_v1,
		.matchsize	= sizeof(struct xt_set_info_match_v1),
		.checkentry	= set_match_v1_checkentry,
		.destroy	= set_match_v1_destroy,
		.me		= THIS_MODULE
	},
	/* counters support: update, match */
	{
		.name		= "set",
		.family		= NFPROTO_IPV4,
		.revision	= 3,
		.match		= set_match_v3,
		.matchsize	= sizeof(struct xt_set_info_match_v3),
		.checkentry	= set_match_v3_checkentry,
		.destroy	= set_match_v3_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "set",
		.family		= NFPROTO_IPV6,
		.revision	= 3,
		.match		= set_match_v3,
		.matchsize	= sizeof(struct xt_set_info_match_v3),
		.checkentry	= set_match_v3_checkentry,
		.destroy	= set_match_v3_destroy,
		.me		= THIS_MODULE
	},
};

static struct xt_target set_targets[] __read_mostly = {
	{
		.name		= "SET",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.target		= set_target_v0,
		.targetsize	= sizeof(struct xt_set_info_target_v0),
		.checkentry	= set_target_v0_checkentry,
		.destroy	= set_target_v0_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "SET",
		.revision	= 1,
		.family		= NFPROTO_IPV4,
		.target		= set_target_v1,
		.targetsize	= sizeof(struct xt_set_info_target_v1),
		.checkentry	= set_target_v1_checkentry,
		.destroy	= set_target_v1_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "SET",
		.revision	= 1,
		.family		= NFPROTO_IPV6,
		.target		= set_target_v1,
		.targetsize	= sizeof(struct xt_set_info_target_v1),
		.checkentry	= set_target_v1_checkentry,
		.destroy	= set_target_v1_destroy,
		.me		= THIS_MODULE
	},
	/* --timeout and --exist flags support */
	{
		.name		= "SET",
		.revision	= 2,
		.family		= NFPROTO_IPV4,
		.target		= set_target_v2,
		.targetsize	= sizeof(struct xt_set_info_target_v2),
		.checkentry	= set_target_v2_checkentry,
		.destroy	= set_target_v2_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "SET",
		.revision	= 2,
		.family		= NFPROTO_IPV6,
		.target		= set_target_v2,
		.targetsize	= sizeof(struct xt_set_info_target_v2),
		.checkentry	= set_target_v2_checkentry,
		.destroy	= set_target_v2_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "DNS_SET",
		.revision	= 1,
		.family		= NFPROTO_IPV4,
		.target		= dns_set_target_v1,
		.targetsize	= sizeof(struct xt_dns_set_info_target_v1),
		.checkentry	= dns_set_target_v1_checkentry,
		.destroy	= dns_set_target_v1_destroy,
		.me		= THIS_MODULE
	},
};

static struct iphdr *xt_build_ipv4(struct sk_buff *skb, __be32 saddr, __be32 daddr)
{
        struct iphdr *iph;

        skb_reset_network_header(skb);
        iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
        iph->version = 4;
        iph->ihl = sizeof(*iph) / 4;
        iph->tos = 0;
        iph->id = 0;
        iph->frag_off = htons(IP_DF);
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = saddr;
        iph->daddr = daddr;

        return iph;
}

static struct tcphdr *xt_build_tcp(struct sk_buff *skb)
{
	struct tcphdr *tcph;

	skb_reset_transport_header(skb);
	tcph = (struct tcphdr *)skb_put(skb, sizeof(struct tcphdr));
	tcph->source 	= htons(80);
	tcph->dest = htons(80);
	tcph->seq = htonl(0x4c25192d);
	tcph->ack_seq = 0;
	tcp_flag_word(tcph) = TCP_FLAG_SYN;
	tcph->doff = sizeof(struct tcphdr) / 4;
	tcph->window = htons(512);
	tcph->check	= 0;
	tcph->urg_ptr	= 0;

	return tcph;
}

static void free_per_cpu_skb(void)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct sk_buff *skb = per_cpu(fake_skb, cpu);
		if (skb)
			kfree_skb(skb);
	}
}

static int alloc_per_cpu_skb(void)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct sk_buff *skb;
		skb = alloc_skb(LL_MAX_HEADER + sizeof(struct iphdr) + sizeof(struct tcphdr), GFP_KERNEL);
		if (!skb)
			goto out;
		skb_reserve(skb, LL_MAX_HEADER);
		skb->protocol = htons(ETH_P_IP);
		xt_build_ipv4(skb, 0, 0);
		xt_build_tcp(skb);
		per_cpu(fake_skb, cpu) = skb;
	}
	return 0;

out:
	free_per_cpu_skb();
	return -ENOMEM;
}

static int __init xt_set_init(void)
{
	int ret;
	ret = alloc_per_cpu_skb();
	if (ret)
		goto err_xt_percpu;

	ret = xt_register_matches(set_matches, ARRAY_SIZE(set_matches));
	if (ret)
		goto err_xt_match;

	ret = xt_register_targets(set_targets,
					  ARRAY_SIZE(set_targets));
	if (ret)
		goto err_xt_target;

	return ret;

err_xt_target:
	xt_unregister_matches(set_matches,
		      ARRAY_SIZE(set_matches));
err_xt_match:
	free_per_cpu_skb();
err_xt_percpu:
	return ret;
}

static void __exit xt_set_fini(void)
{
	xt_unregister_matches(set_matches, ARRAY_SIZE(set_matches));
	xt_unregister_targets(set_targets, ARRAY_SIZE(set_targets));
	free_per_cpu_skb();
}

module_init(xt_set_init);
module_exit(xt_set_fini);
