/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 *                         Martin Josefsson <gandalf@wlug.westbo.se>
 * Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.  
 */

/* Shared library add-on to iptables to add IP set mangling target. */
#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include <xtables.h>
#include <linux/netfilter/xt_set.h>
#include "libxt_set.h"

/* Revision 1 */

struct xt_dns_set_info_target_v1 {
	struct xt_set_info add_set;
	struct xt_set_info del_set;
	__u32 flags;
	__u32 cmdflags;
};

static void
dns_set_target_help_v1(void)
{
	printf("DNS_SET target options:\n"
	       " --add-set name flags [--exist] \n"
	       "		add dns A records to named sets\n"
	       " --log		broadcast dns message use nfnetlink\n");
}

static const struct option dns_set_target_opts_v1[] = {
	{.name = "add-set", .has_arg = true, .val = '1'},
	{.name = "log", .has_arg = false, .val = '2'},	
	{.name = "del-set", .has_arg = true,  .val = '3'},
	{.name = "exist",	.has_arg = false, .val = '4'},
	XT_GETOPT_TABLEEND,
};

static void
dns_set_target_check_v1(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			   "You must specify either `--add-set' or `--log'");
}

static void
dns_set_target_init_v1(struct xt_entry_target *target)
{
	struct xt_dns_set_info_target_v1 *info =
		(struct xt_dns_set_info_target_v1 *) target->data;

	info->add_set.index = info->del_set.index = IPSET_INVALID_ID;
	info->flags = info->cmdflags = 0;
}

static void
dns_parse_target_v1(char **argv, int invert, unsigned int *flags,
		struct xt_set_info *info, const char *what)
{
	if (info->dim)
		xtables_error(PARAMETER_PROBLEM,
			      "--%s can be specified only once", what);

	if (!argv[optind]
	    || argv[optind][0] == '-' || argv[optind][0] == '!')
		xtables_error(PARAMETER_PROBLEM,
			      "--%s requires two args.", what);

	if (strlen(optarg) > IPSET_MAXNAMELEN - 1)
		xtables_error(PARAMETER_PROBLEM,
			      "setname `%s' too long, max %d characters.",
			      optarg, IPSET_MAXNAMELEN - 1);

	get_set_byname(optarg, (struct xt_set_info *)info);
	parse_dirs(argv[optind], info);
	optind++;
}

#define IPSET_DNS_SET_LOG (1<<0)

static int
dns_set_target_parse_v1(int c, char **argv, int invert, unsigned int *flags,
		    const void *entry, struct xt_entry_target **target)
{
	struct xt_dns_set_info_target_v1 *myinfo =
		(struct xt_dns_set_info_target_v1 *) (*target)->data;

	switch (c) {
	case '1':		/* --add-set <set> */
		dns_parse_target_v1(argv, invert, flags,
				&myinfo->add_set, "add-set");
		*flags = 1;
		break;
	case '2':
		*flags = 1;
		myinfo->flags |= IPSET_DNS_SET_LOG;
		break;
	case '3':
		/*not support now */
		break;
	case '4':
		myinfo->cmdflags |= IPSET_FLAG_EXIST;
		break;
	default:
		break;
	}
	return 1;
}

static void
print_target(const char *prefix, const struct xt_set_info *info)
{
	int i;
	char setname[IPSET_MAXNAMELEN];

	if (info->index == IPSET_INVALID_ID)
		return;
	get_set_byid(setname, info->index);
	printf(" %s %s", prefix, setname);
	for (i = 1; i <= info->dim; i++) {
		printf("%s%s",
		       i == 1 ? " " : ",",
		       info->flags & (1 << i) ? "src" : "dst");
	}
}

static void
dns_set_target_print_v1(const void *ip, const struct xt_entry_target *target,
                    int numeric)
{
	const struct xt_dns_set_info_target_v1 *info = (const void *)target->data;
	print_target("add-set", &info->add_set);
	if (info->cmdflags & IPSET_FLAG_EXIST)
		printf(" exist");
	if (info->flags & IPSET_DNS_SET_LOG)
		printf(" --log");
}

static void
dns_set_target_save_v1(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_dns_set_info_target_v1 *info = (const void *)target->data;
	print_target("add-set", &info->add_set);
	if (info->cmdflags & IPSET_FLAG_EXIST)
		printf(" exist");
	if (info->flags & IPSET_DNS_SET_LOG)
		printf(" --log");
}

static struct xtables_target dns_set_tg_reg[] = {
	{
		.name		= "DNS_SET",
		.revision	= 1,
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_IPV4,
		.size		= XT_ALIGN(sizeof(struct xt_dns_set_info_target_v1)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_dns_set_info_target_v1)),
		.help		= dns_set_target_help_v1,
		.init		= dns_set_target_init_v1,
		.parse		= dns_set_target_parse_v1,
		.final_check	= dns_set_target_check_v1,
		.print		= dns_set_target_print_v1,
		.save		= dns_set_target_save_v1,
		.extra_opts	= dns_set_target_opts_v1,
	}
};

void _init(void)
{
	xtables_register_targets(dns_set_tg_reg, ARRAY_SIZE(dns_set_tg_reg));
}
