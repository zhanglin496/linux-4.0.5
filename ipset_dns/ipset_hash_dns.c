/* Copyright 2007-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <libipset/data.h>			/* IPSET_OPT_* */
#include <libipset/parse.h>			/* parser functions */
#include <libipset/print.h>			/* printing functions */
#include <libipset/types.h>			/* prototypes */
#include <libipset/session.h>			/* prototypes */
#include <stdio.h>
#include <assert.h>
#include <libipset/debug.h>

static int
ipset_parse_dns(struct ipset_session *session,
		  enum ipset_opt opt, const char *str)
{
	assert(session);
	assert(opt == IPSET_OPT_DNS);
	assert(str);
	return ipset_session_data_set(session, opt, str);
}

static int ipset_print_dns(char *buf, unsigned int len,
			  const struct ipset_data *data,
			  enum ipset_opt opt, uint8_t env)
{
	int size;
	size = snprintf(buf, len, "%s", (char *)ipset_data_get(data, IPSET_OPT_DNS));
	return size + 1;
}

/* Initial revision */
static struct ipset_type ipset_hash_dns0 = {
	.name = "hash:dns",
	.alias = { "dnshash", NULL },
	.revision = 0,
	.family = NFPROTO_IPSET_IPV46,
	.dimension = IPSET_DIM_ONE,
	.elem = {
		[IPSET_DIM_ONE - 1] = {
			.parse = ipset_parse_dns,
			.print = ipset_print_dns,
			.opt = IPSET_OPT_DNS
		},
	},
	.cmd = {
		[IPSET_CREATE] = {
			.args = {
				IPSET_ARG_FAMILY,
				/* Aliases */
				IPSET_ARG_INET,
				IPSET_ARG_INET6,
				IPSET_ARG_HASHSIZE,
				IPSET_ARG_MAXELEM,
				IPSET_ARG_TIMEOUT,
				IPSET_ARG_COUNTERS,
				/* Ignored options: backward compatibilty */
				IPSET_ARG_PROBES,
				IPSET_ARG_RESIZE,
				IPSET_ARG_NONE,
			},
			.need = 0,
			.full = 0,
			.help = "",
		},
		[IPSET_ADD] = {
			.args = {
				IPSET_ARG_TIMEOUT,
				IPSET_ARG_NOMATCH,
				IPSET_ARG_PACKETS,
				IPSET_ARG_BYTES,
				IPSET_ARG_NONE,
			},
			.need = IPSET_FLAG(IPSET_OPT_DNS),
			.full = IPSET_FLAG(IPSET_OPT_DNS),
			.help = "x.x.x.x...",
		},
		[IPSET_DEL] = {
			.args = {
				IPSET_ARG_NONE,
			},
			.need = IPSET_FLAG(IPSET_OPT_DNS),
			.full = IPSET_FLAG(IPSET_OPT_DNS),
			.help = "x.x.x.x...",
		},
		[IPSET_TEST] = {
			.args = {
				IPSET_ARG_NOMATCH,
				IPSET_ARG_NONE,
			},
			.need = IPSET_FLAG(IPSET_OPT_DNS),
			.full = IPSET_FLAG(IPSET_OPT_DNS),
			.help = "x.x.x.x...",
		},
	},
	.usage = "where depending on the INET family\n"
		 "      IP is an IPv4 or IPv6 address (or hostname),\n"
		 "      CIDR is a valid IPv4 or IPv6 CIDR prefix.",
	.description = "Initial revision",
};		

void _init(void);
void _init(void)
{
	ipset_type_add(&ipset_hash_dns0);
}
