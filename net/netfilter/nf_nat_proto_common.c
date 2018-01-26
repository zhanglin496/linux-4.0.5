/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/random.h>
#include <linux/netfilter.h>
#include <linux/export.h>

#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_l3proto.h>
#include <net/netfilter/nf_nat_l4proto.h>

bool nf_nat_l4proto_in_range(const struct nf_conntrack_tuple *tuple,
			     enum nf_nat_manip_type maniptype,
			     const union nf_conntrack_man_proto *min,
			     const union nf_conntrack_man_proto *max)
{
	__be16 port;

	if (maniptype == NF_NAT_MANIP_SRC)
		port = tuple->src.u.all;
	else
		port = tuple->dst.u.all;

	return ntohs(port) >= ntohs(min->all) &&
	       ntohs(port) <= ntohs(max->all);
}
EXPORT_SYMBOL_GPL(nf_nat_l4proto_in_range);

void nf_nat_l4proto_unique_tuple(const struct nf_nat_l3proto *l3proto,
				 struct nf_conntrack_tuple *tuple,
				 const struct nf_nat_range *range,
				 enum nf_nat_manip_type maniptype,
				 const struct nf_conn *ct,
				 u16 *rover)
{
	unsigned int range_size, min, i;
	__be16 *portptr;
	u_int16_t off;

	if (maniptype == NF_NAT_MANIP_SRC)
		portptr = &tuple->src.u.all;
	else
		portptr = &tuple->dst.u.all;

	/* If no range specified... */
	//如果用户没有指定端口范围
	if (!(range->flags & NF_NAT_RANGE_PROTO_SPECIFIED)) {
		/* If it's dst rewrite, can't change port */
		//如果是目的端口选择
		//这里是禁止的
		//因为随机选择目的端口后
		//对方可能根本就收不到数据包
		if (maniptype == NF_NAT_MANIP_DST)
			return;
		//这里为什么要区分512，1024
		//按照netfilter的官方文档是因为把端口分成了三类
		//
		//When this implicit source mapping occurs, ports are divided into three classes:
		
		//Ports below 512
		//Ports between 512 and 1023
		//Ports 1024 and above.
		//A port will never be implicitly mapped into a different class.
		//不同类的端口不允许映射到其他类
		//根据原始数据包的端口值来界定映射的
		//端口最小值和最大值
		if (ntohs(*portptr) < 1024) {
			/* Loose convention: >> 512 is credential passing */
			if (ntohs(*portptr) < 512) {
				min = 1;
				range_size = 511 - min + 1;				
				//映射范围[1, 511]
				//这里[512, 600)之间的端口没有使用
			} else {
				min = 600;
				range_size = 1023 - min + 1; // = 424
				//range_size 表示最大值和最小值的距离				
				//映射范围[600, 1023]
			}
		} else {
			min = 1024;
			range_size = 65535 - 1024 + 1;
			//映射范围[1024, 65535]
		}
	} else {
	//如果用户自己配置了端口范围	
	//这里可以随机选择目的端口
	//这是因为这是用户自己选择的配置
	//用户自己知道自己想干什么
	//所以即便出错，也由用户自己负责
		min = ntohs(range->min_proto.all);
		range_size = ntohs(range->max_proto.all) - min + 1;
	}
//I think use variable 'min' instead of number '1024' is better.

	if (range->flags & NF_NAT_RANGE_PROTO_RANDOM) {
		//根据ip地址和随机数
		//生成一个临时偏移
		off = l3proto->secure_port(tuple, maniptype == NF_NAT_MANIP_SRC
						  ? tuple->dst.u.all
						  : tuple->src.u.all);
	} else if (range->flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY) {
		//伪随机生成一个偏移，跟IP地址无关
		off = prandom_u32();
	} else {
		//使用上一次的off值，下一次选择端口时
		// 会继续从min + off 偏移开始选择
		off = *rover;
	}

	for (i = 0; ; ++off) {
		//保证portptr在指定的范围内[min，min + range_size - 1]
		*portptr = htons(min + off % range_size);
		//尝试range_size 指定的次数，即便端口冲突了
		//也只能尽力而为
		if (++i != range_size && nf_nat_used_tuple(tuple, ct))
			continue;
		//如果设置了随机化端口选择
		//不需要保存off 偏移值
		if (!(range->flags & NF_NAT_RANGE_PROTO_RANDOM_ALL))
			*rover = off;
		return;
	}
}
EXPORT_SYMBOL_GPL(nf_nat_l4proto_unique_tuple);

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
int nf_nat_l4proto_nlattr_to_range(struct nlattr *tb[],
				   struct nf_nat_range *range)
{
	if (tb[CTA_PROTONAT_PORT_MIN]) {
		range->min_proto.all = nla_get_be16(tb[CTA_PROTONAT_PORT_MIN]);
		range->max_proto.all = range->min_proto.all;
		range->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
	}
	if (tb[CTA_PROTONAT_PORT_MAX]) {
		range->max_proto.all = nla_get_be16(tb[CTA_PROTONAT_PORT_MAX]);
		range->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(nf_nat_l4proto_nlattr_to_range);
#endif
