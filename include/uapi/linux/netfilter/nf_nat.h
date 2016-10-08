#ifndef _NETFILTER_NF_NAT_H
#define _NETFILTER_NF_NAT_H

#include <linux/netfilter.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

//表示是否需要做IP地址转换
//可以是源地址和目的地址转换
//设置了需要做IP地址映射，把IP地址映射到指定的范围内
//需要检查IP地址是否在配置的范围内
//如果没有设置该标志，nat模块将不会修改数据包的IP地址
#define NF_NAT_RANGE_MAP_IPS			(1 << 0)
//用户是否通过iptables 配置时指定了端口范围
//比如MASQURADE 模块的--to-ports选项
//内核接受到参数是会用struct nf_nat_range 来构造配置的端口范围来随机选择端口
#define NF_NAT_RANGE_PROTO_SPECIFIED		(1 << 1)
//随机生成端口偏移值，影响端口选择
#define NF_NAT_RANGE_PROTO_RANDOM		(1 << 2)
//主要影响find_best_ips_proto IP地址选择时的算法，影响端口选择
//具体现在还没弄清楚
#define NF_NAT_RANGE_PERSISTENT			(1 << 3)
//调用prandom_u32函数随机一个off值，影响端口选择
#define NF_NAT_RANGE_PROTO_RANDOM_FULLY		(1 << 4)
//需要调用l4proto->unique_tuple来随机生成端口
#define NF_NAT_RANGE_PROTO_RANDOM_ALL		\
	(NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY)

#define NF_NAT_RANGE_MASK					\
	(NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED |	\
	 NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PERSISTENT |	\
	 NF_NAT_RANGE_PROTO_RANDOM_FULLY)

struct nf_nat_ipv4_range {
	unsigned int			flags;
	__be32				min_ip;
	__be32				max_ip;
	union nf_conntrack_man_proto	min;
	union nf_conntrack_man_proto	max;
};

struct nf_nat_ipv4_multi_range_compat {
	unsigned int			rangesize;
	struct nf_nat_ipv4_range	range[1];
};

struct nf_nat_range {
	unsigned int			flags;
	union nf_inet_addr		min_addr;
	union nf_inet_addr		max_addr;
	union nf_conntrack_man_proto	min_proto;
	union nf_conntrack_man_proto	max_proto;
};

#endif /* _NETFILTER_NF_NAT_H */
