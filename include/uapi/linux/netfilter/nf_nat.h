#ifndef _NETFILTER_NF_NAT_H
#define _NETFILTER_NF_NAT_H

#include <linux/netfilter.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

//表示是否需要做IP地址转换
//可以是源地址和目的地址转换
//设置了需要做IP地址映射，把IP地址映射到指定的范围内
//需要检查IP地址是否在配置的范围内
//如果没有设置该标志，nat模块将不会修改数据包的IP地址
//同时也不会修改conntrack reply tuple 中的IP 地址
#define NF_NAT_RANGE_MAP_IPS			(1 << 0)
//用户是否通过iptables 配置时指定了端口范围
//比如MASQURADE 模块的--to-ports选项
//内核接收到参数时会用struct nf_nat_range 来构造配置的端口范围
//该标志的意思用户配置规则时指定了端口选择的范围
//因此，内核需要做两件事
//1. 需要检查数据包的原始端口是否在配置的范围内
//2. 根据用户的配置在范围内选择合适的端口
#define NF_NAT_RANGE_PROTO_SPECIFIED		(1 << 1)
//随机生成端口偏移值，影响端口选择
#define NF_NAT_RANGE_PROTO_RANDOM		(1 << 2)
//主要影响find_best_ips_proto IP地址选择时的算法
//相同的源IP地址都会映射到同一个IP地址
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
	//配置的ipv4/ipv6地址范围
	union nf_inet_addr		min_addr;
	union nf_inet_addr		max_addr;
	//对于udp和tcp来说指代配置的端口号最小值和最大值
	union nf_conntrack_man_proto	min_proto;
	union nf_conntrack_man_proto	max_proto;
};

#endif /* _NETFILTER_NF_NAT_H */
