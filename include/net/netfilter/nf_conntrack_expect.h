/*
 * connection tracking expectations.
 */

#ifndef _NF_CONNTRACK_EXPECT_H
#define _NF_CONNTRACK_EXPECT_H
#include <net/netfilter/nf_conntrack.h>

extern unsigned int nf_ct_expect_hsize;
extern unsigned int nf_ct_expect_max;
//ip_conntrack有一个特性，那就是可以跟踪expect连接，所谓的expect连接，
//理解起来很简单，那就是“在一个连接中生成的另一个连接”，
//那么如何来识别一个连接要生成另一个连接呢？以FTP为例，
//FTP服务器会将文件传输所用的地址和端口信息作为数据载荷传输到对端的，
//Linux网关捕获这个数据包，将其解开然后根据FTP的协议规范获取地址和端口信息，
//随后就生成了一个expect连接。也就说，expect连接的参数是从数据载荷中得到的。
//既然可以从数据载荷中得到一个“期望的连接”，
//那么随后的该期望的连接真正到来的时候一般是被允许通过的，
//这在防火墙上就是所谓的动态规则，在这里，
//一个约定就是防火墙本身对应用层协议是完全信任的，
//比方说FTP载荷中附带了生成expect连接的地址和端口信息，防火墙认为此信息是可信的，
//真的就是服务器或者客户端自己设置上去的。然而现实并不完美，
//这些信息可能是被攻击者硬添加进去的，如此一来，就有了绕过防火墙的可能，
//实现方式多种多样，最常见的就是包重放，攻击者截获一个包，
//然后在其载荷中按照一定的协议规范添加地址和端口信息，
//然后将此包重放在网络，当其经过防火墙的时候，
//防火墙就会生成一条动态的针对expect连接的允许规则，
//这样攻击者便可以绕过防火墙去访问本不该被访问的地址和端口了。

struct nf_conntrack_expect {
	/* Conntrack expectation list member */
	struct hlist_node lnode;

	/* Hash member */
	struct hlist_node hnode;

	/* We expect this tuple, with the following mask */
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_mask mask;

	/* Function to call after setup and insertion */
	void (*expectfn)(struct nf_conn *new,
			 struct nf_conntrack_expect *this);

	/* Helper to assign to new connection */
	struct nf_conntrack_helper *helper;

	/* The conntrack of the master connection */
	struct nf_conn *master;

	/* Timer function; deletes the expectation. */
	struct timer_list timeout;

	/* Usage count. */
	atomic_t use;

	/* Flags */
	unsigned int flags;

	/* Expectation class */
	unsigned int class;

#ifdef CONFIG_NF_NAT_NEEDED
	union nf_inet_addr saved_addr;
	/* This is the original per-proto part, used to map the
	 * expected connection the way the recipient expects. */
	union nf_conntrack_man_proto saved_proto;
	/* Direction relative to the master connection. */
	enum ip_conntrack_dir dir;
#endif

	struct rcu_head rcu;
};

static inline struct net *nf_ct_exp_net(struct nf_conntrack_expect *exp)
{
	return nf_ct_net(exp->master);
}

#define NF_CT_EXP_POLICY_NAME_LEN	16

struct nf_conntrack_expect_policy {
	unsigned int	max_expected;
	unsigned int	timeout;
	char		name[NF_CT_EXP_POLICY_NAME_LEN];
};

#define NF_CT_EXPECT_CLASS_DEFAULT	0

int nf_conntrack_expect_pernet_init(struct net *net);
void nf_conntrack_expect_pernet_fini(struct net *net);

int nf_conntrack_expect_init(void);
void nf_conntrack_expect_fini(void);

struct nf_conntrack_expect *
__nf_ct_expect_find(struct net *net, u16 zone,
		    const struct nf_conntrack_tuple *tuple);

struct nf_conntrack_expect *
nf_ct_expect_find_get(struct net *net, u16 zone,
		      const struct nf_conntrack_tuple *tuple);

struct nf_conntrack_expect *
nf_ct_find_expectation(struct net *net, u16 zone,
		       const struct nf_conntrack_tuple *tuple);

void nf_ct_unlink_expect_report(struct nf_conntrack_expect *exp,
				u32 portid, int report);
static inline void nf_ct_unlink_expect(struct nf_conntrack_expect *exp)
{
	nf_ct_unlink_expect_report(exp, 0, 0);
}

void nf_ct_remove_expectations(struct nf_conn *ct);
void nf_ct_unexpect_related(struct nf_conntrack_expect *exp);

/* Allocate space for an expectation: this is mandatory before calling
   nf_ct_expect_related.  You will have to call put afterwards. */
struct nf_conntrack_expect *nf_ct_expect_alloc(struct nf_conn *me);
void nf_ct_expect_init(struct nf_conntrack_expect *, unsigned int, u_int8_t,
		       const union nf_inet_addr *,
		       const union nf_inet_addr *,
		       u_int8_t, const __be16 *, const __be16 *);
void nf_ct_expect_put(struct nf_conntrack_expect *exp);
int nf_ct_expect_related_report(struct nf_conntrack_expect *expect, 
				u32 portid, int report);
static inline int nf_ct_expect_related(struct nf_conntrack_expect *expect)
{
	return nf_ct_expect_related_report(expect, 0, 0);
}

#endif /*_NF_CONNTRACK_EXPECT_H*/

