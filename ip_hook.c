#include <linux/slab.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_arp.h>
#include <linux/in_route.h>
#include <linux/inetdevice.h>
#include <linux/in.h>



MODULE_LICENSE("GPL");

#ifndef NIPQUAD_FMT
#define NIPQUAD_FMT "%u.%u.%u.%u"
#endif

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif

static unsigned int ip_hook_defrag(const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
#ifndef __GENKSYMS__
			       const struct nf_hook_state *state
#else
			       int (*okfn)(struct sk_buff *)
#endif
            );


static struct nf_hook_ops ip_hook_ops[] = {
	{
		.hook		= ip_hook_defrag,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_FIRST,
	},
};

static unsigned int ip_hook_defrag(const struct nf_hook_ops *ops,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
#ifndef __GENKSYMS__
			       const struct nf_hook_state *state
#else
			       int (*okfn)(struct sk_buff *)
#endif
			       )

{
    struct iphdr *iph;
    iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_ICMP) {
        printk("recv icmp packet indev=%s, saddr="NIPQUAD_FMT", daddr ="NIPQUAD_FMT"\n",
            in ? in->name : "",
            NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
    
    }

    return NF_ACCEPT;
}

static int __init ip_hook_init_ext(void)
{
    int ret;
	ret = nf_register_hooks(ip_hook_ops, ARRAY_SIZE(ip_hook_ops));

    return ret;
}


static void __exit ip_hook_exit_ext(void)
{
    nf_unregister_hooks(ip_hook_ops, ARRAY_SIZE(ip_hook_ops));
}


module_init(ip_hook_init_ext);
module_exit(ip_hook_exit_ext);
