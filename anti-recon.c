/*
 * References:
 *  https://stackoverflow.com/questions/54073052/capture-all-packages-in-kernel-module-with-netfilter-hooks-after-v4-13-x
 *  https://elixir.bootlin.com/linux/latest/source/include/linux/netfilter.h
 *  https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/tcp.h
 *  https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/ip.h
 *  https://elixir.bootlin.com/linux/latest/source/include/linux/skbuff.h
 */

#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adrian Brodzik, Piotr Frątczak");
MODULE_DESCRIPTION("Anti-reconnaissance kernel module.");

static struct nf_hook_ops nfho;

unsigned int hook_funcion(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct tcphdr *tcp = tcp_hdr(skb);
    struct iphdr *ip = ip_hdr(skb);

    if (ntohs(tcp->source) == 80)
    {
        skb_linearize(skb);

        pr_info("src: %pI4 %d dest: %pI4 %d", &ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));
        pr_info("len: %d", skb->len);
        pr_info("data len: %d", skb->data_len);
        pr_info("data:");

        int i;
        for (i = 0; i < skb->len; ++i)
        {
            if (i % 16 == 0)
            {
                pr_cont("\n");
            }

            pr_cont("%c ", skb->data[i]);
        }
    }

    return NF_ACCEPT;
}

int init_module()
{
    pr_info("init\n");
    int ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    struct net *n;
#endif
    nfho.hook = hook_funcion;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    for_each_net(n) ret += nf_register_net_hook(n, &nfho);
#else
    ret = nf_register_hook(&nfho);
#endif
    pr_info("hook returned: %d\n", ret);
    return 0;
}

void cleanup_module()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    struct net *n;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    for_each_net(n) nf_unregister_net_hook(n, &nfho);
#else
    nf_unregister_hook(&nfho);
#endif
    pr_info("exit\n");
}
