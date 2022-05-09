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
    if (skb_is_nonlinear(skb))
    {
        skb_linearize(skb);
    }

    struct iphdr *ip = ip_hdr(skb);
    struct tcphdr *tcp = tcp_hdr(skb);

    if (ntohs(tcp->source) == 22 && skb->len > 0)
    {
        char *p = (char *)((char *)tcp + (unsigned int)(tcp->doff * 4));

        char *template = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4";
        char *x;

        while ((x = strstr(p, template)) != NULL)
        {
            strncpy(x, "SSH-1.0-OpenSSH_6.3p1 Debian-3debian0.3", strlen(template));
        }
    }

    if (ntohs(tcp->source) == 80 && skb->len > 0)
    {
        pr_info("src: %pI4 %d dest: %pI4 %d", &ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));
        pr_info("len: %d", skb->len);
        pr_info("skb checksum: %d", skb->csum);
        pr_info("tcp checksum: %d", tcp->check);
        pr_info("ip checksum: %d", ip->check);
        pr_info("data:");

        char *p = (char *)((char *)tcp + (unsigned int)(tcp->doff * 4));

        char *template = "Apache/2.4.41 (Ubuntu)";
        char *x;

        while ((x = strstr(p, template)) != NULL)
        {
            strncpy(x, "nginx/1.3.15 (Debian) ", strlen(template));
        }
    }

    /*if (ip)
    {
        ip->ttl = 128;
        ip->check = 0;
        ip->check = ip_fast_csum((unsigned char *)ip, ip->ihl);
    }*/

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
