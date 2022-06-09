/*
 * References:
 *  https://stackoverflow.com/questions/54073052/capture-all-packages-in-kernel-module-with-netfilter-hooks-after-v4-13-x
 *  https://stackoverflow.com/a/49698390
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

    if (ip->protocol == IPPROTO_TCP && skb->len == 44 && tcp->ack == 1 && tcp->syn == 1)
    {
        pr_info("len: %d", skb->len);
        pr_info("ihl: %d", ip->ihl);
        pr_info("tos: %d", ip->tos);
        pr_info("tot_len: %d", ip->tot_len);
        pr_info("id: %d", ip->id);
        pr_info("frag_off: %d", ip->frag_off);
        pr_info("ttl: %d", ip->ttl);
        pr_info("protocol: %d", ip->protocol);
        pr_info("check: %d", ip->check);
    }

    /*if (ntohs(tcp->source) == 22 && skb->len > 0)
    {
        char *p = (char *)((char *)tcp + (unsigned int)(tcp->doff * 4));

        char *template = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4";
        char *x;

        while ((x = strstr(p, template)) != NULL)
        {
            strncpy(x, "SSH-2.0-OpenSSH_6.3p1 Debian-1debian0.1", strlen(template));
        }
    }*/

    if (ntohs(tcp->source) == 80 && skb->len > 0)
    {
        pr_info("src: %pI4 %d dest: %pI4 %d", &ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));

        char *p = (char *)((char *)tcp + (unsigned int)(tcp->doff * 4));

        char *template = "Apache/2.4.41 (Ubuntu)";
        char *x;

        while ((x = strstr(p, template)) != NULL)
        {
            strncpy(x, "nginx/1.3.15 (Debian) ", strlen(template));
        }
    }

    if (skb)
    {
        skb->ip_summed = CHECKSUM_NONE;
        skb->csum_valid = 0;
        skb->csum = 0;
    }

    if (ip)
    {
        ip->check = 0;
        ip->check = ip_fast_csum((unsigned char *)ip, ip->ihl);
    }

    if (tcp)
    {
        int tcplen = ntohs(ip->tot_len) - ip->ihl * 4;
        tcp->check = 0;
        tcp->check = csum_tcpudp_magic(ip->saddr, ip->daddr, tcplen, IPPROTO_TCP, csum_partial((char *)tcp, tcplen, 0));
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
