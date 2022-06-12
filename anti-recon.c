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

#define TCP_NOP 1

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adrian Brodzik, Piotr Frątczak");
MODULE_DESCRIPTION("Anti-reconnaissance kernel module.");

static struct nf_hook_ops nfho;

void set_tcp_opt(void *dest, uint64_t value, uintptr_t size)
{
    uintptr_t i;

    for (i = 0; i < (size & (~7)); i += size)
    {
        memcpy(((char *)dest) + i, &value, size);
    }

    for (; i < size; ++i)
    {
        ((char *)dest)[size - 1 - i] = ((char *)&value)[i & 7];
    }
}

unsigned int hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (skb_is_nonlinear(skb))
    {
        skb_linearize(skb);
    }

    struct iphdr *ip = ip_hdr(skb);
    struct tcphdr *tcp = tcp_hdr(skb);

    bool changed_values = false;

    /* Intercept FTP */
    if (ntohs(tcp->source) == 21 && skb->len > 0)
    {
        pr_info("INTERCEPTING src: %pI4 %d dest: %pI4 %d", &ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));

        char *p = (char *)((char *)tcp + (unsigned int)(tcp->doff * 4));

        char *template = "vsFTPd 3.0.3";
        char *x;

        while ((x = strstr(p, template)) != NULL)
        {
            pr_info("changed ftp identifier");
            strncpy(x, "vsFTPd 2.3.4", strlen(template));
            changed_values = true;
        }
    }

    /* Intercept SSH */
    if (ntohs(tcp->source) == 22 && skb->len > 0)
    {
        pr_info("INTERCEPTING src: %pI4 %d dest: %pI4 %d", &ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));

        char *p = (char *)((char *)tcp + (unsigned int)(tcp->doff * 4));

        char *template = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        char *x;

        while ((x = strstr(p, template)) != NULL)
        {
            pr_info("changed ssh identifier");
            strncpy(x, "SSH-2.0-OpenSSH_6.3p1 Debian-1debian0.1", strlen(template));
            changed_values = true;
        }
    }

    /* Intercept HTTP */
    if (ntohs(tcp->source) == 80 && skb->len > 0)
    {
        pr_info("INTERCEPTING src: %pI4 %d dest: %pI4 %d", &ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));

        {
            char *p = (char *)((char *)tcp + (unsigned int)(tcp->doff * 4));
            char *template = "Apache/2.4.41 (Ubuntu)";
            char *x;

            while ((x = strstr(p, template)) != NULL)
            {
                pr_info("changed http identifier");
                strncpy(x, "nginx/1.3.15 (Debian) ", strlen(template));
                changed_values = true;
            }
        }

        {
            char *p = (char *)((char *)tcp + (unsigned int)(tcp->doff * 4));
            char *template = "Vary: Accept-Encoding\r\nContent-Type: text/html";
            char *x;

            while ((x = strstr(p, template)) != NULL)
            {
                pr_info("changed http fields");
                strncpy(x, "Content-Type: text/html\r\nVary: Accept-Encoding", strlen(template));
                changed_values = true;
            }
        }
    }

    /* Intercept scanner probe */
    if (ip->protocol == IPPROTO_TCP && skb->len > 0 && tcp->ack == 1 && tcp->syn == 1)
    {
        pr_info("INTERCEPTING src: %pI4 %d dest: %pI4 %d", &ip->saddr, ntohs(tcp->source), &ip->daddr, ntohs(tcp->dest));

        /* Modify TCP Window size and IP initial TTL */
        ip->ttl = 128;
        uint16_t new_win = 8192;
        tcp->window = htons(new_win);
        pr_info("new TTL: %d", ip->ttl);
        pr_info("new WS: %d", new_win);

        /* Modify TCP Options */
        uint8_t *p = (uint8_t *)tcp + 20;
        uint8_t *end = (uint8_t *)tcp + tcp->doff * 4;

        pr_info("TCP Options length: %ld", end - p);

        while (p < end)
        {
            uint8_t kind = *p++;

            if (kind == 0)
            {
                pr_info("end of options");
                break;
            }

            if (kind == 1)
            {
                pr_info("NOP");
                continue;
            }

            uint8_t length = *p++;

            if (kind == 2)
            {
                uint16_t mss = ntohs(*(uint16_t *)p);
                uint16_t new_mss = 645;
                set_tcp_opt(p, new_mss, length - 2);
                pr_info("MSS: %d, new MSS:%d, len: %d", mss, new_mss, length);
            }

            if (kind == 3)
            {
                uint8_t ws = *(uint8_t *)p;
                uint8_t new_ws = 4;
                set_tcp_opt(p, new_ws, length - 2);
                pr_info("WS: %d, new WS: %d, len: %d", ws, new_ws, length);
            }

            if (kind == 4)
            {
                pr_info("SACK permitted, len: %d", length);
            }

            if (kind == 5)
            {
                pr_info("SACK, len: 8^n");
            }

            if (kind == 8)
            {
                pr_info("Timestamps deleted, len: %d", length);
                memset(p - 2, TCP_NOP, length);
            }

            if (kind == 34)
            {
                pr_info("Fast Open, len: %d", length);
            }

            p += (length - 2);
        }

        changed_values = true;
    }

    if (changed_values)
    {
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
    nfho.hook = hook_function;
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
