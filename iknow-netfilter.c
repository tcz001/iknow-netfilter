#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho;
struct iphdr *iph;
struct tcphdr *tcp_header;
struct sk_buff *sock_buff;
unsigned int sport, dport;

unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    //NOTE: Feel free to uncomment printks! If you are using Vagrant and SSH
    //      too many printk's will flood your logs.
    printk(KERN_INFO "=== BEGIN HOOK ===\n");

    sock_buff = skb;

    if (!sock_buff) {
        return NF_ACCEPT;
    }

    iph = (struct iphdr *)skb_network_header(sock_buff);

    if (!iph) {
        printk(KERN_INFO "no ip header\n");
        return NF_ACCEPT;
    }

    if(iph->protocol==IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)skb_transport_header(sock_buff);
        printk(KERN_INFO "TCP pid: %d\n", current->pid);

        printk(KERN_INFO "IP header: original source: %d.%d.%d.%d dest: %d.%d.%d.%d\n", NIPQUAD(iph->saddr) , NIPQUAD(iph->daddr));
        /* iph->saddr = iph->saddr ^ 0x10000000; */
        printk(KERN_INFO "IP header: original source: %d.%d.%d.%d dest: %d.%d.%d.%d\n", NIPQUAD(iph->saddr) , NIPQUAD(iph->daddr));

        printk(KERN_INFO "TCP ports original: source: %d, dest: %d \n", htons((unsigned short int) tcp_header->source), htons((unsigned short int) tcp_header->dest));
        tcp_header->dest = htons((unsigned short int) 443);
        printk(KERN_INFO "TCP ports modified: source: %d, dest: %d \n", htons((unsigned short int) tcp_header->source), htons((unsigned short int) tcp_header->dest));

        // printk(KERN_INFO "SKBuffer: len %d, data_len %d\n", sock_buff->len, sock_buff->data_len);
    }

    //if(iph->protocol==IPPROTO_ICMP) {
    //    printk(KERN_INFO "=== ICMP === pid: %d\n", current->pid);
    //    printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
    //    iph->saddr = iph->saddr ^ 0x10000000;
    //    printk(KERN_INFO "IP header: modified source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
    //    printk(KERN_INFO "IP header: original destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
    //    printk(KERN_INFO "=== ICMP ===\n");
    //}

    //if(in) { printk(KERN_INFO "in->name:  %s\n", in->name); }
    //if(out) { printk(KERN_INFO "out->name: %s\n", out->name); }
    printk(KERN_INFO "=== END HOOK ===\n");
    return NF_ACCEPT;

}

static int __init initialize(void) {
    nfho.hook = hook_func;
    //nfho.hooknum = NF_INET_PRE_ROUTING;
    //Interesting note: A pre-routing hook may not work here if our Vagrant
    //                  box does not know how to route to the modified source.
    //                  For the record, mine did not.
    nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);
    return 0;
}

static void __exit teardown(void) {
    nf_unregister_hook(&nfho);
}

module_init(initialize);
module_exit(teardown);
