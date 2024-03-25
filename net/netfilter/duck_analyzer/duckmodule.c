#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define NETLINK_USER 31

struct sock *nl_sk = NULL;
static int user_space_pid = 0;

static void nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int user_pid;

    nlh = (struct nlmsghdr*)skb->data;
    user_pid = NETLINK_CB(skb).portid; // Correctly obtain the PID from skb

    printk(KERN_INFO "Netlink received PID: %d\n", user_pid);

    // Receive PID from user space and set as PID for sending messages.
    user_space_pid = user_pid;
}

static void send_nl_msg(char *msg) {
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size = strlen(msg);
    int res;

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    strncpy(nlmsg_data(nlh), msg, msg_size);

    // Send the message to user-space
    res = nlmsg_unicast(nl_sk, skb_out, user_space_pid);

    if (res < 0)
        printk(KERN_ERR "Error while sending to user\n");
}

static struct nf_hook_ops netfilter_ops;

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct ipv6hdr *ipv6h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    char msg[512]; // Adjust size as needed

    iph = ip_hdr(skb);

    if (iph->version == 4) { // IPv4
        // IPv4
        tcph = tcp_hdr(skb);
        udph = udp_hdr(skb);
        char *protocol = (iph->protocol == IPPROTO_TCP) ? "TCP" : "UDP";
        unsigned short source_port = (iph->protocol == IPPROTO_TCP) ? ntohs(tcph->source) : ntohs(udph->source);
        unsigned short dest_port = (iph->protocol == IPPROTO_TCP) ? ntohs(tcph->dest) : ntohs(udph->dest);

        snprintf(msg, sizeof(msg), "{\"SRC\": \"%pI4\", \"DST\": \"%pI4\", \"Protocol\": \"%s\", \"SRC_PORT\": \"%u\", \"DST_PORT\":\"%u\"}",
             &iph->saddr, &iph->daddr, protocol, source_port, dest_port);
    } else if (iph->version == 6) {
        // IPv6
        ipv6h = ipv6_hdr(skb);
        char *protocol = (ipv6h->nexthdr == IPPROTO_TCP) ? "TCP" : "UDP";
        unsigned short source_port = (ipv6h->nexthdr == IPPROTO_TCP) ? ntohs(tcph->source) : ntohs(udph->source);
        unsigned short dest_port = (ipv6h->nexthdr == IPPROTO_TCP) ? ntohs(tcph->dest) : ntohs(udph->dest);

        snprintf(msg, sizeof(msg), "{\"SRC\": \"%pI6\", \"DST\": \"%pI6\", \"Protocol\": \"%s\", \"SRC_PORT\": \"%u\", \"DST_PORT\":\"%u\"}",
             &ipv6h->saddr, &ipv6h->daddr, protocol, source_port, dest_port);
    }

    send_nl_msg(msg);
    return NF_ACCEPT;
}

static int __init netlink_init(void) {
    struct netlink_kernel_cfg cfg = {
            .input = nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Failed to create netlink socket.\n");
        return -10;
    }

    netfilter_ops.hook = hook_func;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.hooknum = NF_INET_FORWARD;
    netfilter_ops.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_ops);

    return 0;
}

static void __exit netlink_exit(void) {
    netlink_kernel_release(nl_sk);
    nf_unregister_net_hook(&init_net, &netfilter_ops);
}

module_init(netlink_init);
module_exit(netlink_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chris Trower");
MODULE_DESCRIPTION("Netfilter hook and Netlink communication module");
MODULE_VERSION("0.01");