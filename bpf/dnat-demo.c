// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2019-2020 Authors of Cilium */

#include <linux/bpf.h>     // struct __sk_buff
#include <linux/pkt_cls.h> // TC_ACT_OK
#include <linux/ip.h>      // struct iphdr
#include <linux/tcp.h>     // struct tcphdr
#include <stddef.h>        // offsetof()
#include "dnat-demo.h"

// the destination IP that determines if we will redirect the packet.
#define VIRTUAL_IP 0x0a00020b  // 10.0.2.11
#define NEW_IP 0x0a06b716  // 10.6.183.22
#define PORT 0x1a0a // 6666

__section("egress")
int tc_egress(struct __sk_buff *skb)
{
    __u32 virtual_ip = bpf_htonl(VIRTUAL_IP);
    __u32 new_ip = bpf_htonl(NEW_IP);
    __u16 dport = bpf_htons(PORT);

    const int l3_off = ETH_HLEN;            // IP header offset
    const int l4_off = l3_off + IP_HLEN;    // TCP header offset: l3_off + sizeof(struct iphdr)
    __be32 sum;                             // IP checksum

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip4 = (struct iphdr *)(data + l3_off);
    struct tcphdr *tcph = (struct tcphdr *)(data + l4_off);

    // validation
    if (data + sizeof(*ip4) > data_end) {
        return TC_ACT_OK;
    }
    if (data + sizeof(*ip4) + sizeof(*tcph) > data_end) { // not our packet
        return TC_ACT_OK;
    }

    // filter
    if (ip4->daddr != virtual_ip || tcph->dest != dport || ip4->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    printk("try to change egress destination IP addr");
    // DNAT: virtual_ip -> new_ip, then update L3 and L4 checksum
    sum = csum_diff((void *)&ip4->daddr, 4, (void *)&new_ip, 4, 0);
    skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), (void *)&new_ip, 4, 0);
    l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);
	l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);
    printk("change egress destination IP addr successfully");

    return TC_ACT_OK;
}

__section("ingress")
int tc_ingress(struct __sk_buff *skb)
{
    __u32 virtual_ip = bpf_htonl(VIRTUAL_IP);
    __u32 new_ip = bpf_htonl(NEW_IP);
    __u16 sport = bpf_htons(PORT);

    const int l3_off = ETH_HLEN;            // IP header offset
    const int l4_off = l3_off + IP_HLEN;    // TCP header offset: l3_off + sizeof(struct iphdr)
    __be32 sum;                             // IP checksum

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip4 = (struct iphdr *)(data + l3_off);
    struct tcphdr *tcph = (struct tcphdr *)(data + l4_off);

    // validation
    if (data + sizeof(*ip4) > data_end) {
        return TC_ACT_OK;
    }
    if (data + sizeof(*ip4) + sizeof(*tcph) > data_end) { // not our packet
        return TC_ACT_OK;
    }

    // filter
    if (ip4->saddr != new_ip || tcph->source != sport || ip4->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    printk("try to change ingress source IP addr");
    // SNAT: new_ip -> virtual_ip, then update L3 and L4 header
    sum = csum_diff((void *)&ip4->saddr, 4, (void *)&virtual_ip, 4, 0);
    skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), (void *)&virtual_ip, 4, 0);
    l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), 0, sum, 0);
	l4_csum_replace(skb, l4_off + offsetof(struct tcphdr, check), 0, sum, BPF_F_PSEUDO_HDR);
    printk("change ingress source IP addr successfully");


    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
