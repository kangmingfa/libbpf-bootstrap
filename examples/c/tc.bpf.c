// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u16);
	__type(value, char[8]);
} rap_sid SEC(".maps");

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *tcph;
	__u16 dest;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(void  *)(data + 14);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;
	
	tcph = (struct tcphdr*)(void*) (data + 14 + l3->ihl * 4);
	if ((void *)(tcph + 1) > data_end){
		return TC_ACT_OK;
	}
	dest = bpf_ntohs(tcph->dest);
	if (dest == 80) {
		bpf_printk("dest port is %d",dest);
		bpf_printk("Got IP packet: tot_len: %d, ttl: %d, hdr len: %d", bpf_ntohs(l3->tot_len), l3->ttl, l3->ihl * 4);
		__u16 key = 42;
		char *value = bpf_map_lookup_elem(&rap_sid,&key);
		bpf_printk("map get value is %s",value);
	}

	
	
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
