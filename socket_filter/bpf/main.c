// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "net_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

u64 ip4_counter = 0;
u64 ip6_counter = 0;

// we want to count all ip packets
SEC("socket/ip_packet_counter")
int socket__protocol_dispatcher(struct __sk_buff *skb) {
	u32 protocol = skb->protocol;
	switch(protocol) {
	case bpf_htons(ETH_P_IP):
		__sync_fetch_and_add(&ip4_counter, 1);
		break;
	case bpf_htons(ETH_P_IPV6):
		__sync_fetch_and_add(&ip6_counter, 1);
		break;
	}
	return 0;
}
