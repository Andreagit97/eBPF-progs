// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "net_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define TRAFFIC_MARK 1234
#define PORT_FILTER 5432

SEC("socket/print_marked_traffic")
int socket__protocol_dispatcher(struct __sk_buff *skb) {
	// If we want to mark the traffic
	// if(skb->mark != TRAFFIC_MARK) {
	// 	return 0;
	// }

	skb_info_t skb_info = {0};
	conn_tuple_t skb_tup = {0};

	// Exporting the conn tuple from the skb, alongside couple of relevant fields from the skb.
	if(!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
		return 0;
	}

	// Filter on the port
	if(skb_tup.sport != PORT_FILTER && skb_tup.dport != PORT_FILTER) {
		return 0;
	}

	char dir = 'U';  // Unknown
	switch(skb->pkt_type) {
	case PACKET_HOST:
		dir = 'I';  // Incoming
		break;
	case PACKET_OUTGOING:
		dir = 'O';  // Outgoing
		break;
	case PACKET_OTHERHOST:
		dir = 'E';  // External
		break;
	}

	bpf_printk("[%c] ifx: %u, sip: %pI4, sport: %u, dip: %pI4, dport: %d, s: %u, a: %u, f: %s",
	           dir,
	           skb->ifindex,
	           &skb_tup.saddr_l,
	           skb_tup.sport,
	           &skb_tup.daddr_l,
	           skb_tup.dport,
	           skb_info.tcp_seq,
	           skb_info.tcp_ack,
	           tcp_flags_to_str_partial(skb_info.tcp_flags));

	return 0;
}
