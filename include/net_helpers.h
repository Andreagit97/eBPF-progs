#pragma once

/*
 * Isolate byte #n and put it into byte #m, for __u##b type.
 * E.g., moving byte #6 (nnnnnnnn) into byte #1 (mmmmmmmm) for u64:
 * 1) xxxxxxxx nnnnnnnn xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx mmmmmmmm xxxxxxxx
 * 2) nnnnnnnn xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx mmmmmmmm xxxxxxxx 00000000
 * 3) 00000000 00000000 00000000 00000000 00000000 00000000 00000000 nnnnnnnn
 * 4) 00000000 00000000 00000000 00000000 00000000 00000000 nnnnnnnn 00000000
 */
#define ___bpf_mvb(x, b, n, m) ((__u##b)(x) << (b - (n + 1) * 8) >> (b - 8) << (m * 8))

#define ___bpf_swab16(x) ((__u16)(___bpf_mvb(x, 16, 0, 1) | ___bpf_mvb(x, 16, 1, 0)))

#define ___bpf_swab32(x)                                                                   \
	((__u32)(___bpf_mvb(x, 32, 0, 3) | ___bpf_mvb(x, 32, 1, 2) | ___bpf_mvb(x, 32, 2, 1) | \
	         ___bpf_mvb(x, 32, 3, 0)))

#define ___bpf_swab64(x)                                                                 \
	((u64)(___bpf_mvb(x, 64, 0, 7) | ___bpf_mvb(x, 64, 1, 6) | ___bpf_mvb(x, 64, 2, 5) | \
	       ___bpf_mvb(x, 64, 3, 4) | ___bpf_mvb(x, 64, 4, 3) | ___bpf_mvb(x, 64, 5, 2) | \
	       ___bpf_mvb(x, 64, 6, 1) | ___bpf_mvb(x, 64, 7, 0)))

/* LLVM's BPF target selects the endianness of the CPU
 * it compiles on, or the user specifies (bpfel/bpfeb),
 * respectively. The used __BYTE_ORDER__ is defined by
 * the compiler, we cannot rely on __BYTE_ORDER from
 * libc headers, since it doesn't reflect the actual
 * requested byte order.
 *
 * Note, LLVM's BPF target has different __builtin_bswapX()
 * semantics. It does map to BPF_ALU | BPF_END | BPF_TO_BE
 * in bpfel and bpfeb case, which means below, that we map
 * to cpu_to_be16(). We could use it unconditionally in BPF
 * case, but better not rely on it, so that this header here
 * can be used from application and BPF program side, which
 * use different targets.
 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_constant_ntohs(x) ___bpf_swab16(x)
#define __bpf_constant_htons(x) ___bpf_swab16(x)
#define __bpf_ntohl(x) __builtin_bswap32(x)
#define __bpf_htonl(x) __builtin_bswap32(x)
#define __bpf_constant_ntohl(x) ___bpf_swab32(x)
#define __bpf_constant_htonl(x) ___bpf_swab32(x)
#define __bpf_ntohll(x) __builtin_bswap64(x)
#define __bpf_htonll(x) __builtin_bswap64(x)
#define __bpf_constant_ntohll(x) ___bpf_swab64(x)
#define __bpf_constant_htonll(x) ___bpf_swab64(x)
#define __bpf_be64_to_cpu(x) __builtin_bswap64(x)
#define __bpf_cpu_to_be64(x) __builtin_bswap64(x)
#define __bpf_constant_be64_to_cpu(x) ___bpf_swab64(x)
#define __bpf_constant_cpu_to_be64(x) ___bpf_swab64(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_ntohs(x) (x)
#define __bpf_htons(x) (x)
#define __bpf_constant_ntohs(x) (x)
#define __bpf_constant_htons(x) (x)
#define __bpf_ntohl(x) (x)
#define __bpf_htonl(x) (x)
#define __bpf_constant_ntohl(x) (x)
#define __bpf_constant_htonl(x) (x)
#define __bpf_ntohll(x) (x)
#define __bpf_htonll(x) (x)
#define __bpf_constant_ntohll(x) (x)
#define __bpf_constant_htonll(x) (x)
#define __bpf_be64_to_cpu(x) (x)
#define __bpf_cpu_to_be64(x) (x)
#define __bpf_constant_be64_to_cpu(x) (x)
#define __bpf_constant_cpu_to_be64(x) (x)
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_htons(x) (__builtin_constant_p(x) ? __bpf_constant_htons(x) : __bpf_htons(x))
#define bpf_ntohs(x) (__builtin_constant_p(x) ? __bpf_constant_ntohs(x) : __bpf_ntohs(x))
#define bpf_htonl(x) (__builtin_constant_p(x) ? __bpf_constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x) (__builtin_constant_p(x) ? __bpf_constant_ntohl(x) : __bpf_ntohl(x))
#define bpf_htonll(x) (__builtin_constant_p(x) ? __bpf_constant_htonll(x) : __bpf_htonll(x))
#define bpf_ntohll(x) (__builtin_constant_p(x) ? __bpf_constant_ntohll(x) : __bpf_ntohll(x))
#define bpf_cpu_to_be64(x) \
	(__builtin_constant_p(x) ? __bpf_constant_cpu_to_be64(x) : __bpf_cpu_to_be64(x))
#define bpf_be64_to_cpu(x) \
	(__builtin_constant_p(x) ? __bpf_constant_be64_to_cpu(x) : __bpf_be64_to_cpu(x))

/* ========================================================================= */

#define PACKET_HOST 0      /* To us		*/
#define PACKET_OUTGOING 4  /* Outgoing of any type */
#define PACKET_OTHERHOST 3 /* To someone else 	*/

#define ETH_HLEN 14
#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/

// from uapi/linux/in.h
#define __IPPROTO_ICMP 1
#define __IPPROTO_TCP 6
#define __IPPROTO_UDP 17

// From include/net/tcp.h
// tcp_flag_byte(th) (((u_int8_t *)th)[13])
#define TCP_FLAGS_OFFSET 13

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

/* ========================================================================= */

typedef struct {
	u32 data_off;
	u32 data_end;
	u32 tcp_seq;
	u32 tcp_ack;
	u8 tcp_flags;
} skb_info_t;

typedef struct {
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	u64 saddr_h;
	u64 saddr_l;
	u64 daddr_h;
	u64 daddr_l;
	u16 sport;
	u16 dport;
	u32 netns;

	// Metadata description:
	// First bit indicates if the connection is TCP (1) or UDP (0)
	// Second bit indicates if the connection is V6 (1) or V4 (0)
	u32 metadata;  // This is that big because it seems that we atleast need a 32-bit aligned
	               // struct
} conn_tuple_t;

static __always_inline u64 __load_word(void *ptr, u32 offset) {
	// kernel 4.14
	if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_skb_load_bytes) &&
	   bpf_core_enum_value(enum bpf_func_id, BPF_FUNC_skb_load_bytes) == BPF_FUNC_skb_load_bytes) {
		u32 res = 0;
		bpf_skb_load_bytes(ptr, offset, &res, sizeof(res));
		return bpf_htonl(res);
	} else {
		return 0;
	}
}

static __always_inline u64 __load_half(void *ptr, u32 offset) {
	// kernel 4.14
	if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_skb_load_bytes) &&
	   bpf_core_enum_value(enum bpf_func_id, BPF_FUNC_skb_load_bytes) == BPF_FUNC_skb_load_bytes) {
		u16 res = 0;
		bpf_skb_load_bytes(ptr, offset, &res, sizeof(res));
		return bpf_htons(res);
	} else {
		return 0;
	}
}

static __always_inline u64 __load_byte(void *ptr, u32 offset) {
	// kernel 4.14
	if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_skb_load_bytes) &&
	   bpf_core_enum_value(enum bpf_func_id, BPF_FUNC_skb_load_bytes) == BPF_FUNC_skb_load_bytes) {
		u8 res = 0;
		bpf_skb_load_bytes(ptr, offset, &res, sizeof(res));
		return res;
	} else {
		return 0;
	}
}

static __always_inline void read_ipv4_skb(struct __sk_buff *skb, u64 off, u64 *addr) {
	*addr = __load_word(skb, off);
	*addr = bpf_ntohll(*addr) >> 32;
}

static __always_inline void read_ipv6_skb(struct __sk_buff *skb,
                                          u64 off,
                                          u64 *addr_l,
                                          u64 *addr_h) {
	*addr_h |= (u64)__load_word(skb, off) << 32;
	*addr_h |= (u64)__load_word(skb, off + 4);
	*addr_h = bpf_ntohll(*addr_h);

	*addr_l |= (u64)__load_word(skb, off + 8) << 32;
	*addr_l |= (u64)__load_word(skb, off + 12);
	*addr_l = bpf_ntohll(*addr_l);
}

static __always_inline char *tcp_flags_to_str_partial(u8 flags) {
	if(flags & TCP_SYN && flags & TCP_ACK) {
		return "S+A";
	}
	if(flags & TCP_FIN && flags & TCP_ACK) {
		return "F+A";
	}
	if(flags & TCP_FIN && flags & TCP_RST) {
		return "F+R";
	}
	if(flags & TCP_ACK && flags & TCP_RST) {
		return "A+R";
	}
	if(flags & TCP_RST) {
		return "R";
	}
	if(flags & TCP_FIN) {
		return "F";
	}
	if(flags & TCP_SYN) {
		return "S";
	}
	if(flags & TCP_ACK) {
		return "A";
	}
	return ".";
}

// return 0 or the dst IP in host order.
static __always_inline u32 read_dst_ipv4_from_skb(struct __sk_buff *skb) {
	u16 l3_proto = __load_half(skb, offsetof(struct ethhdr, h_proto));
	if(l3_proto != ETH_P_IP) {
		return 0;
	}
	u32 res = 0;
	bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &res, sizeof(res));
	return res;
}

// to rewrite using cilium reference
static __always_inline u64 read_conn_tuple_skb(struct __sk_buff *skb,
                                               skb_info_t *info,
                                               conn_tuple_t *tup) {
	info->data_off = ETH_HLEN;

	u16 l3_proto = __load_half(skb, offsetof(struct ethhdr, h_proto));
	info->data_end = ETH_HLEN;
	u8 l4_proto = 0;
	switch(l3_proto) {
	case ETH_P_IP: {
		u8 ipv4_hdr_len = (__load_byte(skb, info->data_off) & 0x0f) << 2;
		info->data_end += __load_half(skb, info->data_off + offsetof(struct iphdr, tot_len));
		if(ipv4_hdr_len < sizeof(struct iphdr)) {
			return 0;
		}
		l4_proto = __load_byte(skb, info->data_off + offsetof(struct iphdr, protocol));
		read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, saddr), &tup->saddr_l);
		read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, daddr), &tup->daddr_l);
		info->data_off += ipv4_hdr_len;
		break;
	}
	case ETH_P_IPV6:
		info->data_end += sizeof(struct ipv6hdr) +
		                  __load_half(skb, info->data_off + offsetof(struct ipv6hdr, payload_len));
		l4_proto = __load_byte(skb, info->data_off + offsetof(struct ipv6hdr, nexthdr));
		read_ipv6_skb(skb,
		              info->data_off + offsetof(struct ipv6hdr, saddr),
		              &tup->saddr_l,
		              &tup->saddr_h);
		read_ipv6_skb(skb,
		              info->data_off + offsetof(struct ipv6hdr, daddr),
		              &tup->daddr_l,
		              &tup->daddr_h);
		info->data_off += sizeof(struct ipv6hdr);
		break;
	default:
		return 0;
	}

	switch(l4_proto) {
	case __IPPROTO_UDP:
		tup->sport = __load_half(skb, info->data_off + offsetof(struct udphdr, source));
		tup->dport = __load_half(skb, info->data_off + offsetof(struct udphdr, dest));
		info->data_off += sizeof(struct udphdr);
		break;
	case __IPPROTO_TCP:
		tup->sport = __load_half(skb, info->data_off + offsetof(struct tcphdr, source));
		tup->dport = __load_half(skb, info->data_off + offsetof(struct tcphdr, dest));

		info->tcp_seq = __load_word(skb, info->data_off + offsetof(struct tcphdr, seq));
		info->tcp_ack = __load_word(skb, info->data_off + offsetof(struct tcphdr, ack_seq));
		info->tcp_flags = __load_byte(skb, info->data_off + TCP_FLAGS_OFFSET);
		// TODO: Improve readability and explain the bit twiddling below
		info->data_off +=
		        ((__load_byte(skb, info->data_off + offsetof(struct tcphdr, ack_seq) + 4) & 0xF0) >>
		         4) *
		        4;
		break;
	default:
		return 0;
	}

	if((info->data_end - info->data_off) < 0) {
		return 0;
	}

	return 1;
}
