// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

u64 counter = 0;

SEC("raw_tp/sys_enter")
int test(void *ctx) {
	__sync_fetch_and_add(&counter, 1);
	return 0;
}
