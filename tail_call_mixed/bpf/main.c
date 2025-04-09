// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tp_btf/sys_exit")
int t1_hotplug(void *ctx) {
	bpf_printk("tail call hotplug");
	return 0;
}

// This is no more possible since kernel 6.12.0
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} tail_calls SEC(".maps") = {
        .values =
                {
                        [0] = (void *)&t1_hotplug,
                },
};

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long syscall_id) {
	bpf_tail_call(ctx, &tail_calls, 0);
	return 0;
}
