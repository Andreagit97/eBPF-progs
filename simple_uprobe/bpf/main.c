// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// One unique shared ringbuffer, this could cause contention kernel side, in a real production case
// probably is better to use one buffer per-CPU
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

// ipv4 only at the moment
struct event {
	s32 pid;
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("uprobe/call_number")
int uprobe_call_number(struct pt_regs *ctx) {
	struct event *event = (struct event *)bpf_ringbuf_reserve(&ringbuf, sizeof(struct event), 0);
	if(!event) {
		return 0;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	event->pid = task->tgid;

	bpf_ringbuf_submit(event, 0);

	return 0;
}
