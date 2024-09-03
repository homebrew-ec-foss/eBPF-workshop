//syscall_counter.bpf.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} syscall_count_map SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int count_syscalls(void *ctx) {
	__u64  pid = bpf_get_current_pid_tgid() >> 32;
	__u64 *count;

  count = bpf_map_lookup_elem(&syscall_count_map, &pid);
  if (count != NULL) {
      *count += 1;
      bpf_map_update_elem(&syscall_count_map, &pid, count, BPF_ANY);
  } else {
      __u64 initial_count = 1;
      bpf_map_update_elem(&syscall_count_map, &pid, &initial_count, BPF_ANY);
  }

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
