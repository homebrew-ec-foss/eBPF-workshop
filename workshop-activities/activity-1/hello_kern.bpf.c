//hello_kern.bpf.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("raw_tracepoint/sys_enter")
int helloworld(void *ctx) {
	bpf_printk("Hello World!\n");
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
