# Activity 1: Introduction to eBPF and tracing syscalls

## 1. Hello World Program
To compile the program:
```
clang -target bpf -I/usr/include/$(uname -m)-linux-gnu -g -O2 -c syscall_counter_kern.bpf.c -o syscall_counter_kern.bpf.o
```

To load and attach the program into the kernel:
```
sudo bpftool prog load syscall_counter.bpf.o /sys/fs/bpf/prog autoattach
```

You can check the trace pip using:
```
sudo bpftool prog tracelog
```

## 2. System Call Counting:
We need to run the same commands, just run the makefile provided in this directory ```make```
