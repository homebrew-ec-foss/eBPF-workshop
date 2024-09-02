TARGET = net
INTERFACE  = eth0
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}

all: $(TARGET) $(BPF_OBJ) 
.PHONY: all 
.PHONY: $(TARGET)

$(TARGET): $(BPF_OBJ)
	bpftool net detach xdp dev $(INTERFACE)
	rm -f /sys/fs/bpf/$(TARGET)
	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)
	bpftool net attach xdp pinned /sys/fs/bpf/$(TARGET) dev $(INTERFACE)

$(BPF_OBJ): %.o: %.c vmlinux.h
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2 -o $@ -c $<

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h		

clean:
	- bpftool net detach xdp dev $(INTERFACE)
	- rm -f /sys/fs/bpf/$(TARGET)
	- rm $(BPF_OBJ)
