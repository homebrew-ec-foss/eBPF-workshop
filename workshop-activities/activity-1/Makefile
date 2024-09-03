TARGET = syscall_counter_kern
LINK = prog
BPF_PATH = /sys/fs/bpf/$(LINK)
BPF_OBJ = ${TARGET:=.bpf.o}

all: $(TARGET) $(BPF_OBJ)
.PHONY: all
.PHONY: $(TARGET)

$(TARGET): $(BPF_OBJ)
        rm -f $(BPF_PATH)
        bpftool prog load $(BPF_OBJ) $(BPF_PATH) autoattach

$(BPF_OBJ): %.o: %.c
        clang \
            -target bpf \
                -I/usr/include/$(shell uname -m)-linux-gnu \
            -Wall \
            -O2 -g -o $@ -c $<

clean:
        - sudo rm -f $(BPF_PATH)
        - rm -f $(BPF_OBJ)
