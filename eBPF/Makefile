#
# Build eBPF program to do Load PDU Receive Coalescing (LPRC) for OB-UDPST
#

# Variables
CC = clang
CFLAGS = -O2 -g -Wall -Wextra -Wno-missing-declarations
TARGET_ARCH = -target bpf -mcpu=v3

# Targets and Prerequisites
all: vmlinux.h udpst_lprc.o

# Automatically generate vmlinux.h (via bpftool) if it doesn't exist
vmlinux.h:
	@rm -f $@ $@.tmp
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c >$@.tmp && \
	mv $@.tmp $@ || { \
		echo "Error: Failed to generate $@ via bpftool. Check if CONFIG_DEBUG_INFO_BTF is enabled in kernel config."; \
		rm -f $@.tmp $@; \
		exit 1; \
	}

# Compile
udpst_lprc.o: udpst_lprc.c vmlinux.h
	$(CC) $(CFLAGS) $(TARGET_ARCH) -c $< -o $@

# Cleanup
clean:
	rm -f *.o
cleanall: clean
	rm -f vmlinux.h
