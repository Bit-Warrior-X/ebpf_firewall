#!/bin/bash

#xdp-loader unload -a ens38
#mkdir build
#clang -O2 -g -target bpf -c kernel/ebpf_firewall_kernel.c -o build/ebpf_firewall_kernel.o
#gcc -o build/ebpf_firewall_userspace userspace/src/ebpf_firewall_unix.c userspace/src/ebpf_firewall_log.c userspace/src/ebpf_firewall_core.c userspace/src/ebpf_firewall_config.c 
#-I userpsace/include -lbpf -lxdp -lnetfilter_conntrack -lpthread


CLANG        ?= clang
GCC          ?= gcc
BPF_ARCH     ?= bpf            # clang -target bpf
CLANG_FLAGS  := -O2 -g -target $(BPF_ARCH) -Wall -Wextra

# Paths
BUILD_DIR    := build
KERNEL_SRC   := kernel/ebpf_firewall_kernel.c
KERNEL_OBJ   := $(BUILD_DIR)/ebpf_firewall_kernel.o

USR_SRCS     := userspace/src/ebpf_firewall_unix.c \
                userspace/src/ebpf_firewall_log.c  \
                userspace/src/ebpf_firewall_core.c \
                userspace/src/ebpf_firewall_config.c

USR_CLI      := userspace/src/ebpf_firewall_cli.c

USR_BIN      := $(BUILD_DIR)/ebpf_firewall_userspace
USR_CLIBIN   := $(BUILD_DIR)/ebpf_firewall_cli
USR_INC_DIR  := userspace/include

# Libraries
USR_LIBS     := -lbpf -lxdp -lnetfilter_conntrack -lpthread


# ──────────────── Targets ────────────────
.PHONY: all unload run clean

all: $(BUILD_DIR) unload $(KERNEL_OBJ) $(USR_BIN) $(USR_CLIBIN)

# 1. Build directory
$(BUILD_DIR):
	@mkdir -p $@
	cp firewall.config build/

# 2. Compile eBPF object
$(KERNEL_OBJ): $(KERNEL_SRC) | $(BUILD_DIR)
	@echo ">> Compiling eBPF kernel object"
	$(CLANG)  -I. $(CLANG_FLAGS) -c $< -o $@

# 3. Compile userspace binary
$(USR_BIN): $(USR_SRCS) | $(BUILD_DIR)
	@echo ">> Linking userspace firewall"
	$(GCC) -o $@ $^ -I$(USR_INC_DIR) $(USR_LIBS) -I.

$(USR_CLIBIN): $(USR_CLI) | $(BUILD_DIR)
	@echo ">> Linking userspace cli firewall"
	$(GCC) -o $@ $^

run: all
	@cd $(BUILD_DIR) && ./ebpf_firewall_userspace

clean:
	@rm -rf $(BUILD_DIR)