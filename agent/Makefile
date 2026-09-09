# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
.DELETE_ON_ERROR:

OUTPUT := .output
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
VMLINUX := $(OUTPUT)/vmlinux.h
BPF_OBJECT := $(OUTPUT)/host_events.bpf.o
SKELETON := $(OUTPUT)/host_events.skel.h
NETWORK_BPF_OBJECT := $(OUTPUT)/server.bpf.o
NETWORK_SKELETON := $(OUTPUT)/server.skel.h
AGENT := $(OUTPUT)/host-events
STATIC_AGENT := $(OUTPUT)/host-events-static

CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config

UNAME_M := $(shell uname -m)
BPF_ARCH := $(UNAME_M)
ifeq ($(UNAME_M),x86_64)
BPF_ARCH := x86
endif
ifeq ($(UNAME_M),aarch64)
BPF_ARCH := arm64
endif
ifeq ($(UNAME_M),ppc64le)
BPF_ARCH := powerpc
endif
ifeq ($(UNAME_M),s390x)
BPF_ARCH := s390
endif

MULTIARCH_INCLUDE := /usr/include/$(shell $(CC) -dumpmachine)
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)
STATIC_LIBBPF_LIBS := $(shell $(PKG_CONFIG) --static --libs libbpf 2>/dev/null)
ifeq ($(strip $(LIBBPF_LIBS)),)
LIBBPF_LIBS := -lbpf -lelf -lz
endif
ifeq ($(strip $(STATIC_LIBBPF_LIBS)),)
STATIC_LIBBPF_LIBS := -lbpf -lelf -lz
endif

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
	-Wall -Wextra -I$(OUTPUT) -Iinclude -I$(MULTIARCH_INCLUDE) \
	$(LIBBPF_CFLAGS)
USER_CFLAGS := -g -O2 -Wall -Wextra -Werror -I$(OUTPUT) -Iinclude \
	$(LIBBPF_CFLAGS)

.PHONY: all clean check network static help

all: $(AGENT) $(NETWORK_SKELETON)

$(OUTPUT):
	mkdir -p $@

$(VMLINUX): | $(OUTPUT)
	@test -r $(VMLINUX_BTF) || \
		(echo "BTF not found at $(VMLINUX_BTF)" >&2; exit 1)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(BPF_OBJECT): src/bpf/host_events.bpf.c include/agent_events.h $(VMLINUX) | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKELETON): $(BPF_OBJECT) | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

$(NETWORK_BPF_OBJECT): server.c include/agent_events.h $(VMLINUX) | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(NETWORK_SKELETON): $(NETWORK_BPF_OBJECT) | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

network: $(NETWORK_SKELETON)

$(AGENT): src/user/host_events.c include/agent_events.h $(SKELETON) $(NETWORK_SKELETON) | $(OUTPUT)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBBPF_LIBS) -pthread

$(STATIC_AGENT): src/user/host_events.c include/agent_events.h $(SKELETON) $(NETWORK_SKELETON) | $(OUTPUT)
	$(CC) $(USER_CFLAGS) -static $< -o $@ $(STATIC_LIBBPF_LIBS) -pthread

static: $(STATIC_AGENT)

check: $(AGENT)
	@echo "Build check passed: $(AGENT)"

clean:
	rm -rf $(OUTPUT)

help:
	@echo "make              Build the CO-RE sensors and test reader"
	@echo "make check        Build with warnings treated as errors"
	@echo "make network      Build only the network BPF object and skeleton"
	@echo "make static       Build a self-contained compatibility-test loader"
	@echo "make clean        Remove generated files"
	@echo "VMLINUX_BTF=PATH  Override the target kernel BTF source"
