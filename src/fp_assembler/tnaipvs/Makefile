# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
BUILD_DIR = $(abspath ../../../build/)
OUTPUT := $(abspath $(BUILD_DIR)/.output)
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

TNAFPM_SRC := $(CURDIR)

LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
VMLINUX := $(abspath ../../../vmlinux/vmlinux.h)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../../../../libbpf/include/uapi -I$(dir $(VMLINUX)) -I../../../common #-I ../common/iptables/include -I/usr/include/libnl3 

TNAFPM = tnafpm.ipvs

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all
all: $(TNAFPM)

.PHONY: clean
clean:
	rm -rf $(OUTPUT)/$(TNAFPM).bpf.o

$(TNAFPM): $(OUTPUT)/$(TNAFPM).bpf.o

$(OUTPUT)/$(TNAFPM).bpf.o: $(patsubst %, %.bpf.c, $(TNAFPM_SRC)/$(TNAFPM)) | $(OUTPUT) $(LIBBPF_OBJ) $(VMLINUX)
	$(CLANG) -g -O2 -w -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(patsubst %, %.bpf.c, $(TNAFPM_SRC)/$(TNAFPM)) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info
