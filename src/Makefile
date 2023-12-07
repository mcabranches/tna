# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
CXX := g++
BUILD_DIR = $(abspath ../build/)
OUTPUT := $(abspath $(BUILD_DIR)/.output)
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
##TNAFPM_SRC := $(abspath ./fp_assembler)

LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL ?= $(abspath $(OUTPUT)/bpftool/bpftool)
VMLINUX := $(abspath ../vmlinux/vmlinux.h)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../../libbpf/include/uapi -I$(dir $(VMLINUX)) -I../common -I ../common/iptables/include -I/usr/include/libnl3 
CXXFLAGS := -g -Wall

TNAFP = tnafp
TNAFPTC = tnafp.tc
#TNAFPM = tnafpm
APP = tna

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all
all: $(APP)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) && rm $(VMLINUX)

# create .output directory
$(OUTPUT) $(OUTPUT)/libbpf $(dir $(BPFTOOL)): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) 
	mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(OUTPUT) 
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): $(LIBBPF_OBJ) | $(dir $(BPFTOOL))
	$(MAKE) OUTPUT=$(dir $(BPFTOOL)) -C $(BPFTOOL_SRC)

# Build kernel side xdp/bpf apps
$(OUTPUT)/$(TNAFP).bpf.o: $(patsubst %, %.bpf.c, $(TNAFP)) | $(OUTPUT) $(BPFTOOL) $(LIBBPF_OBJ) $(VMLINUX)
	$(CLANG) -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(patsubst %, %.bpf.c, $(TNAFP)) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

$(OUTPUT)/$(TNAFP).skel.h: $(OUTPUT)/$(TNAFP).bpf.o
	$(BPFTOOL) gen skeleton $(OUTPUT)/$(TNAFP).bpf.o > $@

$(TNAFP): $(OUTPUT)/$(TNAFP).bpf.o $(OUTPUT)/$(TNAFP).skel.h

# Build kernel side tc/bpf apps
$(OUTPUT)/$(TNAFPTC).bpf.o: $(patsubst %, %.bpf.c, $(TNAFPTC)) | $(OUTPUT) $(BPFTOOL) $(LIBBPF_OBJ) $(VMLINUX)
	$(CLANG) -g -O2 -Wall -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(patsubst %, %.bpf.c, $(TNAFPTC)) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

$(OUTPUT)/$(TNAFPTC).skel.h: $(OUTPUT)/$(TNAFPTC).bpf.o
	$(BPFTOOL) gen skeleton $(OUTPUT)/$(TNAFPTC).bpf.o > $@

$(TNAFPTC): $(OUTPUT)/$(TNAFPTC).bpf.o $(OUTPUT)/$(TNAFPTC).skel.h


$(APP): $(TNAFP) $(TNAFPTC) | $(OUTPUT) $(LIBBPF_OBJ)
	$(CXX) $(CXXFLAGS) $(APP).cc $(LIBBPF_OBJ) $(INCLUDES) -lelf -lz -lnl-route-3 -lnl-3 -lpthread -lip4tc -lip6tc -lxtables -fpermissive -w -o $(BUILD_DIR)/$@

# Generate vmlinux.h
$(VMLINUX): $(VMLINUX_DIR) $(BPFTOOL) $(APP)
	mkdir -p $(dir $(VMLINUX))
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
