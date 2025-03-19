# BPF 프로그램 컴파일을 위한 Makefile

# 컴파일러 및 옵션
CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
BPF_TARGET := bpf

# 인클루드 디렉토리
INCLUDE_DIR = ../../include
KERNEL_INCLUDE = /usr/include
KERNEL_ARCH_INCLUDE = /usr/include/$(shell uname -m)-linux-gnu/
VMLINUX_INCLUDE = $(shell find /usr/lib/modules -name vmlinux.h | head -n1 | xargs dirname)

# 컴파일 플래그
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -I$(INCLUDE_DIR) -I$(KERNEL_INCLUDE) -I$(KERNEL_ARCH_INCLUDE) -I$(VMLINUX_INCLUDE)

# 소스 및 대상 파일
BPF_SOURCES := xdp_filter.c
BPF_OBJECTS := $(BPF_SOURCES:.c=.o)

# 최종 타겟
all: $(BPF_OBJECTS)

# BPF 오브젝트 파일 생성 규칙
%.o: %.c
	$(CLANG) $(BPF_CFLAGS) -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -c $< -o $@
	@echo "BPF program $@ compiled successfully"

# 설치 규칙
install: all
	@mkdir -p ../../target/bpf
	@cp $(BPF_OBJECTS) ../../target/bpf/

# 클린업 규칙
clean:
	@rm -f $(BPF_OBJECTS)
	@echo "Cleaned up BPF objects"

.PHONY: all install clean
