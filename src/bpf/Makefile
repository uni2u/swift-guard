# BPF 프로그램 컴파일을 위한 Makefile

BPF_PROG := xdp_filter
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror

all: $(BPF_PROG).o

$(BPF_PROG).o: $(BPF_PROG).c
	$(CLANG) -target bpf -D__TARGET_ARCH_x86_64 $(CFLAGS) -c $< -o $@
	@echo "Compiled $@"

clean:
	rm -f $(BPF_PROG).o
	
install: $(BPF_PROG).o
	@mkdir -p ../../target/bpf
	@cp $(BPF_PROG).o ../../target/bpf/

.PHONY: all clean install
