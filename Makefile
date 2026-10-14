# Swift-Guard Makefile
# Main build and installation script for Swift-Guard

# Installation directories
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
LIBDIR = $(PREFIX)/lib/swift-guard
WASMDIR = $(LIBDIR)/wasm
CONFDIR = /etc/swift-guard
SYSTEMDDIR = /etc/systemd/system

# Project directories
BPFDIR = src/bpf
WASMMODDIR = wasm
TARGETDIR = target/release

# Files
BPF_OBJECTS = $(BPFDIR)/xdp_filter.o
WASM_MODULES = $(wildcard $(WASMMODDIR)/modules/*.wasm)
BINS = $(TARGETDIR)/xdp-filter $(TARGETDIR)/swift-guard-daemon
CONFIG_TEMPLATE = config/swift-guard.yaml
SYSTEMD_SERVICE = config/swift-guard.service

# Phony targets
.PHONY: all build build-bpf build-rust build-wasm install install-bpf install-bins install-wasm install-conf install-service uninstall clean help

# Default target
all: build

# Help target
help:
	@echo "Swift-Guard Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all         - Build everything (default)"
	@echo "  build       - Build all components"
	@echo "  build-bpf   - Build only the BPF/XDP programs"
	@echo "  build-rust  - Build only the Rust components"
	@echo "  build-wasm  - Build only the WASM modules"
	@echo "  install     - Install Swift-Guard to system"
	@echo "  uninstall   - Remove Swift-Guard from system"
	@echo "  clean       - Clean build artifacts"
	@echo ""
	@echo "Configuration options:"
	@echo "  PREFIX      - Installation prefix (default: /usr/local)"
	@echo ""
	@echo "Example usage:"
	@echo "  make build"
	@echo "  sudo make install"
	@echo "  make clean"

# Build all components (WASM은 wasm32 타깃이 있을 때만 — 없으면 건너뜀)
build: build-bpf build-rust
	@if rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then \
		$(MAKE) build-wasm; \
	else \
		echo "wasm32-unknown-unknown target not installed: skipping WASM modules (optional)."; \
	fi

# Build BPF/XDP programs
build-bpf:
	@echo "Building BPF/XDP programs..."
	$(MAKE) -C $(BPFDIR)

# Build Rust components
build-rust:
	@echo "Building Rust components..."
	cargo build --release

# Build WASM modules
build-wasm:
	@echo "Building WASM modules..."
	cd $(WASMMODDIR) && bash ./build.sh

# Install everything
install: install-bpf install-bins install-wasm install-conf install-service
	@echo "Installation complete. Swift-Guard has been installed to $(PREFIX)."
	@echo "Configuration is in $(CONFDIR)."
	@echo ""
	@echo "To start the service, run:"
	@echo "  sudo systemctl enable --now swift-guard"
	@echo ""
	@echo "To use the CLI tool, run:"
	@echo "  xdp-filter --help"

# 설치 단계는 빌드하지 않는다: `sudo make install`이 root로 cargo/rustup을 실행하면
# (rustup은 사용자 계정에 설치되므로) 실패한다. 먼저 일반 사용자로 `make build`.
define require_built
	@for f in $(1); do \
		if [ ! -e "$$f" ]; then \
			echo "ERROR: $$f 가 없습니다. 먼저 일반 사용자로 'make build' 를 실행하세요."; exit 1; \
		fi; \
	done
endef

# Install BPF objects
install-bpf:
	$(call require_built,$(BPF_OBJECTS))
	@echo "Installing BPF objects to $(LIBDIR)..."
	install -d $(LIBDIR)
	install -m 644 $(BPF_OBJECTS) $(LIBDIR)/

# Install binaries
install-bins:
	$(call require_built,$(BINS))
	@echo "Installing binaries to $(BINDIR)..."
	install -d $(BINDIR)
	install -m 755 $(BINS) $(BINDIR)/

# Install WASM modules (선택: 빌드된 .wasm 이 있을 때만)
install-wasm:
	install -d $(WASMDIR)
	@if [ -n "$(WASM_MODULES)" ]; then \
		echo "Installing WASM modules to $(WASMDIR)..."; \
		install -m 644 $(WASM_MODULES) $(WASMDIR)/; \
	else \
		echo "No built WASM modules (optional: 'make build-wasm'), skipping."; \
	fi

# Install configuration
install-conf:
	@echo "Installing configuration to $(CONFDIR)..."
	install -d $(CONFDIR)
	if [ ! -f $(CONFDIR)/config.yaml ]; then \
		install -m 644 $(CONFIG_TEMPLATE) $(CONFDIR)/config.yaml; \
	else \
		echo "Configuration already exists, not overwriting."; \
		echo "See $(CONFIG_TEMPLATE) for the latest template."; \
	fi

# Install systemd service
install-service:
	@echo "Installing systemd service..."
	@if [ -d /run/systemd/system ]; then \
		install -d $(SYSTEMDDIR); \
		install -m 644 $(SYSTEMD_SERVICE) $(SYSTEMDDIR)/swift-guard.service; \
		systemctl daemon-reload; \
	else \
		echo "systemd not running (container/WSL?): skipping service install."; \
	fi

# Uninstall everything
uninstall:
	@echo "Uninstalling Swift-Guard..."
	-systemctl stop swift-guard 2>/dev/null
	-systemctl disable swift-guard 2>/dev/null
	rm -f $(SYSTEMDDIR)/swift-guard.service
	-systemctl daemon-reload 2>/dev/null
	rm -f $(BINDIR)/xdp-filter
	rm -f $(BINDIR)/swift-guard-daemon
	rm -rf $(LIBDIR)
	@echo "Swift-Guard has been uninstalled."
	@echo "Note: Configuration in $(CONFDIR) was not removed."
	@echo "To completely remove Swift-Guard, also run:"
	@echo "  sudo rm -rf $(CONFDIR)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(BPFDIR) clean
	cargo clean
	@echo "Cleaned."
