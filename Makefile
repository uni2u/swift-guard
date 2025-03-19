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

# Build all components
build: build-bpf build-rust build-wasm

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
	cd $(WASMMODDIR) && ./build.sh

# Install everything
install: install-bpf install-bins install-wasm install-conf install-service
	@echo "Installation complete. Swift-Guard has been installed to $(PREFIX)."
	@echo "Configuration is in $(CONFDIR)."
	@echo ""
	@echo "To start the service, run:"
	@echo "  sudo systemctl enable --now swift-guard"
	@echo ""
	@echo "To use the CLI tool, run:"
	@echo "  xdp-filter help"

# Install BPF objects
install-bpf: build-bpf
	@echo "Installing BPF objects to $(LIBDIR)..."
	install -d $(LIBDIR)
	install -m 644 $(BPF_OBJECTS) $(LIBDIR)/

# Install binaries
install-bins: build-rust
	@echo "Installing binaries to $(BINDIR)..."
	install -d $(BINDIR)
	install -m 755 $(BINS) $(BINDIR)/

# Install WASM modules
install-wasm: build-wasm
	@echo "Installing WASM modules to $(WASMDIR)..."
	install -d $(WASMDIR)
	if [ -n "$(WASM_MODULES)" ]; then \
		install -m 644 $(WASM_MODULES) $(WASMDIR)/; \
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
	install -m 644 $(SYSTEMD_SERVICE) $(SYSTEMDDIR)/swift-guard.service
	systemctl daemon-reload

# Uninstall everything
uninstall:
	@echo "Uninstalling Swift-Guard..."
	systemctl stop swift-guard || true
	systemctl disable swift-guard || true
	rm -f $(SYSTEMDDIR)/swift-guard.service
	systemctl daemon-reload
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
