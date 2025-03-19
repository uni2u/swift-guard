# swift-guard
Secure WebAssembly Inspection Framework for Traffic using Guard

# Swift-Guard: High-Performance Adaptive Packet Processing Framework

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Rust](https://img.shields.io/badge/rust-1.65%2B-orange.svg)](https://www.rust-lang.org/)
[![XDP](https://img.shields.io/badge/XDP-enabled-green.svg)](https://www.iovisor.org/technology/xdp)

## 📝 Overview

Swift-Guard provides a high-performance packet filtering and redirection framework leveraging the Linux kernel's eXpress Data Path (XDP) technology. This framework enables wire-speed packet processing with sophisticated traffic classification and dynamic redirection capabilities critical for adaptive security architectures.

By operating at the network driver level, Swift-Guard achieves microsecond-level processing latency while maintaining the flexibility to implement complex filtering logic and redirection policies.

## 🔑 Key Features

- **Ultra-low Latency Processing**: Kernel-bypass architecture for near-zero overhead packet classification
- **Fine-grained Traffic Control**: Advanced 5-tuple+ filtering with extended metadata support
- **Dynamic Redirection**: Programmable traffic steering to inspection modules or alternative network paths
- **Real-time Policy Management**: Intuitive CLI for runtime policy configuration
- **Self-adaptive Security Integration**: Foundation for trigger-based security module instantiation
- **Comprehensive Telemetry**: Detailed performance and traffic statistics
- **WebAssembly Integration**: Support for WASM-based packet inspection and security modules

## 🛠️ Technical Architecture

### Core Components

Swift-Guard implements a two-tier architecture:

```
[Kernel Space]
    └── [XDP Program]
          ├── [Packet Classification Engine] - Optimized 5-tuple+ classification
          ├── [BPF Map Cluster] - Policy and state storage
          └── [Redirection Mechanism] - Packet path reconfiguration

[User Space]
    ├── [Rust Control Daemon]
    │     ├── [libbpf-rs Bindings] - Kernel interface
    │     ├── [Map Management Logic] - Policy CRUD operations
    │     └── [Telemetry Collector] - Performance and operational metrics
    │
    ├── [WASM Runtime]
    │     ├── [Module Manager] - Module lifecycle control 
    │     ├── [Packet Inspection API] - Interface for security modules
    │     └── [Security Modules] - Pluggable traffic analysis routines
    │
    └── [CLI Interface]
          ├── [Command Parser] - Structured argument processing
          └── [Policy Validator] - Syntax and semantic validation
```

## 📋 Project Setup

### Project Structure

Upon cloning the repository, you'll see the following directory structure:

```
swift-guard/
├── Cargo.toml                 # Rust project settings
├── README.md                  # This file
├── Makefile                   # Project-level build script
├── src/
│   ├── bpf/                   # XDP program source (C)
│   ├── cli/                   # CLI tool source (Rust)
│   ├── daemon/                # Control daemon source (Rust)
│   └── common/                # Shared code
├── include/                   # Header files
├── wasm/                      # WebAssembly modules
├── tools/                     # Benchmarking and analysis tools
├── tests/                     # Test cases
└── config/                    # Configuration examples
```

### Environment Requirements

Before installing Swift-Guard, ensure your system meets the following requirements:

- **Operating System**: Linux (Ubuntu 20.04+ or Debian 11+ recommended)
- **Kernel Version**: 5.10 or newer (5.15+ recommended for best XDP support)
- **Network Interface**: Network cards with XDP support (Intel X520/X540/X550 or newer recommended)
- **Development Tools**: Rust 1.65+, LLVM/Clang 10+, Make, GCC

You can check your kernel version with:
```bash
uname -r
```

To verify XDP support on your network interface:
```bash
ethtool -i <interface_name> | grep "driver\|firmware-version"
```

## 🚀 Installation

### 1. Install Dependencies

```bash
# Install system dependencies
sudo apt update
sudo apt install -y \
    clang llvm \
    libelf-dev \
    build-essential \
    linux-headers-$(uname -r) \
    pkg-config \
    git \
    curl

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. Clone Repository

```bash
git clone https://github.com/uni2u/swift-guard.git
cd swift-guard
```

### 3. Build BPF Program

```bash
# Build XDP program
cd src/bpf
make
cd ../..
```

### 4. Build WASM Modules

```bash
# Build WebAssembly modules
cd wasm
./build.sh
cd ..
```

### 5. Build Rust Components

```bash
# Build CLI and daemon
cargo build --release
```

### 6. Install

```bash
# Install components to system
sudo make install
```

If this is your first time running the installation, the Makefile will:
- Copy XDP object files to `/usr/local/lib/swift-guard/`
- Copy WASM modules to `/usr/local/lib/swift-guard/wasm/`
- Install binaries to `/usr/local/bin/`
- Create the default config in `/etc/swift-guard/`

## 📋 Usage

### Starting the Daemon

Before using the CLI, you need to start the daemon:

```bash
# Start the daemon
sudo swift-guard-daemon

# Or as a service
sudo systemctl start swift-guard
```

### Basic Commands

Swift-Guard provides a comprehensive CLI for managing packet filtering and redirection rules:

```bash
# Attach XDP program to network interface
$ xdp-filter attach eth0 --mode driver

# Add filtering rule to drop traffic
$ xdp-filter add-rule --src-ip 192.168.1.100 --dst-port 80 --protocol tcp --action drop --label "block-web-access"

# Add rule to redirect suspicious traffic to inspection interface
$ xdp-filter add-rule --src-ip 10.0.0.0/8 --dst-port 22 --protocol tcp --tcp-flags SYN --action redirect --redirect-if wasm0 --label "inspect-ssh-connections"

# List active rules
$ xdp-filter list-rules --stats

# View performance statistics
$ xdp-filter stats --interval 5

# Delete rule by label
$ xdp-filter delete-rule --label "block-web-access"

# Detach XDP program
$ xdp-filter detach eth0
```

### Working with WASM Modules

Swift-Guard supports loading custom WebAssembly security modules:

```bash
# Load a WASM module
$ xdp-filter wasm load --name http-inspector --file /path/to/http_inspector.wasm

# List loaded WASM modules
$ xdp-filter wasm list

# View WASM module statistics
$ xdp-filter wasm stats --name http-inspector

# Unload a WASM module
$ xdp-filter wasm unload --name http-inspector
```

### Configuration

Swift-Guard can be configured through the configuration file at `/etc/swift-guard/config.yaml`:

```bash
# Edit configuration
$ sudo nano /etc/swift-guard/config.yaml

# Reload configuration
$ sudo systemctl reload swift-guard
```

Example configuration templates are available in the `config/examples/` directory.

## 🧪 Testing and Benchmarking

The project includes various scripts for testing and benchmarking:

```bash
# Run basic throughput test
$ cd tools/bench
$ ./basic_throughput_test.sh --interface eth0

# Test rule scaling performance
$ ./rule_scaling_test.sh --interface eth0

# Measure WASM overhead
$ ./wasm_overhead_test.sh --interface eth0
```

For detailed analysis, use the included Python script:

```bash
$ cd tools/analysis
$ ./analyze_performance.py
```

## 🛠️ Troubleshooting

### Common Issues

1. **XDP Loading Fails**:
   - Check kernel version: `uname -r`
   - Verify XDP support: `ip link show dev eth0`
   - Try with generic mode: `xdp-filter attach eth0 --mode generic`

2. **Performance Issues**:
   - Check NIC offload features: `ethtool -k eth0`
   - Disable certain offloads: `ethtool -K eth0 gso off tso off gro off`
   - Monitor resource usage: `xdp-filter stats --interval 1`

3. **WASM Module Errors**:
   - Check module format: WASM modules must be compiled with compatible flags
   - Review logs: `journalctl -u swift-guard -f`

### Logging

To increase log verbosity for debugging:

```bash
$ sudo RUST_LOG=debug swift-guard-daemon
```

## 📊 Research and Performance Benchmarks

Swift-Guard delivers exceptional performance with minimal overhead:

| Metric | Value | Notes |
|--------|-------|-------|
| Packet Processing Latency | 2-5 μs | For 5-tuple classification |
| Maximum Throughput | ~10-15 Mpps | Single core, 1518-byte packets |
| Rule Addition Latency | < 50 μs | Time to apply new rule |
| Memory Footprint | ~2-5 MB | Base program with 10k rules |

*Note: Performance metrics were measured on an Intel Xeon E5-2680v4 @ 2.4GHz with Linux 5.15.0*

## 🔍 WASM Integration for Security Inspection

Swift-Guard integrates a WebAssembly (WASM) runtime to enable pluggable, language-agnostic security modules. To create your own security module:

1. Write your module in Rust, C/C++, or AssemblyScript
2. Implement the required API functions:
   - `allocate(size: i32) -> i32`
   - `inspect_packet(ptr: i32, len: i32) -> i32`
3. Compile to WebAssembly target
4. Load using the CLI commands

For examples, see the `wasm/modules/` directory.

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the GNU General Public License v2 - see the [LICENSE](LICENSE) file for details.

## 📚 References

- [XDP Documentation](https://github.com/xdp-project/xdp-tutorial)
- [libbpf-rs Documentation](https://github.com/libbpf/libbpf-rs)
- [eBPF & XDP Reference Guide](https://cilium.readthedocs.io/en/latest/bpf/)
- [WebAssembly for Proxies](https://github.com/proxy-wasm/spec)
