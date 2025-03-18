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
    └── [CLI Interface]
          ├── [Command Parser] - Structured argument processing
          └── [Policy Validator] - Syntax and semantic validation
```

### Performance Optimization Strategy

Swift-Guard employs multiple optimization techniques:

1. **Memory Access Pattern Optimization**
   - Sequential packet header parsing to maximize cache locality
   - Strategic boundary checks positioned for verifier approval
   - Zero-copy packet handling where possible

2. **Map Access Efficiency**
   - LPM (Longest Prefix Match) Trie for efficient IP prefix handling
   - Hot path map lookup minimization
   - Per-CPU statistics to prevent atomic update contention

3. **Control Path Efficiency**
   - Rust zero-cost abstractions for user-space components
   - Minimal system call overhead in critical paths
   - Efficient serialization/deserialization for BPF map interactions

## 🚀 Installation

### Prerequisites

- Linux kernel 5.10+ with XDP support
- LLVM and Clang 10+
- Rust 1.65+
- libbpf-dev

### Building from Source

```bash
# Install dependencies
$ sudo apt install -y clang llvm libelf-dev build-essential linux-headers-$(uname -r)

# Clone repository
$ git clone https://github.com/uni2u/swift-guard.git
$ cd swift-guard

# Build
$ cargo build --release
```

## 📋 Usage

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

### Command Reference

#### Attach Command

```
xdp-filter attach <interface> [FLAGS] [OPTIONS]

ARGS:
    <interface>    Network interface name

FLAGS:
    -h, --help     Prints help information
    --force        Skip check for XDP support

OPTIONS:
    --mode <mode>  Attach mode (default: driver, options: driver, offload, generic)
```

#### Add-Rule Command

```
xdp-filter add-rule --action <action> [OPTIONS]

OPTIONS:
    --src-ip <src_ip>            Source IP address (format: a.b.c.d or a.b.c.d/prefix)
    --dst-ip <dst_ip>            Destination IP address (format: a.b.c.d or a.b.c.d/prefix)
    --src-port <src_port>        Source port or port range (format: port or port1-port2)
    --dst-port <dst_port>        Destination port or port range (format: port or port1-port2)
    --protocol <protocol>        Protocol (options: tcp, udp, icmp, any)
    --tcp-flags <tcp_flags>      TCP flags to match (format: SYN,ACK,FIN,RST,PSH,URG)
    --pkt-len <pkt_len>          Packet length range to match (format: min-max)
    --action <action>            Action (options: pass, drop, redirect, count)
    --redirect-if <redirect_if>  Redirect interface (required for redirect action)
    --priority <priority>        Rule priority (higher number = higher priority, default: 0)
    --rate-limit <rate_limit>    Rate limit in packets per second (0 = unlimited)
    --expire <expire>            Rule expiration time in seconds (0 = no expiration)
    --label <label>              Rule name/label for identification
```

For complete documentation of all commands, please see the [Command Reference](docs/commands.md).

## 📊 Performance Benchmarks

Swift-Guard delivers exceptional performance with minimal overhead:

| Metric | Value | Notes |
|--------|-------|-------|
| Packet Processing Latency | 2-5 μs | For 5-tuple classification |
| Maximum Throughput | ~10-15 Mpps | Single core, 1518-byte packets |
| Rule Addition Latency | < 50 μs | Time to apply new rule |
| Memory Footprint | ~2-5 MB | Base program with 10k rules |

*Note: Performance metrics were measured on an Intel Xeon E5-2680v4 @ 2.4GHz with Linux 5.15.0*

## 🔍 Integration with Security Frameworks

Swift-Guard serves as a foundational component for advanced security architectures:

- **WASM-based Inspection Modules**: Redirect suspicious traffic to WebAssembly-powered inspection containers
- **Dynamic Defense Orchestration**: Trigger instantiation of security functions based on traffic patterns
- **Zero-Trust Network Access**: Enforce fine-grained access control at the kernel level
- **DDoS Mitigation**: Early-stage attack detection and mitigation before reaching application layers

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the GNU General Public License v2 - see the [LICENSE](LICENSE) file for details.

## 📚 References

- [XDP Documentation](https://github.com/xdp-project/xdp-tutorial)
- [libbpf-rs Documentation](https://github.com/libbpf/libbpf-rs)
- [eBPF & XDP Reference Guide](https://cilium.readthedocs.io/en/latest/bpf/)
