# Swift-Guard Performance and Security Evaluation Methodology

## Overview
This document defines how the performance and security effectiveness of Swift-Guard are evaluated, so that results are reproducible and objective. Each scenario is marked with its current implementation status. The step-by-step procedure is in [`linux-verification.md` (Tier 3)](linux-verification.md#tier-3--성능) and the scenario plan in [`poc-plan.md`](poc-plan.md).

## Test Environment
### Hardware Configuration
Reference hardware (the environment assumed when setting targets; record the actual machine in each run's `meta_*.txt`):
- CPU: Intel Xeon E5-2680v4 (14 cores, 2.4GHz)
- Memory: 64GB DDR4 RAM
- Network: Intel X710 10Gbps NIC (XDP driver mode)
- Storage: 1TB NVMe SSD
- Traffic generator: a second Linux host running kernel pktgen, cabled directly to the DUT NIC

### Software Configuration
- OS: Ubuntu 22.04 LTS
- Kernel: Linux 5.15+ minimum (Ubuntu 22.04 GA kernel)
- Rust: 1.78+
- LLVM/Clang: 14+
- libbpf-rs 0.19.1 / libbpf-sys 1.5.0 (as pinned in `Cargo.lock`)

## Performance Evaluation
### 1. Packet Processing Performance
Metrics:
- **Throughput**: packets per second and Gbps of every frame XDP sees (`xdp_rx_pps`, `xdp_rx_gbps`), measured from the `xdp_rx_*` columns of `xdp-filter stats --format csv` (bytes = L2 frame as seen by XDP, excluding FCS/preamble/IFG — not line rate). The rule-matched rate (`pps`, `gbps`) is reported alongside
- **Latency**: average, median, P95 and P99 processing time — *no tool yet*
- **CPU Usage**: overall busy %, softirq %, and the busiest CPU's busy % during the measurement window (from `/proc/stat`)

Note: `xdp_rx_pps` counts **every packet XDP sees** (the RX slot of the per-CPU `xdp_stats_map`, incremented before parsing), so it does not depend on rule matching and is the primary throughput metric. `pps` counts **only packets that match a rule** (the global `stats_map` total). By default the benchmark scripts install a drop rule (`bench-match`) matching the generated traffic's source address so that the XDP_DROP path is measured; with `--rule-action none` no rule is installed, `pps` is 0 and `xdp_rx_pps` measures the XDP_PASS (kernel stack) path. Per-verdict counters (drop, pass, redirect, count, no_match, invalid, non_ipv4, action_error) are kept in the raw stats CSV. Result directories from older versions (without the `xdp_rx_*` columns) are still read by the analyzer, which then falls back to `pps` and says so in `summary.md`.

#### Tools
- Kernel pktgen via `tools/bench/pktgen_tx.sh` (on the sender), or any external generator
- `perf`: CPU usage and performance counters
- `bpftool`: program and map inspection (`bpftool prog show`, `bpftool map show`)

#### Test Scenarios
- **Baseline**: XDP attached with one matching drop rule, per frame size — `tools/bench/basic_throughput_test.sh` (`--rule-action none` for the no-rule XDP_PASS path)
- **XDP Filtering**: throughput vs. number of rules in the source or destination LPM map (up to 10240 per map) — `tools/bench/rule_scaling_test.sh`
- **Full Pipeline**: combined XDP filtering and WASM inspection — *not implemented (requires XDP→WASM data path)*
- **Scalability**: throughput under increasing offered load — run the baseline with increasing generator rate/threads (`--pktgen-threads`); no dedicated script

### 2. Resource Efficiency
Metrics:
- **Memory Usage**: daemon RSS (`daemon_rss_kb` in the result CSVs); BPF map memory via `bpftool map show` (memlock) — manual
- **CPU Efficiency**: cycles per processed packet — manual (`perf stat` during a run)
- **Container Overhead**: resource cost of dynamic instance management — *not implemented*

## Security Effectiveness Evaluation
*Not implemented — requires the XDP→WASM data path and an attack-traffic/verdict harness (see `poc-plan.md` section 6).* Static rule behaviour (drop/redirect/count) is covered by functional tests (`tools/test/e2e_check.sh`, `tools/test/examples.sh`), not by this methodology.

### 1. Threat Detection Accuracy (not implemented)
Metrics:
- **True Positive Rate (TPR)**: attack detection rate
- **False Positive Rate (FPR)**: normal traffic misclassification
- **F1 Score**: precision-recall balance

#### Attack Scenarios
- **DDoS**: UDP/ICMP/SYN/HTTP floods
- **Scanning**: port and vulnerability scans
- **Intrusion**: known exploit patterns and protocol violations

### 2. Mitigation Impact (not implemented)
Metrics:
- **Response Time**: detection-to-action latency
- **Traffic Blocking**: attack traffic reduction rate
- **False Positive Impact**: service disruption due to errors

### 3. Comparative Analysis (not implemented — no measurement scripts)
Compare Swift-Guard with:
- **Legacy IDS/IPS** (Suricata, Snort)
- **Cloud-Native Solutions** (Cilium, Falco)
- **Traditional Firewalls** (iptables/nftables)

## Automated Testing
All available experiments are scripts in this repository:

```bash
# Functional prerequisites (Tier 2)
sudo tools/test/e2e_check.sh --build          # kernel E2E: verifier, attach, matching, stats, XDP counters, L4 parser (IP options/fragments), cleanup
sudo tools/test/examples.sh                   # docs/examples.md regression on the virtual lab

# Benchmark flow check without a NIC (numbers are meaningless)
sudo tools/test/bench_flow_check.sh

# Performance (Tier 3, physical NIC)
sudo tools/bench/basic_throughput_test.sh --interface <nic> --mode driver --generator external
sudo tools/bench/rule_scaling_test.sh --interface <nic> --mode driver --generator external
```

### Test Results and Analysis
Results are CSV files under `--output-dir` (default `./results`): `throughput_results.csv`, `rule_scaling_results.csv`, raw per-second `xdp-filter stats --format csv` samples, and `meta_*.txt` describing the environment. Column definitions are in [`poc-plan.md`](poc-plan.md#결과-파일과-열).

```bash
pip install -r tools/analysis/requirements.txt     # matplotlib
python3 tools/analysis/analyze_performance.py --results-dir results
```
The analyzer writes `summary.md` and PNG plots to `results/plots/` (summary only if matplotlib is missing or `--no-plots` is given).
