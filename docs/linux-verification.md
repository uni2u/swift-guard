# Swift-Guard 검증 가이드

Swift-Guard 검증은 세 단계(Tier)로 나뉜다. 단계마다 필요한 환경이 다르고, 아래 단계를 통과해야 위 단계가 의미를 가진다.

| Tier | 무엇을 확인하나 | 필요한 환경 | 실행 |
|------|----------------|------------|------|
| **1. 빌드·단위 테스트** | BPF 컴파일(BTF 포함), daemon/CLI 컴파일, 맵 바이트 레이아웃, API, 단위 테스트 | Rust 툴체인이 있는 아무 환경. daemon과 BPF는 Linux(또는 Docker)가 필요 | `cargo test --workspace`, `make -C src/bpf` |
| **2. 커널 기능 (E2E)** | verifier 로드, XDP attach/detach, drop·count·redirect 매치, CIDR(LPM 바이트 오더), 목적지 룰(dst_rules)과 출발지 룰 우선, 룰별·전역 통계, 입력 거부, SIGTERM 시 정리 | **Linux 커널 5.10+와 root**. 물리 NIC는 필요 없다(veth + generic XDP) | `sudo tools/test/e2e_check.sh --build` |
| **3. 성능** | 프레임 크기별 Mpps·Gbps, CPU 사용률, 룰 수에 따른 처리량, 룰 추가 시간, driver 모드. 지연(P50/P99)은 측정 도구 없음 | 물리 서버, XDP driver 모드를 지원하는 NIC(Intel X520/X710 등), 트래픽 발생기(커널 pktgen 등) | `tools/bench/basic_throughput_test.sh`, `tools/bench/rule_scaling_test.sh`, `tools/analysis/analyze_performance.py` ([`poc-plan.md`](poc-plan.md)). 흐름만 확인: `sudo tools/test/bench_flow_check.sh` |

---

## Tier 1 — 빌드·단위 테스트

```bash
sudo apt install -y clang llvm libelf-dev libbpf-dev build-essential pkg-config linux-headers-$(uname -r)
make -C src/bpf                     # xdp_filter.o. .BTF 섹션이 있어야 libbpf가 맵을 연다
cargo build --release               # xdp-filter, swift-guard-daemon
cargo test --workspace              # 단위 테스트 (common 바이트 레이아웃, daemon 서버·WASM 등)
```

- Rust **1.78+**가 필요하다(Cargo.lock v4).
- macOS에서는 `common`과 `cli` 크레이트만 빌드된다. daemon은 libbpf-sys 때문에 Linux에서만 빌드된다.

## Tier 2 — 커널 기능 (E2E)

### 환경
다음 중 하나면 된다.
- Linux VM: Lima, UTM, Multipass, VirtualBox 등. Ubuntu 22.04+ 권장(커널 5.15+)
- 클라우드 VM
- Linux 물리 장비
- Docker `--privileged` 컨테이너. x86_64 Docker Desktop(커널 7.x linuxkit)에서 동작을 확인했다. 커널이 `bpf()`를 막는 환경에서는 e2e_check가 daemon 기동 단계에서 실패로 알린다.

### 실행
```bash
sudo apt install -y iproute2 iputils-ping bpftool    # bpftool은 선택(verifier 단독 검사)
sudo tools/test/e2e_check.sh --build                 # 빌드부터 E2E까지 한 번에
# 옵션: --with-ignored (cargo test -- --ignored 실행), --keep (실패 시 토폴로지·로그 보존)
```

### 토폴로지
스크립트가 만들고, 끝나면 지운다.
```
[netns sg-e2e-src] sg-e2e-peer 10.200.0.2  <== veth ==>  sg-e2e-dut 10.200.0.1, 10.200.0.11  [XDP generic 부착]
                                                         sg-e2e-rd0  <== veth ==>  sg-e2e-rd1  (redirect 대상)
```
daemon은 테스트 전용 포트 `127.0.0.1:17654`로 띄우고, 설정 파일 없이 기본값으로 돈다. 그래서 시스템에 설치된 daemon과 충돌하지 않는다.

### 검증 항목

| # | 항목 | 판정 기준 |
|---|------|----------|
| 1 | verifier | `bpftool prog load` 성공 (bpftool이 없으면 2번에서 대신 확인) |
| 2 | daemon 기동 | API 포트 응답 |
| 3 | attach (generic) | `ip -d link`에 xdp 표시, 룰이 없을 때 ping 통과 |
| 4 | drop /32 | ICMP 차단, 룰별 통계 ≥3, 전역 통계(PERCPU 합산) >0, 삭제 후 복구 |
| 5 | drop /24 | CIDR 매치. LPM 키를 네트워크 바이트 오더로 넣었는지 검증 |
| 6 | count | 트래픽은 통과하고 패킷은 집계됨 |
| 7 | redirect | 원래 경로로는 응답이 없고, 대상 veth의 rx가 증가 |
| 8 | dst 룰 | 목적지 10.200.0.11로 가는 ICMP를 dst drop 룰로 차단하고, 다른 목적지(10.200.0.1)는 영향 없음. 룰별 통계 ≥3, list-rules DEST에 표시. src pass가 dst보다 우선함(dst 카운터 불변). src 조건이 맞지 않으면 dst로 넘어감. dst count·redirect 동작. 같은 prefix의 src 룰과 dst 룰 동시 허용 |
| 9 | 입력 거부 | src·dst 둘 다 없음, 둘 다 지정, 없는 인터페이스, drop+redirect-if, src/dst prefix 중복, label 중복은 모두 Error(앞의 두 개와 dst 중복은 문구까지 확인). daemon은 계속 살아 있음 |
| 10 | WASM 관리 | load/list/stats/unload. `wasm/modules/http_inspector.wasm`이 빌드돼 있을 때만 실행 |
| 11 | detach | CLI로 detach하면 xdp가 해제됨 |
| 12 | SIGTERM | 5초 안에 종료되고 xdp가 해제됨 |

### 추가 수동 점검 (자동화하지 않은 항목)
```bash
X=./target/release/xdp-filter
sudo ./target/release/swift-guard-daemon -b src/bpf/xdp_filter.o -i veth0 -v & DPID=$!

# 외부 프로그램이 교체해 넣은 XDP는 detach하지 않아야 한다
sudo ip -force link set dev veth0 xdpgeneric obj src/bpf/xdp_filter.o sec xdp
$X detach veth0; ip -d link show veth0 | grep -c xdp      # Error 메시지, 1 (외부 프로그램 유지)

# 요청 프레임 상한(1 MiB): 큰 길이 헤더를 보내면 Error 후 연결이 닫히고 daemon은 살아 있어야 한다
printf '\xff\xff\xff\xff' | nc -q2 127.0.0.1 7654 | xxd | head -2; kill -0 $DPID && echo alive

# 동시 연결 상한(64): idle 연결 64개를 붙잡은 상태에서는 busy 응답, 10초 IO timeout이 지나면 정상
for i in $(seq 64); do (sleep 15 | nc 127.0.0.1 7654 >/dev/null &); done; sleep 0.5
$X list-rules            # server busy (또는 connection reset)
sleep 12; $X list-rules  # 정상

sudo kill -TERM $DPID
```

### 알려진 한계
- `cargo test -- --ignored`의 기존 통합 테스트(`tests/integration/`)는 `sudo`와 `target/debug/` 바이너리를 하드코딩하고 기본 포트 7654를 쓴다. 그래서 root 셸이나 컨테이너에서는 실패한다. 같은 범위를 `e2e_check.sh`가 더 넓게 검증한다.
- generic 모드만 검증한다. driver 모드와 offload 모드는 NIC 드라이버가 지원해야 하므로 Tier 3에서 확인한다.
- daemon이 `SIGKILL`로 죽으면 XDP가 붙은 채 남는다. `sudo ip link set dev <if> xdp off`(또는 `xdpgeneric off`)로 직접 해제한다.

### 사용 예시 회귀
[`examples.md`](examples.md)의 예시 12종을 실습 랩(`tools/test/lab.sh`)에서 그대로 실행하고 기대 결과와 비교한다.
```bash
sudo tools/test/examples.sh -v
```

## Tier 3 — 성능

시나리오와 해석은 [`poc-plan.md`](poc-plan.md), 지표 정의는 [`evaluation.md`](evaluation.md)를 따른다. 여기서는 실행 절차만 정리한다.

### 사전 조건
- **같은 장비에서 Tier 2를 먼저 통과**시킨다(`sudo tools/test/e2e_check.sh --build`). 기능 문제가 성능 수치를 오염시키지 않게 하기 위해서다.
- **매치 룰이 필요하다.** `xdp-filter stats`의 전역 총계는 룰에 매치한 패킷만 센다(룰에 매치하지 않고 통과한 패킷, 비 IPv4는 세지 않는다). 벤치 스크립트는 트래픽 출발지(`--src-ip`)에 매치하는 룰 `bench-match`(기본 `--rule-action drop`)를 자동으로 넣는다. 송신 장비의 출발지 IP를 `--src-ip`와 맞춘다.
- driver 모드를 지원하는 NIC(`ethtool -i <nic>`로 드라이버 확인). generic 모드 수치는 driver 모드와 비교할 수 없다.
- 권장: `irqbalance` 정지, 수신 큐 IRQ와 CPU 고정, CPU 주파수 고정(performance governor).
- daemon: API(`127.0.0.1:7654`)가 응답하지 않으면 스크립트가 직접 띄우고 끝나면 종료한다. 이미 실행 중이면 재사용한다(기존 룰이 결과에 영향을 줄 수 있다는 경고를 출력하고, 스크립트가 넣은 룰만 지운다). 그 daemon이 인터페이스에 이미 붙여 두었으면 `--no-attach`를 쓴다. 재사용 daemon에서는 `--force-attach`가 거부되고, `bench-match` 라벨이 이미 있으면 에러로 중단한다.
- 측정 중 daemon이 죽거나 stats 수집이 실패하면 그 행을 기록하지 않고 종료 코드 1로 끝난다.

### 트래픽 생성기 (`--generator`)
| 값 | 구성 | 비고 |
|----|------|------|
| `external` (기본) | 별도 송신 장비 → DUT NIC | 송신 장비에서 `tools/bench/pktgen_tx.sh`(커널 pktgen, 단독 실행 가능) 또는 TRex 등. 스크립트는 크기마다 안내를 출력하고 Enter를 기다린다(`--no-prompt`면 `--warmup`초 대기). `packet_size`는 라벨일 뿐이므로 송신 측 크기를 맞춘다 |
| `pktgen` | 같은 호스트의 다른 NIC(`--tx-dev`) → 케이블 직결 → DUT NIC | 커널 pktgen 모듈 필요. 송신이 같은 CPU를 쓰므로 수치가 낮게 나올 수 있다 |
| `lab` | 실습 랩 veth(`sg-lab0`) + python 송신 | **흐름 검증용 — 성능 수치 아님.** NIC 불필요 |

### 실행 예
```bash
# 송신 장비 (DUT의 IP/MAC으로, 출발지는 매치 룰과 같은 198.18.0.2)
sudo tools/bench/pktgen_tx.sh --dev <tx-nic> --dst-ip <DUT-IP> --dst-mac <DUT-MAC> --src-ip 198.18.0.2 --size 64 --duration 70

# DUT: 처리량 (프레임 크기별)
sudo tools/bench/basic_throughput_test.sh --interface <nic> --mode driver --generator external --packet-sizes 64 --duration 60

# DUT: 단일 호스트 구성 (tx NIC와 DUT NIC를 케이블로 직결)
sudo tools/bench/basic_throughput_test.sh --interface <nic> --generator pktgen --tx-dev <tx-nic>

# DUT: 룰 스케일링 (1 → 10000개 누적, 각 30초)
sudo tools/bench/rule_scaling_test.sh --interface <nic> --mode driver --generator external --duration 30

# 분석 (matplotlib: pip install -r tools/analysis/requirements.txt, 없으면 summary.md만)
python3 tools/analysis/analyze_performance.py --results-dir results
```
옵션 전체는 `--help`로 확인한다. 공통 옵션: `--interface`, `--mode driver|generic`, `--generator`, `--duration`, `--src-ip`, `--dst-ip`, `--rule-action drop|count|none`, `--output-dir`(기본 `./results`), `--api-server`, `--bpf-obj`, `--bin-dir`, `--no-daemon`, `--no-attach`, `--force-attach`, `--tx-dev`, `--dst-mac`, `--pktgen-threads`, `--no-prompt`, `--warmup`. `basic_throughput_test.sh` 전용 `--packet-sizes`, `rule_scaling_test.sh` 전용 `--rule-counts`, `--side src|dst`, `--packet-size`.

### 결과 파일 (`--output-dir`, 기본 `./results`)
| 파일 | 내용 |
|------|------|
| `meta_throughput.txt`, `meta_rule_scaling.txt` | 날짜, git rev, 커널, CPU, NIC 드라이버, 모드, 생성기 등 (`key=value`) |
| `throughput_results.csv` | 크기별 요약: `packet_size,generator,mode,rule_action,duration_sec,samples,pps,pps_peak,gbps,cpu_util,cpu_softirq,cpu_busiest,if_rx_pps,daemon_rss_kb` |
| `rule_scaling_results.csv` | 룰 수별 요약: 위 열 앞에 `rule_count,side,packet_size`, 뒤에 `rules_added,add_rules_sec,add_rule_us_avg` |
| `throughput/stats_<size>.csv`, `rule_scaling/stats_<count>.csv` | `xdp-filter stats --format csv` 원본 (1초 샘플) |
| `throughput/generator_<size>.log`, `rule_scaling/generator_<count>.log` | 생성기 출력 |
| `daemon.log` | 스크립트가 daemon을 띄운 경우 |
| `plots/` | `analyze_performance.py` 출력: `summary.md`, `throughput.png`, `throughput_cpu.png`, `throughput_timeseries.png`, `rule_scaling.png`, `rule_add_latency.png` |

열 정의는 [`poc-plan.md` 결과 파일](poc-plan.md#결과-파일과-열)에 있다. 확인할 것: driver 모드 attach 성공, `pps>0`, `cpu_busiest`가 수신 큐 CPU에서 높게 나오는지, `if_rx_pps`와 `pps`의 비교(매치율 확인. 드라이버마다 XDP_DROP 패킷을 rx 카운터에 넣는지가 다르므로 참고값).

### 흐름 검증 (NIC 불필요)
```bash
sudo tools/test/bench_flow_check.sh            # --build: 먼저 빌드, --keep: 결과 디렉토리 보존
```
실습 랩과 lab 생성기로 위 스크립트 전체(daemon 기동 → attach → 매치 룰 → 트래픽 → stats CSV → 요약 CSV → 분석 → 정리)를 실제로 실행하고, CSV 헤더·행 수·`pps>0`·분석 산출물·정리 상태를 판정한다. **수치는 veth와 python 송신의 한계일 뿐이며 성능 결과가 아니다.**
