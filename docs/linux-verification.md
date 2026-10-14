# Swift-Guard 검증 가이드

Swift-Guard 검증은 세 단계(Tier)로 나뉜다. 단계마다 필요한 환경이 다르고, 아래 단계를 통과해야 위 단계가 의미를 가진다.

| Tier | 무엇을 확인하나 | 필요한 환경 | 실행 |
|------|----------------|------------|------|
| **1. 빌드·단위 테스트** | BPF 컴파일(BTF 포함), daemon/CLI 컴파일, 맵 바이트 레이아웃, API, 단위 테스트 | Rust 툴체인이 있는 아무 환경. daemon과 BPF는 Linux(또는 Docker)가 필요 | `cargo test --workspace`, `make -C src/bpf` |
| **2. 커널 기능 (E2E)** | verifier 로드, XDP attach/detach, drop·count·redirect 매치, CIDR(LPM 바이트 오더), 룰별·전역 통계, 입력 거부, SIGTERM 시 정리 | **Linux 커널 5.10+와 root**. 물리 NIC는 필요 없다(veth + generic XDP) | `sudo tools/test/e2e_check.sh --build` |
| **3. 성능** | Mpps, 지연(P50/P99), CPU 사용률, driver 모드, 10GbE 처리량. 논문 수치용 | 물리 서버, XDP 지원 NIC(Intel X520/X710 등), 트래픽 발생기 | [`poc-plan.md`](poc-plan.md), [`evaluation.md`](evaluation.md) |

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
[netns sg-e2e-src] sg-e2e-peer 10.200.0.2  <== veth ==>  sg-e2e-dut 10.200.0.1  [XDP generic 부착]
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
| 8 | 입력 거부 | src-ip 없음, dst-ip 지정, 없는 인터페이스, drop+redirect-if, prefix 중복은 모두 Error. daemon은 계속 살아 있음 |
| 9 | WASM 관리 | load/list/stats/unload. `wasm/modules/http_inspector.wasm`이 빌드돼 있을 때만 실행 |
| 10 | detach | CLI로 detach하면 xdp가 해제됨 |
| 11 | SIGTERM | 5초 안에 종료되고 xdp가 해제됨 |

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
[`examples.md`](examples.md)의 예시 10종을 실습 랩(`tools/test/lab.sh`)에서 그대로 실행하고 기대 결과와 비교한다.
```bash
sudo tools/test/examples.sh -v
```

## Tier 3 — 성능

물리 장비 구성과 시나리오는 [`poc-plan.md`](poc-plan.md)를, 측정 방법론과 지표는 [`evaluation.md`](evaluation.md)를 따른다. 시작하기 전에 같은 장비에서 Tier 2를 먼저 통과시켜, 기능 문제가 성능 수치를 오염시키지 않게 한다.

```bash
sudo tools/test/e2e_check.sh --build                       # 1) 기능 확인
sudo tools/bench/basic_throughput_test.sh --interface <nic>  # 2) 처리량 (driver 모드)
python3 tools/analysis/analyze_performance.py              # 3) 분석
```
