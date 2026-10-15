# Swift-Guard PoC 계획 및 벤치마킹 가이드

이 문서는 Swift-Guard PoC와 SCIE 저널 투고를 위한 벤치마킹 계획이다. 실행 절차 요약은 [`linux-verification.md`의 Tier 3](linux-verification.md#tier-3--성능)에 있다.

## 구현 상태

| 시나리오 | 스크립트 | 측정 가능 | 비고 |
|----------|----------|-----------|------|
| 기본 처리량 (2.1) | `tools/bench/basic_throughput_test.sh` | ✅ | 프레임 크기별 pps·Gbps·CPU (1차 지표 `xdp_rx_pps`) |
| 룰 스케일링 (2.2) | `tools/bench/rule_scaling_test.sh` | ✅ | 룰 수별 pps (1차 지표 `xdp_rx_pps`) |
| 룰 추가 지연 (2.2) | `tools/bench/rule_scaling_test.sh` (`add_rule_us_avg`) | △ | CLI 프로세스 생성·API 연결(Unix 소켓) 포함. 순수 맵 갱신 지연 아님 |
| 지연 P50/P99 | — | ❌ | 측정 도구 없음 (6장) |
| WASM 오버헤드 (2.3) | — | ❌ | XDP→WASM 데이터 경로가 없다 |
| 보안 효과성 (3.1) | — | ❌ | 같은 이유 + 공격 트래픽·판정 하네스 없음 |
| 기존 솔루션 비교 | — | ❌ | 실측 스크립트 없음 |

흐름(스크립트가 끝까지 도는지)은 물리 NIC 없이 `sudo tools/test/bench_flow_check.sh`로 확인할 수 있다. 이때 나오는 수치는 성능 결과가 아니다.

## 1. 테스트 환경

### 하드웨어
- CPU: Intel Xeon E5-2680v4급 이상 (16코어 이상 권장)
- RAM: 32GB 이상
- NIC: XDP driver 모드를 지원하는 10GbE 이상 (Intel X520/X540/X550/X710 등)
- 송신 장비: 커널 pktgen을 돌릴 Linux 장비 1대(권장) 또는 DUT의 두 번째 NIC

### 소프트웨어
- OS: Ubuntu 22.04 LTS 이상, 커널 5.15+ (Ubuntu 22.04 GA 커널. 5.15 미만이면 벤치 스크립트가 경고한다)
- Rust **1.78+** (Cargo.lock v4)
- 패키지: `clang llvm libelf-dev libbpf-dev build-essential pkg-config linux-headers-$(uname -r) iproute2`
- 분석: `python3`, `matplotlib` (`pip install -r tools/analysis/requirements.txt`. 없으면 summary.md만 만든다)

### 토폴로지
```
(a) 권장: 송신 장비 ── 케이블 ── DUT NIC [XDP]
          tools/bench/pktgen_tx.sh       basic_throughput_test.sh --generator external

(b) 단일 호스트: DUT의 tx NIC ── 케이블 직결 ── DUT의 rx NIC [XDP]
          basic_throughput_test.sh --generator pktgen --tx-dev <tx-nic>  (송신과 수신이 CPU를 나눠 쓴다)

(c) 흐름 검증만: 실습 랩 veth sg-lab0 [XDP generic] ← python 송신
          --generator lab  (성능 수치 아님)
```
기본(`--rule-action drop`)은 XDP_DROP 룰로 측정하므로 목적지 서버(트래픽 싱크)는 필요 없다. `--rule-action count|none`은 패킷을 커널 스택으로 넘기므로(XDP_PASS) DUT의 커널이 그 트래픽을 처리한다.

## 측정 전 공통 사항

- **Tier 2 선행:** 같은 장비에서 `sudo tools/test/e2e_check.sh --build`를 먼저 통과시킨다.
- **두 가지 카운터:** `xdp-filter stats --format csv`(17열) 한 행에는 두 종류의 총계가 있다.
  - `xdp_rx_*`(BPF `xdp_stats_map`의 RX 슬롯): XDP가 본 **모든 프레임**을 파싱 전에 센다. 룰 매치와 무관하다. 여기서 나오는 **`xdp_rx_pps`가 처리량의 1차 지표**다.
  - `total_*`(BPF `stats_map`): **룰에 매치한 패킷만** 센다. 여기서 나오는 `pps`/`gbps`는 매치 룰 경로를 거친 패킷의 처리량이다.
  - 결과별 카운터(`xdp_drop_packets` … `xdp_action_error_packets`)는 원본 stats CSV에 그대로 남는다. 매치하지 않은 패킷은 `xdp_no_match_packets`, 비 IPv4는 `xdp_non_ipv4_packets`로 보인다.
- **매치 룰(`--rule-action`)은 측정 시나리오를 정한다:** 스크립트는 기본으로 트래픽 출발지(`--src-ip`, 기본 `198.18.0.2`)에 매치하는 룰 `bench-match`(`--protocol any`, `--rule-action drop`)를 넣는다. 이 룰이 없어도 `xdp_rx_pps`는 측정되지만, 대표 지표인 **XDP_DROP 경로**(룰 조회 + drop)를 재려면 송신 측 출발지 IP를 맞춘다. 맞추면 `pps`가 `xdp_rx_pps`와 거의 같아진다.
  - `drop`(기본): 룰 매치 후 XDP_DROP.
  - `count`: 룰 매치 후 XDP_PASS(커널 스택으로 감).
  - `none`: 룰을 넣지 않는다. 모든 패킷이 `no_match`로 XDP_PASS된다(커널 스택 경로). `pps`/`gbps`는 0이고 `xdp_rx_pps`로 처리량을 잰다.
- **계약 확인:** 측정 전에 stats CSV 헤더가 17열 계약과 같은지, daemon이 XDP 카운터를 주는지(`xdp_rx_packets`가 빈 칸이 아닌지) 확인한다. 다르면 "재빌드 필요"로 중단한다(이전 버전 `xdp-filter`·daemon·`xdp_filter.o` 혼용 방지).
- **daemon:** 스크립트가 API(`--api-server`, 기본 `unix:/run/swift-guard/api.sock`. TCP는 `tcp:127.0.0.1:<port>` 루프백만) 응답을 `xdp-filter list-rules`로 확인한다. 스크립트는 root로 실행하므로 소켓 권한(`root:swift-guard 0660`)에 막히지 않는다. 응답이 없으면 설정 파일 없이(기본값) daemon을 띄우고 끝나면 종료한다. 이미 실행 중이면 재사용한다. 이때는 기존 룰이 결과와 룰 한도에 영향을 준다는 경고를 출력하고, 끝나면 스크립트가 넣은 룰만 지운다. 재사용 daemon에 label `bench-match` 룰이 이미 있으면 지우지 않고 에러로 중단한다.
- **attach:** 기본 `--mode driver`. 스크립트가 attach하고 끝나면 detach한다. 재사용 daemon이 이미 그 인터페이스에 붙여 두었으면 `--no-attach`를 쓴다(attach도 detach도 하지 않는다). `--force-attach`(다른 프로그램의 XDP를 교체)는 스크립트가 daemon을 띄운 경우에만 허용되고, 재사용 daemon에서는 거부된다 — 교체 후 정리 단계의 detach가 운영 중인 필터를 떼어내지 않게 하기 위해서다.
- **실패 처리:** 측정 중 daemon이 응답하지 않거나 `xdp-filter stats`가 실패하면(데이터 행 0 포함) 그 측정의 요약 행을 기록하지 않고 종료 코드 1로 중단한다. 앞서 끝난 측정의 행은 남는다. 정리(trap)는 백그라운드 stats·생성기를 프로세스 그룹째 종료한다.
- **비율 계산:** pps·Mbps(룰 매치)와 xdp_rx_pps·xdp_rx_mbps(전체)는 CLI가 연속 두 샘플(1초 간격) 총계의 차이로 계산한다. 첫 샘플은 비율이 없다(CSV 빈 칸).
- **경고:** 측정 후 `xdp_rx_pps=0`이면 "트래픽이 XDP에 도달하지 않음"(인터페이스·송신 경로·dst MAC 확인), `xdp_rx_pps>0`인데 `pps=0`이고 `--rule-action`이 none이 아니면 "룰 미매치"(출발지 IP 확인)를 출력한다.
- **튜닝 권고:** `irqbalance` 정지, 수신 큐 IRQ와 CPU 고정, CPU 주파수 고정(performance governor), 측정 중 다른 부하 금지.
- **바이트 기준:** Gbps는 XDP가 보는 L2 프레임(FCS·프리앰블·IFG 제외) 기준이다. 선로 속도(line rate)와 다르다. 프레임 크기 옵션은 FCS를 포함한 L2 크기(64–1518)다.

## 2. 성능 벤치마크 시나리오

### 2.1 기본 처리량

- **목적:** 프레임 크기별 XDP 처리 성능
- **지표:** xdp_rx_pps·xdp_rx_gbps(1차), 룰 매치 pps·Gbps, CPU 사용률(전체·softirq·가장 바쁜 CPU), 인터페이스 rx pps, daemon RSS

```bash
# 송신 장비
sudo tools/bench/pktgen_tx.sh --dev <tx-nic> --dst-ip <DUT-IP> --dst-mac <DUT-MAC> --src-ip 198.18.0.2 --size 64 --duration 70
# DUT (external: 크기마다 안내 후 Enter 대기)
sudo tools/bench/basic_throughput_test.sh --interface <nic> --mode driver --generator external --packet-sizes 64 --duration 60

# 단일 호스트 (pktgen이 크기별로 자동 송신)
sudo tools/bench/basic_throughput_test.sh --interface <nic> --generator pktgen --tx-dev <tx-nic>

# XDP_PASS(커널 스택) 경로: 룰 없이 xdp_rx_pps 만 측정
sudo tools/bench/basic_throughput_test.sh --interface <nic> --generator pktgen --tx-dev <tx-nic> --rule-action none

# 흐름 검증 (NIC 불필요, 수치 의미 없음)
sudo tools/bench/basic_throughput_test.sh --generator lab --duration 5
```
측정 1회(크기 하나)의 절차:
1. `xdp-filter stats --format csv --interval 1 --count <duration+3>`을 백그라운드로 `throughput/stats_<size>.csv`에 기록
2. 1초 뒤 `/proc/stat`·인터페이스 `rx_packets` 스냅샷 → 생성기 `duration`초 → 스냅샷
3. 요약: 지표마다 비율 열이 0보다 큰 행(active)만 쓰고, 3행 이상이면 처음·마지막 행(부분 초)을 뺀 평균. `pps`/`gbps`는 stats CSV 4·5열(`pps`, `mbps`), `xdp_rx_pps`/`xdp_rx_gbps`는 8·9열(`xdp_rx_pps`, `xdp_rx_mbps`)로 각각 따로 계산한다

### 2.2 룰 스케일링

- **목적:** 맵에 든 룰 수가 처리량에 주는 영향, 룰 추가 시간
- **지표:** 룰 수별 xdp_rx_pps(첫 단계 대비 %), 룰 매치 pps, `add_rule_us_avg`

```bash
sudo tools/bench/rule_scaling_test.sh --interface <nic> --mode driver --generator external --duration 30
sudo tools/bench/rule_scaling_test.sh --interface <nic> --generator pktgen --tx-dev <tx-nic> --side dst
sudo tools/bench/rule_scaling_test.sh --generator lab --rule-counts 1,10,100 --duration 3     # 흐름 검증
```
- 단계(`--rule-counts`, 기본 `1,10,100,1000,5000,10000`)마다 filler 룰을 **누적** 추가하고 측정한다. `rule_count`는 매치 룰을 포함한 bench 룰 총수다.
- filler: `198.19.<i/256>.<i%256>/32`, label `bench-fill-<i>`, action pass. 트래픽과 매치하지 않는다. `--src-ip`·`--dst-ip`가 198.19.0.0/16이면 거부한다.
- 데이터 구조: 출발지 맵(`filter_rules`)과 목적지 맵(`dst_rules`)이 각각 LPM trie, **맵당 최대 10240**(`MAX_FILTER_RULES`), **prefix당 룰 1개**. 패킷마다 `/32` 키로 출발지 맵을 1회 조회하고, 미스(또는 조건 불일치)면 목적지 맵을 1회 더 조회한다. `--side dst`는 매치 룰과 filler를 목적지 맵에 넣어 모든 패킷이 두 번 조회되게 한다.
- `add_rule_us_avg` = 단계에서 추가한 filler 수로 나눈 벽시계 시간이다. `xdp-filter add-rule` 프로세스 생성과 API 연결(Unix 소켓)을 포함하므로 **순수 맵 갱신 지연이 아니다.** 매치 룰은 준비 단계에서 넣으므로 `rules_added`에 포함되지 않는다.
- 가설(미측정): LPM trie 조회 비용은 룰 수보다 prefix 길이 분포에 좌우되므로, 모두 /32인 이 시나리오에서는 룰 수에 대해 평탄할 것으로 예상한다.

### 2.3 WASM 모듈 오버헤드 — 현재 측정 불가

현재 WASM 모듈은 daemon에서 관리(load/list/stats/unload)만 된다. XDP가 패킷을 사용자 공간 WASM 모듈로 넘기는 경로가 없으므로 오버헤드를 원리상 측정할 수 없다. 선행 구현이 필요하다.
- XDP → 사용자 공간 데이터 경로 (AF_XDP 또는 perf/ring buffer)
- 사용자 공간에서 WASM `inspect_packet` 호출, 판정 결과를 룰/맵에 반영하는 경로

### 결과 파일과 열

`--output-dir`(기본 `./results`)에 다음을 만든다. 두 스크립트는 자기 파일만 덮어쓰므로 같은 디렉토리에 공존한다. 요약 CSV의 `xdp_rx_*` 3열은 맨 끝에 붙어 있으므로 기존 열 번호는 바뀌지 않았다(이전 버전 결과에는 이 3열이 없다).

| 파일 | 내용 |
|------|------|
| `meta_throughput.txt` / `meta_rule_scaling.txt` | `key=value`: date, git_rev, kernel, cpu_model, nproc, interface, driver, mode, generator, rule_action, duration, src_ip, dst_ip, daemon_reused (+ packet_sizes / side, packet_size, rule_counts) |
| `throughput_results.csv` | `packet_size,generator,mode,rule_action,duration_sec,samples,pps,pps_peak,gbps,cpu_util,cpu_softirq,cpu_busiest,if_rx_pps,daemon_rss_kb,xdp_rx_pps,xdp_rx_pps_peak,xdp_rx_gbps` |
| `rule_scaling_results.csv` | `rule_count,side,packet_size,generator,mode,rule_action,duration_sec,samples,pps,pps_peak,gbps,cpu_util,cpu_softirq,cpu_busiest,if_rx_pps,daemon_rss_kb,rules_added,add_rules_sec,add_rule_us_avg,xdp_rx_pps,xdp_rx_pps_peak,xdp_rx_gbps` |
| `throughput/stats_<size>.csv`, `rule_scaling/stats_<count>.csv` | `xdp-filter stats --format csv` 원본(17열): `timestamp_ms,total_packets,total_bytes,pps,mbps,xdp_rx_packets,xdp_rx_bytes,xdp_rx_pps,xdp_rx_mbps,xdp_drop_packets,xdp_pass_packets,xdp_redirect_packets,xdp_count_packets,xdp_no_match_packets,xdp_invalid_packets,xdp_non_ipv4_packets,xdp_action_error_packets` |
| `throughput/generator_<size>.log`, `rule_scaling/generator_<count>.log` | 생성기 출력 |
| `daemon.log` | 스크립트가 daemon을 띄운 경우 |
| `plots/` | 분석기 출력 (4장) |

| 열 | 의미 |
|----|------|
| `samples` | 원본 stats CSV의 데이터 행 수 |
| `pps` | **룰 매치 기준.** stats CSV `pps` 열의 active 행(>0) 평균, 3행 이상이면 처음·마지막 제외. 정수. `--rule-action none`이면 0 |
| `pps_peak` | 전체 행 `pps` 최대 |
| `gbps` | active 행 `mbps` 평균 / 1000 (소수 4자리, L2 바이트 기준) |
| `cpu_util` | 측정 구간 전체 CPU busy% = (total − idle − iowait) / total |
| `cpu_softirq` | softirq / total (%) |
| `cpu_busiest` | CPU별 busy% 중 최대 — XDP는 수신 큐 CPU에서 돌므로 이 값이 병목을 보여 준다 |
| `if_rx_pps` | 인터페이스 `rx_packets` 증가율. 드라이버마다 XDP_DROP 패킷 계수 여부가 달라 참고용 |
| `daemon_rss_kb` | daemon VmRSS (pid를 모르면 빈 칸) |
| `rules_added`, `add_rules_sec`, `add_rule_us_avg` | 단계에서 추가한 filler 수, 걸린 초, 룰당 µs. `rules_added=0`이면 뒤 두 칸은 빈 칸 |
| `xdp_rx_pps` | **XDP가 본 전체 프레임 기준 (처리량 1차 지표).** stats CSV `xdp_rx_pps` 열에 `pps`와 같은 규칙 적용. 룰 매치와 무관 |
| `xdp_rx_pps_peak` | 전체 행 `xdp_rx_pps` 최대 |
| `xdp_rx_gbps` | active 행 `xdp_rx_mbps` 평균 / 1000 (소수 4자리, L2 바이트 기준) |

## 3. 보안 효과성 테스트

### 3.1 공격 탐지 및 차단 — 현재 측정 불가

탐지율·오탐률은 WASM 검사 결과가 있어야 정의된다. 2.3과 같은 데이터 경로가 없으므로 원리상 측정할 수 없다. 선행 구현: XDP→WASM 데이터 경로, 판정 결과 반영 경로, 공격 트래픽 생성·판정 하네스(6장). 지금 할 수 있는 것은 정적 룰(drop/redirect)의 동작 확인이며, 이는 Tier 2(`tools/test/e2e_check.sh`)와 [`examples.md`](examples.md)가 다룬다.

## 4. 데이터 분석 및 그래프 생성

```bash
pip install -r tools/analysis/requirements.txt          # matplotlib
python3 tools/analysis/analyze_performance.py --results-dir results [--output-dir results/plots] [--no-plots]
```
`tools/analysis/analyze_performance.py`는 위 CSV를 표준 `csv` 모듈로 읽는다. 출력(기본 `<results-dir>/plots/`):

| 파일 | 내용 |
|------|------|
| `summary.md` | 요약 표 + meta. 섹션마다 사용한 처리량 지표를 표시한다 |
| `throughput.png` | 프레임 크기별 Mpps, Gbps (처리량 지표 기준) |
| `throughput_cpu.png` | `cpu_util`, `cpu_busiest` |
| `throughput_timeseries.png` | `throughput/stats_*.csv`의 1초 시계열 (`xdp_rx_pps`, 없으면 `pps`) |
| `rule_scaling.png` | 룰 수(log) 대비 Mpps(처리량 지표 기준), 첫 단계 대비 % |
| `rule_add_latency.png` | `add_rule_us_avg` |

- **처리량 지표:** 요약 CSV에 `xdp_rx_*` 열이 있으면 `xdp_rx_pps`/`xdp_rx_pps_peak`/`xdp_rx_gbps`를 쓴다. 이전 버전 결과(열 없음)는 `pps`/`pps_peak`/`gbps`(룰 매치 기준)를 쓰고 summary.md에 "이전 형식 결과"로 표시한다. 룰 매치 `pps`는 throughput 표에 별도 열로 함께 보인다.
- 입력 파일이 없거나 열이 계약(현재 또는 이전 형식)과 다르면 그 분석만 건너뛴다. 입력이 하나도 없으면 종료 코드 1.
- matplotlib이 없거나 `--no-plots`면 summary.md만 만든다.
- `generator=lab` 행이 있으면 그래프 제목과 summary.md에 "FLOW CHECK ONLY (lab generator) — not a performance result"를 표시한다.

## 5. SCIE 저널 투고를 위한 결과 정리

### 5.1 논문 구조

1. **Abstract**
   - Swift-Guard의 주요 개념, 혁신점, 주요 결과 요약

2. **Introduction**
   - 네트워크 보안의 현재 도전 과제
   - XDP 및 eBPF 기술의 등장과 중요성
   - WASM의 보안 애플리케이션 가능성
   - 연구 목표 및 기여점

3. **Related Work**
   - 기존 네트워크 보안 솔루션 비교
   - XDP 기반 연구 동향
   - WASM 기반 보안 애플리케이션 리뷰

4. **System Architecture**
   - Swift-Guard 아키텍처 상세 설명
   - XDP 필터링 메커니즘
   - WASM 통합 인터페이스
   - 최적화 기법

5. **Implementation**
   - 주요 구현 세부 사항
   - 핵심 알고리즘 및 데이터 구조
   - 시스템 컴포넌트 통합

6. **Evaluation**
   - 실험 환경 및 방법론
   - 성능 벤치마크 결과
   - 보안 효과성 평가
   - 기존 솔루션과의 비교

7. **Discussion**
   - 결과 분석 및 의미
   - 제한 사항 및 향후 개선 방향
   - 실제 환경 적용 시 고려 사항

8. **Conclusion**
   - 연구 요약 및 주요 발견
   - 향후 연구 방향

### 5.2 주요 실험 결과 (가설 — 미측정)

아래는 연구 목표로 세운 가설이며, 근거가 되는 측정은 아직 없다.

- **처리량:** 기존 네트워크 보안 솔루션 대비 3–4배 처리량 (근거 없음 — 비교 대상 측정 스크립트 없음)
- **지연 시간:** 마이크로초 단위 처리 (근거 없음 — 지연 측정 도구 없음)
- **규칙 확장성:** 10,000개 규칙에서도 처리량 저하가 작음 (근거 없음 — 2.2로 검증 예정)
- **WASM 오버헤드:** 기본 XDP 대비 10–15% (데이터 경로 구현 후 검증)
- **보안 효과성:** 주요 공격 탐지율 95% 이상, 오탐률 5% 미만 (데이터 경로 구현 후 검증)

## 6. 작성이 필요한 도구

| 도구 | 용도 |
|------|------|
| 지연 측정 | P50/P99. 예: TRex latency stream, 또는 NIC 하드웨어 타임스탬프 |
| XDP→WASM 데이터 경로 | AF_XDP 또는 perf/ring buffer로 패킷을 WASM `inspect_packet`에 전달, 판정 반영 (2.3, 3.1의 선행 조건) |
| 공격 트래픽 생성·판정 하네스 | 공격 유형별 트래픽 생성, 탐지/차단 결과 수집 (3.1) |
| BPF 맵 메모리 측정 자동화 | `bpftool map show`의 memlock을 결과에 기록 (현재는 `daemon_rss_kb`만) |
| 비교 대상 측정 | iptables/nftables, 룰 없는 vanilla XDP(XDP_DROP) 같은 기준선 스크립트 |

## 7. 추가 개발 및 연구 방향

1. **분산 환경 지원**:
   - Kubernetes 환경 통합
   - 다중 노드 간 정책 일관성 보장

2. **자가 적응형 보안**:
   - 머신러닝 기반 이상 탐지
   - 실시간 위협 상황에 따른 자동 정책 조정

3. **고급 WASM 보안 모듈**:
   - DPI(Deep Packet Inspection) 모듈
   - 암호화 트래픽 분석 모듈
   - IoT 프로토콜 특화 보안 모듈

4. **성능 최적화**:
   - 멀티 큐 NIC 최적화
   - NUMA 인식 리소스 할당
   - CPU 친화성 튜닝
