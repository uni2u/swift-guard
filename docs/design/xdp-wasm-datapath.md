# XDP → WASM 패킷 검사 데이터 경로: 설계 비교

- 상태: **결정 대기** (팀·지도교수 검토용). 이 문서는 코드를 바꾸지 않는다.
- 기준 코드: `main` HEAD `42d4eea`(초안). 1장 "현재 구조"는 HEAD `5d98195` 기준으로 갱신했다(2026-10-16).
- 작성: sg-architect, 2026-10-14
- 전제: `_workspace/01_architect_plan.md`(L4 파싱 수정, 미구현 옵션 거부, XDP 전체 카운터)가 먼저 들어간다고 가정했다. **세 가지 모두 반영 완료**(커밋 `bb5179f`; 1장 참고). 이 문서에서 새로 제안하는 액션 번호·맵 이름은 그 계획이 확정한 값(`ACTION_*` 1–4, `SG_STAT_*` 0–8)과 겹치지 않게 맞춘다.
- 표기: **[확인]** = 이 저장소 코드나 공식 문서·레지스트리에서 직접 확인함. **[확인 필요]** = 확인하지 못한 수치나 주장. **[측정 필요]** = 실험으로만 정할 수 있는 값.

---

## 0. 요약

- **추천:** **(d) 플로우 단위 하이브리드**를 고른다. 새 플로우의 첫 N개 패킷만 사본을 perf buffer(또는 ring buffer)로 사용자 공간에 보내 WASM으로 판정한다. 판정은 BPF 플로우 판정 캐시(LRU hash)와 동적 LPM 룰에 기록하고, 이후 패킷은 XDP가 캐시만 보고 처리한다. 운반 계층은 (b)를 재사용한다. 1단계는 (b)만으로 최소 실험 버전을 만들고, 2단계에서 (d)를 완성한다. 인라인 동기 판정 (a) AF_XDP는 필요할 때만 3단계 이후 비교군으로 둔다.
- **이유:**
  1. 원본 패킷이 사용자 공간을 거치지 않는다. 검사하지 않는 트래픽의 XDP 처리량이 거의 그대로 유지되고, daemon이 죽거나 멈추면 자연스럽게 fail-open이 된다.
  2. 지금 쓰는 libbpf-rs 0.19.1과 libbpf-sys 1.5만으로 만들 수 있다. 새 C 라이브러리(libxdp)도, NIC 큐 스티어링도 필요 없다.
  3. "탐지 → XDP 룰 자동 설치 → 만료"라는 자가 적응 루프가 구조 자체에 들어 있다. 반응 시간을 단일 시계(CLOCK_MONOTONIC) 하나로 잴 수 있다.
  4. 단점은 판정이 비동기라는 점이다. 플로우 첫 패킷 몇 개는 판정 전에 통과한다. 이 누출량을 지표로 정의해 논문에서 정면으로 보고하는 것을 제안한다(7장 Q1).

---

## 1. 현재 구조 (코드로 확인한 사실)

### 1.1 XDP 프로그램 — `src/bpf/xdp_filter.c` + `include/swift_guard.h` [확인]

- `xdp_filter_func` → IPv4이면 `handle_ipv4`가 처리한다. 파서 정책(커밋 `bb5179f`):
  - version≠4, IHL<5, IPv4 헤더 20B 미만, IHL×4가 패킷보다 긺, `tot_len < IHL×4`, `tot_len`이 실제 L3 길이보다 긺 → `XDP_DROP`(invalid). 룰 조회보다 먼저라 pass 룰로 예외 처리할 수 없다.
  - L4는 `iph + IHL×4`에서 읽는다(IP 옵션 건너뜀). L4 길이는 프레임 끝(`data_end`, 이더넷 패딩 포함)이 아니라 `tot_len − IHL×4`로 정한다.
  - 비조각·첫 조각: L4 길이가 TCP 20B / UDP 8B 이상이면 포트·플래그를 읽는다. 모자라면 MF=1(tiny fragment, RFC 1858) → invalid DROP, MF=0 → 포트 미확인(포트·플래그 조건 룰은 매치하지 않음).
  - 후속 조각: TCP이고 offset=1 → invalid DROP(RFC 1858). 그 외는 포트 미확인.
  - IPv4가 아니거나 이더넷 헤더 미만인 프레임은 검사 없이 `XDP_PASS`.
- 먼저 출발지 LPM 맵 `filter_rules`를 `/32` 키로 1회 조회한다. 미스이거나 조건이 맞지 않으면 목적지 LPM 맵 `dst_rules`를 1회 조회한다. 매치된 룰에 `apply_rule`을 적용한다.
- 액션은 `ACTION_PASS=1`, `ACTION_DROP=2`, `ACTION_REDIRECT=3`(`redirect_map` → `bpf_redirect`), `ACTION_COUNT=4`가 있다. 그 밖의 값(과 redirect 대상 없음)은 `XDP_PASS`로 처리하고 `SG_STAT_ACTION_ERR`로 센다(daemon은 1–4 밖의 action을 거부한다).
- 통계는 세 가지다. 매치된 룰 값 안의 `stats`는 `__sync_fetch_and_add`로 갱신된다. LPM 맵 값에 원자 연산을 쓰는 방식이 이미 verifier를 통과하고 있다는 뜻이다. 전역 `stats_map`(PERCPU_ARRAY)은 **매치된 패킷만** 센다. XDP 전체 카운터 `xdp_stats_map`(PERCPU_ARRAY, 값 `struct sg_counter` 16B = packets·bytes)은 슬롯 `SG_STAT_RX=0`, `DROP=1`, `PASS=2`, `REDIRECT=3`, `COUNT=4`, `NO_MATCH=5`, `INVALID=6`, `NON_IPV4=7`, `ACTION_ERR=8`(`SG_STAT_MAX=9`)이고, 패킷마다 RX 1회 + 결과 슬롯 정확히 1회 증가한다(불변식 RX = Σ결과). Rust 쪽 슬롯 상수는 `src/common/bpf_layout.rs`의 `xdp_stat`, CLI `stats --format csv`는 이 카운터를 `xdp_*` 열로 내보낸다(헤더 17열).
- 빌드: `src/bpf/Makefile`이 `-mcpu=v3`(JMP32·ALU32·atomics fetch/cmpxchg)로 컴파일한다(`BPF_CPU=v2`로 되돌릴 수 있음). 최소 커널은 5.15다(daemon은 미만이면 경고만 하고 계속한다).
- `struct filter_rule`은 88B다. `rate_limit`(off 20, u32)와 `expire`(off 24, u32) 필드가 있지만 **BPF가 읽지 않는다**. daemon의 `FilterRule::creation_time`은 `#[allow(dead_code)] // 향후 expire 처리용` 상태다.

### 1.2 daemon — `src/daemon/src/{main,server,maps,bpf,wasm}.rs` [확인]

- libbpf-rs 0.19.1의 `Object`/`Map`은 raw pointer를 들고 있어서 `!Send`다. 그래서 `MapManager`와 `XdpAttachManager`는 **main 태스크에서만** 쓴다. 연결 태스크는 BPF 요청을 `mpsc::channel::<BpfJob>(64)`로 accept 루프(main 태스크)에 보내고, 응답을 `oneshot`으로 받는다. 이 채널은 현재 `server.rs::serve()` 안에서 만들어진다.
- libbpf-rs 0.19.1에는 `MapHandle`이 없다. `Map::fd() -> i32`는 있다. `RingBuffer<'a>`는 `*mut ring_buffer`를 들고 있어 `!Send`이고, `RingBufferBuilder::add(&Map, cb)`처럼 `&Map`을 요구한다. 따라서 **소비 스레드를 따로 두려면 맵 fd를 꺼내 `libbpf_sys::ring_buffer__new(fd, …)` 또는 `perf_buffer__new`를 그 스레드에서 직접 호출해야 한다.** fd는 프로세스 전역이라 스레드 간 이동에 문제가 없다. 단, fd의 수명은 main의 `Object`에 묶인다(5.3절).
- `WasmManager`는 `Send + Sync`이고, 정적 단언으로 고정되어 있다. 안에는 `Mutex<Vec<WasmInspector>>` **하나**가 있고, 모듈마다 `Store`가 하나씩 있다. `inspect_packet(&[u8]) -> Result<bool>`가 이미 있지만 `#[allow(dead_code)]`이고 호출하는 곳이 없다. 패킷 1개를 검사할 때마다 게스트 호출이 3회(`allocate` → `inspect_packet` → `deallocate`) 일어나고, 호출마다 epoch deadline이 걸린다(기본 10ms, 설정 `wasm.execution_timeout_ms` 1–10000. 모듈 메모리 상한은 `wasm.memory_limit_mb` 기본 32, `init`은 1초 고정). 모든 모듈이 **잠금 하나 아래에서 직렬 실행**되므로, 검사 스레드를 늘려도 지금 구조로는 병렬화되지 않는다.
- WASM ABI v1은 `inspect_packet(ptr: i32, len: i32) -> i32`이고, 0이면 통과, 0이 아니면 차단이다. 입력은 이더넷 헤더부터 시작하는 원시 프레임이다. 예제 `wasm/modules/http_inspector.rs`는 0 또는 1만 반환하고, 페이로드 길이가 4096을 넘으면 의심으로 판정한다.
- API 전송: 기본은 Unix 소켓 `unix:/run/swift-guard/api.sock`(`root:swift-guard`, `0660`, 그룹이 없으면 `0600`). 프레이밍은 u32 빅엔디안 길이 + JSON. TCP는 루프백만 옵트인(`tcp:127.0.0.1:<포트>`, 인증 없음). 변경 요청(attach/detach/add-rule/delete-rule/wasm load·unload)은 `API <Variant> from uid=… gid=… pid=…`로 info 감사 로그를 남긴다. 자원 상한: 프레임 1 MiB, 동시 연결 64, 연결별 읽기·쓰기 각 10초, 동시 진행 `wasm load` 2.
- 입력 검증(`server.rs::validate_add_rule`): 미구현 옵션 `priority`·`rate_limit`·`expire`는 0만 허용하고 0이 아니면 Error로 거부한다(`--pkt-len`은 CLI가 거부). action은 1–4(`VALID_ACTIONS`), protocol은 1/6/17/255만 받는다.
- 정상 종료나 panic unwind로 끝나면 `DetachGuard`가 XDP를 뗀다. 즉 **daemon이 정상적으로 내려가면 필터 자체가 사라진다**. SIGKILL로 죽었을 때만 XDP와 맵이 남는다.

### 1.3 의존성 버전 [확인: `Cargo.lock`, crates.io API 2026-10-14 조회]

| 크레이트 | 사용 중 | 레지스트리 최신 | 비고 |
|---|---|---|---|
| libbpf-rs | 0.19.1 | 0.27.2 (2026-09-25) | `MapHandle`은 0.19에 없음. 업그레이드는 이 설계의 필수 조건이 아님 |
| libbpf-sys | 1.5.0+v1.5.0 | — | 번들 libbpf 1.5. **`xsk_socket__create` 바인딩 없음**(libbpf 1.0에서 xsk API가 libxdp로 이전). `ring_buffer__new`, `bpf_map_update_elem` 바인딩은 있음 |
| wasmtime | 12.0.2 | 49.0.2 | 업그레이드는 선택 사항 |
| tokio | 1.44.1 | — | |
| xsk-rs | — | 0.11.0 (2026-08-28) | libxdp-sys ^0.2.4에 의존. README 기준 "Tested on … Linux kernel 6.5.0", "a fair amount of unsafe". 다운로드 약 16.6만 회 |
| libxdp-sys | — | 0.2.4+1.6.0 (2026-02-04) | 벤더링한 libxdp를 빌드함. 내부 libbpf가 libbpf-sys와 충돌하는지 **[확인 필요]** |
| afxdp | — | 0.4.0 (2021-03-14) | libbpf-sys ^0.3에 의존. **5년 넘게 갱신 없음** → 후보에서 제외 |
| aya | — | 0.14.0 | XSKMAP 지원. 지금 쓰는 libbpf-rs 스택을 통째로 바꿔야 함 → 제외 |
| nfq | — | 0.2.5 (2022-01) | (e) NFQUEUE 비교군용 |

---

## 2. 요구사항과 평가 기준

| # | 기준 | 정의 / 이 프로젝트에서 묻는 것 |
|---|---|---|
| R1 | 처리량 영향: **비대상** 트래픽 | 검사 범위 밖 패킷의 XDP pps가 훅 없음 대비 몇 % 떨어지는가. poc-plan 2.1 스크립트로 측정 가능해야 한다 |
| R2 | 처리량 영향: **대상** 트래픽 | 검사 범위 안 패킷의 pps. 사용자 공간을 거치는가, 사본만 가는가 |
| R3 | 추가 지연 | 대상 패킷의 단방향 지연 증가. 인라인 방식은 WASM 실행 시간이 그대로 지연에 더해진다 |
| R4 | 판정 반영 방식 | **인라인 동기**(판정 전까지 패킷 보류) vs **비동기 사후 차단**(사본 판정 → 룰 설치) |
| R5 | 검사 커버리지 | 전체 / 1:K 샘플링 / 플로우 첫 N패킷 / 헤더만 vs 페이로드 snaplen |
| R6 | 구현 복잡도 | BPF·daemon·WASM ABI 변경량, 새 의존성 |
| R7 | 커널·NIC 요구 | 최소 커널, driver/generic 모드, zero-copy, 큐 스티어링 |
| R8 | verifier 제약 | 가변 길이 복사, 원자 연산, 루프, 스핀락 사용 가능 여부 |
| R9 | Rust 생태계 | libbpf-rs 0.19와 함께 쓸 수 있는가, 크레이트 성숙도 |
| R10 | 실험 설계 적합성 | poc-plan 2.3(WASM 오버헤드), 3.1(TPR/FPR/F1, 반응 시간, 차단율) 측정 가능성 |
| R11 | 장애 시 동작 | daemon 다운·멈춤·과부하 시 fail-open인가 fail-closed인가, 그것을 고를 수 있는가 |

**목표 환경 가정** [확인: `docs/poc-plan.md`, `docs/evaluation.md`]: Ubuntu 22.04(커널 5.15), 최소 5.15(결정됨, Q3), Intel X710(i40e) 10GbE, driver 모드, DUT는 트래픽 싱크(측정용 XDP_DROP 룰). **DUT가 종단 호스트**라는 점이 중요하다. 검사를 통과한 패킷은 DUT의 로컬 스택으로 가야 한다. 브리지·미들박스 토폴로지가 아니다.

---

## 3. 후보 방식 비교

모든 방식에 공통으로 "검사 범위"를 고르는 수단이 필요하다. 이 문서는 새 LPM 룰 액션 **`ACTION_INSPECT`**(01 계획은 액션을 늘리지 않았으므로 5로 확정 가능. `server.rs` `VALID_ACTIONS` 1..=4 확장 필요)를 제안한다. 운영자가 "dst 10.0.0.10/32, TCP 80"처럼 룰로 검사 대상을 지정하고, 매치된 패킷만 검사 경로로 보낸다. 매치되지 않은 트래픽은 기존 경로를 그대로 탄다(R1).

### (a) AF_XDP (XSK) — 인라인 사용자 공간 판정

```
 NIC rxq k ──► XDP xdp_filter_func
                 ├─ 비대상 ─────────────────────────────► XDP_PASS/DROP (기존)
                 └─ INSPECT 매치 ─► bpf_redirect_map(&xsks, rxq_k, XDP_PASS)
                                     │  (XSK 미등록이면 하위 2비트 = 폴백 액션)
                                     ▼
                     [UMEM + RX ring]  ◄─ FILL ring
                                     │
                    daemon xsk worker(rxq k 전용 스레드)
                       WASM inspect → pass ─┬─► TX ring → 같은 netdev 송신(egress)
                                            │   ※ 로컬 스택으로 재주입하는 경로 없음
                                            └─► (종단 호스트) tap 장치에 write → 스택
                                    drop → 프레임을 FILL로 반환
```

- **패킷 흐름:** 대상 패킷의 **원본**이 사용자 공간으로 간다. 커널 스택은 그 패킷을 보지 못한다.
- **판정 반영:** 인라인 동기 방식이다. drop이면 프레임을 버린다. pass이면 **다시 내보내야** 한다. 커널 문서는 TX 링으로 netdev에 송신하는 방법만 설명하고, 로컬 스택 재주입은 다루지 않는다 [확인: kernel AF_XDP 문서]. DUT가 종단 호스트이므로 pass된 패킷을 tap/veth에 써서 스택으로 다시 넣어야 한다. 이 경로는 사용자→커널 복사와 skb 생성 비용이 들고, 원래 수신 인터페이스와 다른 인터페이스로 들어간 것처럼 보이는 문제(라우팅·소켓 바인딩)가 있다. 브리지 토폴로지(NIC 2개)라면 TX가 자연스럽다.
- **BPF 측 변경:** `BPF_MAP_TYPE_XSKMAP` 추가(키 = rx queue index), `ctx->rx_queue_index` 사용, `bpf_redirect_map(&xsks, idx, XDP_PASS)` 호출. 맵에 해당 인덱스가 없을 때 "하위 2비트를 반환 코드로 쓰는" 폴백은 [확인: bpf-helpers(7)]. 맵에 엔트리가 없을 때 드롭한다는 설명도 커널 문서에 있다. verifier 부담은 작다.
- **큐 제약:** 소켓은 (netdev, queue id) 하나에 바인드되고, **다른 큐에서 온 프레임은 드롭된다** [확인: kernel AF_XDP 문서]. 따라서 (1) 수신 큐마다 소켓과 스레드를 하나씩 두거나, (2) `ethtool` ntuple로 대상 트래픽을 특정 큐로 스티어링해야 한다. 큐 수와 같은 개수의 WASM 인스턴스가 필요하고, 현재 `WasmManager`의 단일 Mutex 구조와 충돌한다.
- **daemon 측 변경:** 큐마다 전용 OS 스레드를 둔다(tokio 밖). UMEM과 ring 관리, FILL/COMPLETION 처리, need_wakeup(커널 문서가 "항상 켜기"를 권장) 처리가 필요하다. libbpf-sys 1.5에는 xsk API가 없으므로 **xsk-rs(libxdp-sys) 같은 새 의존성**이 필요하다. 이 경우 libbpf가 두 벌(libbpf-sys 번들과 libxdp 내부) 들어갈 수 있다 **[확인 필요]**. `!Send` 문제는 XSKMAP fd만 main에서 꺼내 넘기면 되므로 직접 충돌하지 않는다. 다만 WASM은 큐마다 `Store`/`Instance`가 따로 있어야 한다.
- **WASM ABI:** v1 그대로 동작한다. 인라인 판정에는 drop/pass만 의미가 있고 rate_limit은 사용자 공간 토큰 버킷으로 구현하게 된다.
- **성능 특성:** 대상 트래픽의 처리량 상한은 "큐 수 × 1/(WASM 1회 시간 + ring 처리 + 재주입)"이다. WASM 1회 시간은 지금 `avg_processing_time_us`로 잴 수 있다 **[측정 필요]**. zero-copy는 드라이버 지원이 필요하고, 지원하지 않으면 copy 모드로 폴백한다 [확인: 문서]. i40e의 zero-copy 지원 여부와 성능 **[확인 필요]**. 비대상 트래픽에는 XSKMAP 분기가 하나 늘 뿐이다.
- **장애 시 동작:** 소켓을 닫으면 XSKMAP 엔트리가 제거되어 폴백(XDP_PASS)으로 fail-open이 될 것으로 예상한다 **[확인 필요: 소켓 해제 시 맵 엔트리 자동 삭제]**. daemon이 **멈춤·과부하** 상태(살아 있지만 링을 비우지 못함)이면 RX 링이 차서 대상 트래픽이 **드롭된다(사실상 fail-closed)**.
- **위험:** 종단 호스트 재주입 문제(가장 크다), 큐 스티어링에 따른 실험 설정 복잡도, libxdp 의존과 unsafe, 공격 트래픽이 사용자 공간을 직접 포화시키는 문제(검사 대상 DDoS 시 WASM이 병목이 되어 정상 트래픽까지 드롭).

### (b) BPF perf buffer / ring buffer 사본 — 비동기 판정 → 룰 설치

```
 NIC ──► XDP xdp_filter_func
          ├─ 비대상 ─────────────────────────────► 기존 경로
          └─ INSPECT 매치 ─┬─ (샘플 조건 충족 시) 메타 24B + 앞 snaplen 바이트 사본
                           │        └─► PERF_EVENT_ARRAY(CPU별) 또는 RINGBUF
                           └─ 원본: XDP_PASS (계속 진행, 판정 기다리지 않음)

 daemon sg-inspect 스레드:  perf_buffer__poll / ring_buffer__poll (fd 직접)
     ├─ WASM inspect_packet(사본) → verdict
     ├─ verdict=drop/rate_limit → 동적 룰 설치 (BpfJob → main 태스크 → LPM 맵)
     └─ 판정 로그(CSV) 기록 → TPR/FPR, 반응 시간
```

- **패킷 흐름:** 원본은 XDP에서 그대로 진행한다. 사본(헤더와 앞부분 페이로드)만 사용자 공간으로 간다.
- **판정 반영:** 비동기 사후 차단이다. 판정이 나오면 그 출발지 `/32`(또는 판정이 지정한 범위)에 drop/rate-limit 룰을 `expire`와 함께 설치한다. 판정이 나오기 전에 이미 지나간 패킷(누출)이 생긴다.
- **BPF 측 변경 — 사본 복사 방식(verifier가 핵심):**
  - **perf buffer:** `bpf_perf_event_output(ctx, &samples, BPF_F_CURRENT_CPU | ((u64)cap << 32), &meta, sizeof(meta))` 형태로 플래그 상위 비트(`BPF_F_CTXLEN_MASK`, 20비트)에 복사할 패킷 길이를 넣으면 커널이 ctx에서 패킷을 붙여 준다. 헬퍼 문서에 "TC or XDP … packet payload"가 명시되어 있다 [확인: UAPI `bpf.h` 주석, `BPF_F_CTXLEN_MASK = 0xfffff<<32`]. `cap = min(pkt_len, SNAPLEN)`을 **런타임 값**으로 줄 수 있어서 짧은 패킷도 verifier 문제 없이 처리된다. 5.15(최소 커널)에서 사용 가능하다.
  - **ring buffer**(커널 5.8+ → 5.15에서 사용 가능하지만 아래 이유로 5.15에서 패킷 사본 운반을 보장하지 못한다, [확인: libbpf-rs 0.19.1 소스 주석 "As of Linux 5.8"]): `bpf_ringbuf_reserve`는 **상수 크기만** 받는다 [확인: kernel ringbuf 문서]. 그래서 고정 크기 레코드를 예약하고 패킷을 복사해야 한다. 복사 수단은 `bpf_xdp_load_bytes`(헬퍼 존재 [확인: UAPI], 도입 커널 5.18 **[확인 필요]** → 22.04의 5.15에는 없을 수 있음) 아니면 패킷 포인터 경계 검사를 곁들인 bounded loop다(명령어 수 증가). `bpf_ringbuf_output`은 가변 길이를 받지만, 패킷 포인터와 가변 길이의 조합이 verifier를 통과하는지 **[확인 필요]**.
  - → **결정: Phase 1은 perf buffer**(Q3 결정에 따라 확정. 5.15에서 가변 길이 ctx 복사 지원). ringbuf 재검토 조건: 최소 커널 ≥5.18이 되거나, 측정에서 perf의 CPU별 버퍼 메모리·순서 문제가 확인될 때(ringbuf는 CPU 간 순서 보장, 메모리 효율 [확인: 문서]).
  - 버퍼가 가득 차면 ringbuf 예약은 실패하고 블로킹하지 않는다 [확인: 문서]. perf도 출력 실패를 반환한다. 이 실패는 `sample_lost` 카운터로 센다.
- **daemon 측 변경:** 전용 OS 스레드 `sg-inspect`를 둔다. main에서 맵 fd를 꺼내 넘기고, 스레드 안에서 `libbpf_sys::perf_buffer__new(fd, …)`를 호출한다. libbpf-rs `PerfBufferBuilder`/`RingBufferBuilder`는 `&Map`(main 태스크)을 요구하므로 쓸 수 없다. 동적 룰 설치는 기존 `BpfJob` 채널로 main 태스크에 보내 `MapManager`가 수행한다. 이렇게 하면 데몬 룰 캐시(list-rules)와 맵이 일치한다. 이를 위해 `BpfJob` 채널 생성을 `serve()` 밖(main)으로 끌어올려야 한다. `!Send` 구조와 충돌하지 않는다.
- **WASM ABI:** v1으로도 동작한다(≠0 → drop 룰 설치). 다만 사본이 snaplen에서 잘리므로 **원래 길이(`pkt_len`)를 게스트에 알려야 한다**. `http_inspector`의 "payload > 4096" 규칙은 잘린 사본에서는 판정할 수 없다. 이는 4.1절 ABI v2에서 다룬다.
- **성능 특성:** 비대상 트래픽에는 영향이 없다(분기 0개 추가. INSPECT 매치 때만 비용 발생). 대상 트래픽은 원본이 XDP_PASS로 계속 가므로 처리량 상한이 기존 PASS 경로와 같고, 샘플 1개당 헬퍼 호출 1회와 snaplen 복사 비용이 더해진다 **[측정 필요]**. 검사 용량은 `C = 1 / t_wasm`(스레드 1개)이고, 샘플 유입률 `R_s`가 C를 넘으면 버퍼 포화로 `sample_lost`가 늘어난다. 따라서 **"전체 검사"는 고속에서 성립하지 않고**, 샘플링(1:K)이나 (d)의 첫 N패킷 제한이 필요하다.
- **장애 시 동작:** daemon이 멈추거나 죽으면 사본을 소비하지 못해 출력이 실패하지만, 원본은 진행한다(**fail-open**). 이미 설치된 동적 룰은 남는다. 만료 처리가 daemon 쪽에 있으면 만료되지 않은 채 남는 문제가 있다(4.3절).
- **위험:** 누출량이 판정 지연에 비례한다. 샘플링 때문에 탐지율의 정의가 바뀐다(패킷 단위 → 샘플 단위). 공격자가 판정 전 짧은 버스트로 회피할 수 있다.

### (c) 검사용 가상 인터페이스(veth/tap) redirect 또는 미러 + raw socket

```
 NIC ──► XDP ── INSPECT 매치 ─► bpf_redirect(veth_insp0)  (인라인; XDP에는 clone 헬퍼 없음)
                                     │
                         veth_insp1 ─► daemon AF_PACKET raw socket
                                     ├─ pass → ? (tap에 write해 스택 재주입 / 다른 인터페이스로 송신)
                                     └─ drop → 버림
 미러(사본)가 필요하면: TC ingress에서 bpf_clone_redirect(veth_insp0) — XDP가 아님
```

- **패킷 흐름:** XDP에서 고르면 인라인 redirect가 된다(원본이 넘어감). XDP에는 패킷 복제 헬퍼가 없다. 미러(사본)를 만들려면 TC 단계의 `bpf_clone_redirect`나 tc mirred가 필요하다. 이 경우 XDP 데이터 경로라고 부르기 어렵고, skb가 생성된 뒤라 XDP의 성능 이점이 사라진다.
- **판정 반영:** 인라인이면 (a)와 같은 재주입 문제가 생긴다. 미러이면 (b)와 같은 비동기 룰 설치가 된다.
- **BPF 측 변경:** 기존 `ACTION_REDIRECT` + `redirect_map`을 그대로 쓸 수 있다. 가장 작은 변경이다. native XDP에서 veth로 redirect할 때 피어 쪽 XDP 프로그램이 필요한지 **[확인 필요]**.
- **daemon 측 변경:** AF_PACKET 소켓 읽기 스레드를 둔다(tokio도 가능). 의존성 추가는 없다.
- **WASM ABI:** v1.
- **성능 특성:** 패킷마다 skb 생성과 AF_PACKET 복사(recvmsg 또는 TPACKET mmap)가 들어간다. (a)나 (b)보다 패킷당 비용이 크다고 예상한다 **[측정 필요]**.
- **장애 시 동작:** 인라인이면 daemon이 다운되는 순간 대상 트래픽이 블랙홀이 된다(fail-closed, 조절 불가). 미러이면 fail-open.
- **위험:** 논문의 "XDP 데이터 경로" 주장과 맞지 않는다. 성능 결과가 나쁘게 나온다. 장점은 프로토타이핑이 가장 빠르다는 것 하나다.

### (d) 플로우 단위 하이브리드 — 첫 N패킷 샘플 → 플로우 판정 캐시 (추천)

```
 NIC ──► XDP
   1) LPM 룰 (정적 운영자 룰 + 동적 자동 룰)      ─ 매치: 기존 액션 (drop/pass/redirect/count)
   2) INSPECT 매치(또는 inspect 정책) → flow_key(5-tuple)
        flow_verdict(LRU_HASH) 조회
        ├─ DECIDED & 미만료 → verdict 적용: pass / drop / rate_limit(플로우 토큰) / redirect
        ├─ SAMPLING & sampled < N → 사본 전송(perf) + 대기 정책(기본 pass)
        ├─ SAMPLING & sampled ≥ N → 대기 정책(기본 pass), 판정 기다림
        └─ 미스 → BPF_NOEXIST로 SAMPLING 엔트리 삽입 → 사본 전송
 daemon sg-inspect:
   사본 → WASM → verdict
     ├─ 플로우 판정: flow_verdict[key] = {DECIDED, verdict, expire_ns}  ← 스레드에서 fd로 직접 update
     └─ 출발지 차단 판정(정책): LPM 동적 룰 설치 (BpfJob → main), expire 포함
   만료: XDP는 expire_ns가 지난 엔트리를 미스로 취급, LRU가 자동 축출, daemon reaper가 LPM 동적 룰 삭제
```

- **패킷 흐름:** 원본은 항상 XDP 안에서 처리된다. 사용자 공간으로 가는 것은 **플로우당 최대 N개 사본**뿐이다.
- **판정 반영:** 비동기다. 그런데 판정이 플로우 캐시에 기록된 뒤에는 그 플로우의 **나머지 모든 패킷**에 XDP 속도로 적용된다. 누출은 "판정이 나올 때까지 그 플로우에서 통과한 패킷 수"로 한정되고, 플로우 상태에 기록되어 직접 셀 수 있다.
- **BPF 측 변경:**
  - `flow_verdict`: `BPF_MAP_TYPE_LRU_HASH`, 키 `struct sg_flow_key`(16B), 값 `struct sg_flow_state`(72B). 레이아웃은 4.2절.
  - `samples`: `PERF_EVENT_ARRAY`((b)와 공유).
  - `inspect_cfg`: `ARRAY`[1]. N, snaplen, 대기 정책(pass/drop), 1:K 샘플링을 담는다. daemon이 런타임에 바꿀 수 있다.
  - 경합: 같은 플로우가 두 CPU에서 동시에 첫 패킷이 되면 `BPF_NOEXIST` 삽입 하나만 성공한다. 실패한 쪽은 다시 조회한다. `sampled`는 `__sync_fetch_and_add`(결과 미사용 → BPF_XADD, v1 ISA로 가능)로 올린다. 경합 때문에 N을 약간 넘을 수 있지만 허용한다.
  - 플로우 키 파싱은 L4 오프셋에 의존한다. 01 계획의 **IHL 기반 L4 파싱 수정이 선행 조건**이다 — **완료**(`bb5179f`, 1.1절).
  - verifier: 루프가 없고, 맵 조회와 헬퍼 몇 개만 쓴다. 명령어 수가 늘어나지만 한도 문제가 생길 가능성은 낮다고 본다 **[측정 필요: `bpftool prog show`의 xlated 크기]**.
- **daemon 측 변경:** (b)와 같고, 여기에 다음이 추가된다. (1) `sg-inspect` 스레드가 `flow_verdict` fd에 `libbpf_sys::bpf_map_update_elem`을 **직접** 호출한다. 플로우 캐시는 daemon 룰 캐시에 넣지 않으므로 main을 거칠 필요가 없고, 반응 시간에서 tokio 홉이 빠진다. (2) LPM 동적 룰만 `BpfJob`으로 보낸다. (3) 만료 reaper를 둔다(main 태스크의 기존 `select!`에 interval 분기 추가).
- **WASM ABI:** v2(4.1절)를 권장한다. 이유는 판정 종류 확장, `pkt_len`과 플로우 내 순번 전달, 판정 TTL 전달이다. v1 모듈은 그대로 쓸 수 있다(≠0 → drop).
- **성능 특성:**
  - 비대상 트래픽에는 영향이 없다.
  - 대상 트래픽의 DECIDED 플로우는 패킷마다 LRU 조회 1회가 추가된다(LPM 조회 1~2회에 더해). 상대 비용은 **[측정 필요]**. 기존 2.2 룰 스케일링과 같은 방식으로 "INSPECT 범위 + 캐시 히트 100%" 조건을 잴 수 있다.
  - 사용자 공간 부하는 `R_s ≈ (새 플로우/s) × N`이다. 패킷률이 아니라 **플로우 생성률**이 부하를 결정한다. SYN flood처럼 플로우 생성률이 높은 공격은 사본 포화를 일으키므로, 이 경우는 rate limit(4.4절)과 출발지 LPM 룰이 담당한다. 이 경계를 실험으로 보여 줄 수 있다.
- **장애 시 동작:** daemon이 다운되거나 멈추면 사본 출력이 실패하고, 플로우는 SAMPLING 상태에 머물며 대기 정책을 따른다(기본 pass → **fail-open**). `inspect_cfg.pending_policy=drop`이면 대상 범위에 대해 fail-closed가 된다. **정책으로 고를 수 있다**는 것이 (a)·(b)와의 차이다. 이미 DECIDED된 엔트리는 expire_ns까지 유효하다(BPF가 직접 판단하므로 daemon 없이도 만료된다).
- **위험:** (1) 첫 N패킷 안에 악성 페이로드가 나오지 않으면(예: 긴 세션 중간의 공격) 놓친다. N과 재샘플 주기가 탐지율과 비용을 맞바꾸는 핵심 파라미터다. (2) 이 구조에 맞지 않는 플로우 상태형 탐지(포트 스캔은 여러 플로우를 묶어 봐야 함)는 daemon 쪽 집계로 보완해야 한다. 즉 WASM 상태가 인스턴스마다 다른 문제가 있다. (3) LRU 축출로 판정이 사라지면 같은 플로우를 다시 샘플링하게 된다.

### (e) 기타 — 참고·비교군

| 방식 | 요지 | 판단 |
|---|---|---|
| **XDP_PASS + netfilter NFQUEUE** | XDP는 거르지 않고 통과시키고, iptables/nft `NFQUEUE`가 대상 패킷을 사용자 공간으로 보낸다. daemon(nfq 0.2.5)이 WASM으로 판정해 ACCEPT/DROP을 커널에 돌려준다 | 인라인 동기이면서 **로컬 스택 재주입 문제가 없는 유일한 성숙한 방식**이다. 다만 XDP 데이터 경로가 아니다. 논문의 **비교 기준선**("WASM 인라인 IPS를 기존 커널 경로로 구현했을 때")으로 가치가 있다 |
| **cpumap redirect** | XDP에서 다른 CPU로 넘겨 그 CPU에서 skb를 만든다 | 사용자 공간 전달 수단이 아니다. 수신 CPU 부하 분산용이다. 이 문제에는 해당하지 않는다 |
| **TC(cls_bpf) + clone** | `bpf_clone_redirect`로 사본을 만든다 | (c)의 미러 변형. skb 경로라 XDP 이점이 없다 |
| **WASM을 커널에서 실행** | — | 범위 밖이다(커널 모듈 필요, verifier 대상 아님) |

---

## 4. 판정 반영 구조 공통 설계 ((b)/(d) 기준, (a)에도 일부 적용)

### 4.1 Verdict 종류와 WASM ABI v2

| 코드 | 이름 | XDP 반영 | 파라미터(상위 24비트) |
|---|---|---|---|
| 0 | `PASS` | 플로우 DECIDED/pass (이후 검사 안 함) | TTL 초(0 = 기본값) |
| 1 | `DROP` | 플로우 drop. 정책에 따라 출발지 `/32` LPM drop 룰 추가 | TTL 초 |
| 2 | `ALERT` | 통과. 판정 로그·텔레메트리만 남김(탐지 평가용) | — |
| 3 | `RATE_LIMIT` | 플로우(또는 출발지) 토큰 버킷 적용 | pps (최대 2^24−1) |
| 4 | `REDIRECT` | `redirect_map` 슬롯으로 redirect(허니팟 등) | redirect_map 키(ifindex) — 24비트에 들어가지 않으면 슬롯 번호로 간접 지정 **[결정 필요]** |
| 255 | `UNDECIDED` | 판정 보류. 다음 샘플을 더 봄(N 한도 안) | — |

- **반환 인코딩:** `inspect_packet(ptr, len) -> i32`의 시그니처를 그대로 두고, `ret & 0xFF` = 코드, `(ret >> 8) & 0xFFFFFF` = 파라미터로 해석한다.
- **버전 협상(하위 호환):** 게스트가 선택 export `abi_version() -> i32`를 내보내지 않으면 **v1**으로 보고, 지금처럼 0 → PASS, ≠0 → DROP으로 해석한다. 그러면 `http_inspector`를 고치지 않아도 된다. `abi_version()==2`이면 위 표를 쓴다. 정의되지 않은 코드는 DROP으로 처리한다(보수적).
- **입력 메타데이터:** v2 게스트에게는 패킷 앞에 고정 헤더 `struct sg_inspect_meta`를 붙여 넘기고 `len`에 그 크기를 포함하는 방식과, `inspect_packet_ex(ptr, len, meta_ptr)` 같은 별도 export를 쓰는 방식 중 하나를 고른다. 이 문서는 **별도 export 없이 v2에서만 메타 헤더를 앞에 붙이는 방식**을 제안한다(export가 하나로 유지됨). 메타 헤더에는 `pkt_len`(원래 길이), `cap_len`, `flow_seq`(플로우 내 몇 번째 샘플인지), `ts_ns`, 그리고 L3/L4 오프셋(호스트가 이미 파싱한 값)을 담는다.
- 이 변경은 `src/daemon/src/wasm.rs`의 ABI 표, `WasmInspector::inspect_packet`의 반환 타입(`Result<bool>` → `Result<Verdict>`), `WasmManager::inspect_packet`(차단 즉시 반환 → "가장 강한 판정" 합성 규칙 **[결정 필요: 모듈 여러 개의 판정 합성]**), `.claude/skills/wasm-module-dev` 문서 표에 영향을 준다.

### 4.2 맵 계약 (C 정의 = SSOT, `include/swift_guard.h`에 추가 예정)

offset은 x86_64/arm64 자연 정렬 기준의 손 계산이다. 구현할 때 `struct_layout.py`로 측정해 고정한다.

```c
/* 플로우 키: 원본 패킷 방향 그대로(정규화 안 함 — 응답 방향은 별개 플로우) */
struct sg_flow_key {          /* size 16, align 4 */
    __u32 saddr;              /*  0 네트워크 오더 */
    __u32 daddr;              /*  4 네트워크 오더 */
    __u16 sport;              /*  8 호스트 오더(기존 rule_matches와 동일 규칙) */
    __u16 dport;              /* 10 호스트 오더 */
    __u8  proto;              /* 12 */
    __u8  pad[3];             /* 13..15 반드시 0 (해시 키 전체 비교) */
};

struct sg_flow_state {        /* size 72, align 8 */
    __u64 first_seen_ns;      /*  0 bpf_ktime_get_ns (CLOCK_MONOTONIC) */
    __u64 last_seen_ns;       /*  8 */
    __u64 expire_ns;          /* 16 0=만료 없음. 절대 시각(ktime) */
    __u64 pkts;               /* 24 플로우 총 패킷(atomic add) */
    __u64 pkts_before_verdict;/* 32 DECIDED 전까지 통과한 패킷 = 누출량 */
    __u64 rl_window_ns;       /* 40 rate limit 고정 창 시작 */
    __u64 rl_count;           /* 48 창 안 패킷 수 */
    __u32 rl_pps;             /* 56 0=제한 없음 */
    __u32 redirect_ifindex;   /* 60 REDIRECT일 때 */
    __u32 sampled;            /* 64 보낸 사본 수(atomic add) */
    __u8  state;              /* 68 0=SAMPLING 1=DECIDED */
    __u8  verdict;            /* 69 4.1 코드 */
    __u8  pad[2];             /* 70..71 */
};

/* perf 레코드 앞머리. 뒤에 cap_len 바이트의 원시 프레임(이더넷부터)이 붙는다 */
struct sg_sample_meta {       /* size 24, align 8 */
    __u64 ts_ns;              /*  0 XDP 진입 시각 */
    __u32 ifindex;            /*  8 ctx->ingress_ifindex */
    __u32 rx_queue;           /* 12 ctx->rx_queue_index */
    __u32 pkt_len;            /* 16 data_end - data */
    __u16 cap_len;            /* 20 min(pkt_len, snaplen) */
    __u8  reason;             /* 22 1=INSPECT_RULE 2=FLOW_FIRST_N 3=RESAMPLE */
    __u8  flags;              /* 23 */
};

struct sg_inspect_cfg {       /* ARRAY[1], size 16 */
    __u32 first_n;            /*  0 플로우당 사본 수 N (0=사본 끄기) */
    __u32 snaplen;            /*  4 ≤ 0xFFFFF(CTXLEN 마스크), 권장 256~1514 */
    __u32 sample_every_k;     /*  8 (b) 모드 1:K, 1=전부 */
    __u8  pending_policy;     /* 12 0=pass 1=drop (SAMPLING 중 패킷) */
    __u8  mode;               /* 13 0=off 1=per-packet(b) 2=flow(d) */
    __u8  pad[2];
};
```

- **Rust 쪽:** `src/common/bpf_layout.rs`에 같은 offset 상수, encode/decode, offset·크기 테스트를 추가한다(macOS `cargo test -p swift-guard-common`으로 검증 가능).
- **카운터:** XDP 전체 카운터 `xdp_stats_map`(확정: `SG_STAT_RX=0` … `SG_STAT_ACTION_ERR=8`, `SG_STAT_MAX=9`, 1.1절)에 `inspect_matched`, `sample_sent`, `sample_lost`, `flow_hit`, `flow_miss`, `flow_drop`, `rl_drop` 슬롯을 `SG_STAT_*` 9번부터 이어 붙이고 `SG_STAT_MAX`를 올린다(PERCPU). 함께 바꿀 것: `bpf_layout.rs`의 `xdp_stat` 상수와 테스트, daemon의 맵 크기 검증, CLI `stats --format csv` 17열 계약(열을 추가할지, 추가하면 `tools/bench`·분석기·문서의 열 목록까지). (참고: 현재 불변식 RX = Σ결과는 결과 슬롯 1–8만 대상이다.)

### 4.3 TTL·만료 — `expire` 필드 활용

| 대상 | 만료 방식 | 근거 |
|---|---|---|
| 플로우 판정 캐시 | 값의 `expire_ns`(절대 ktime)를 **XDP가 직접** 비교하고, 지났으면 미스로 취급해 다시 샘플링한다. LRU가 메모리를 회수한다 | daemon 없이도 만료된다. `bpf_ktime_get_ns`는 부팅 후 경과 시간이고 suspend 시간을 제외한다 [확인: helper 문서]. 사용자 공간 `CLOCK_MONOTONIC`과 같은 기준이므로 daemon이 `now + ttl`을 계산해 쓴다 |
| LPM 룰(`filter_rule.expire`, 초, 상대값) | **daemon reaper**: `creation_time + expire`가 지나면 `MapManager`가 삭제한다(main 태스크 interval 분기, 예: 1초 주기) | 88B 레이아웃이 바뀌지 않는다. 정밀도는 reaper 주기다. daemon이 다운되면 만료되지 않는다(정상 종료 시에는 DetachGuard가 필터를 떼므로 문제가 작음). SIGKILL 뒤 남은 룰은 기동 시 정리하는 것이 선택 사항 |
| (대안) LPM 룰을 BPF가 만료 | 값에 절대 만료 시각 u64를 추가한다 → `filter_rule` 레이아웃 변경 | 2단계 이후 필요할 때만 검토한다 |

### 4.4 Rate limit 구현

**공통 원칙:** `bpf_spin_lock`은 **HASH/ARRAY 맵 값에서만** 쓸 수 있다 [확인: UAPI `bpf.h` 헬퍼 주석 "only allowed inside maps of types BPF_MAP_TYPE_HASH and BPF_MAP_TYPE_ARRAY"]. 따라서 LPM trie 값(`filter_rule`)과 LRU 값에서는 락 기반의 정확한 토큰 버킷을 쓸 수 없다. **lock-free 고정 창(fixed window) 카운터**를 기본으로 한다.

```
now = bpf_ktime_get_ns()
old = st->rl_window_ns
if (now - old >= 1e9) {                                   // 창 만료
    if (__sync_val_compare_and_swap(&st->rl_window_ns, old, now) == old)
        __sync_lock_test_and_set(&st->rl_count, 0);       // CAS에 이긴 CPU 하나만 리셋 (BPF_CMPXCHG/XCHG, v3·5.12+)
}
cnt = __sync_fetch_and_add(&st->rl_count, 1) + 1          // 반환값 사용 = BPF_FETCH (v3·5.12+)
if (cnt > st->rl_pps)  → XDP_DROP, rl_drop++              // 비원자 재읽기 없음
```

- **정확도:** 남는 오차는 (1) 고정 창 경계의 최대 2배 버스트(방식 고유)와 (2) 리셋과 증가 사이 경합으로 인한 소수 패킷이다. 최소 커널 5.15(Q3 결정)는 BPF_FETCH·BPF_CMPXCHG(5.12+)를 보장하고, Makefile이 `-mcpu=v3`로 빌드한다 [확인: `src/bpf/Makefile` `BPF_CPU ?= v3`]. v1 ISA에서는 fetch 계열 원자 연산의 반환값 사용과 CAS가 컴파일되지 않는다. 원자 연산 대상 필드(`rl_window_ns`, `rl_count`)는 8바이트 정렬을 유지해야 한다(아래 offset 88/96). PoC 오차는 측정해서 보고한다(설정 pps 대비 실측 통과 pps).
- **per-flow:** `sg_flow_state`의 `rl_*` 필드를 쓴다. verdict `RATE_LIMIT(pps)`가 설정한다.
- **per-rule(집계):** XDP는 LPM 조회 결과로 **매치된 prefix가 아니라 값만** 받는다. 그래서 별도 해시 맵의 키를 만들 수 없고, 상태를 **값 안에** 둬야 한다(기존 `stats`처럼). 이렇게 하려면 `filter_rule` 레이아웃이 바뀐다.

  ```c
  struct filter_rule {        /* 88B → 104B, align 8 */
      ... (offset 0..87 기존과 동일, rate_limit@20 의미: pps, 0=무제한) ...
      struct filter_stats stats;   /* 64 */
      __u64 rl_window_ns;          /* 88 신규, daemon은 0으로 씀 */
      __u64 rl_count;              /* 96 신규, daemon은 0으로 씀 */
  };
  ```

  Rust `FILTER_RULE_SIZE` 88 → 104, `off::RL_WINDOW=88`, `off::RL_COUNT=96`, `encode_filter_rule`에 0 채우기, 테스트 갱신이 필요하다. 룰을 다시 추가하면 상태가 초기화된다(stats와 같은 동작).
- **per-source:** 비교군으로 둔다. 출발지 `/32` 동적 룰에 `rate_limit`을 넣으면 per-rule 방식이 곧 per-source가 된다. 별도 맵이 필요 없다.
- **적용 순서:** 룰 매치 → `rate_limit > 0`이면 창 검사(초과 시 drop) → 그다음 액션(pass/count/inspect/redirect). DROP 룰의 rate_limit은 의미가 없으므로 API에서 거부한다.
- **API:** 미구현 옵션(`rate_limit`, `expire` ≠ 0)은 **현재 daemon이 거부한다**(01 계획 반영 완료, `server.rs::validate_add_rule`). 이 설계의 3단계에서 **거부를 해제**한다.

### 4.5 자가 적응 루프와 반응 시간 측정

```
t0 공격 패킷 XDP 진입  (sg_sample_meta.ts_ns)                ─┐
t1 daemon 사본 수신     (clock_gettime(CLOCK_MONOTONIC))       │ 같은 시계
t2 WASM 판정 완료                                              │ (DUT 단일 호스트)
t3 맵 update 반환       (flow: 스레드 직접 / LPM: BpfJob 응답) │
t4 해당 룰·플로우의 첫 drop (flow: last_seen_ns·drop 카운터, ─┘
                         LPM: rule.stats.last_matched 최초 변화)
누출 = sg_flow_state.pkts_before_verdict (또는 t0~t4 사이 공격 출발지 통과 수)
```

- daemon이 판정마다 `results/inspect/verdicts.csv`를 쓴다. 열 제안: `ts_xdp_ns, ts_rx_ns, ts_verdict_ns, ts_installed_ns, saddr, daddr, sport, dport, proto, module, verdict, param, flow_seq, cap_len, pkt_len`.
- **반응 시간** = t3 − t0이 대표 지표다. 구간별로 t1−t0(커널→사용자 전달), t2−t1(WASM), t3−t2(설치)로 쪼갠다. t4는 다음 공격 패킷이 도착하는 간격에 의존하므로 따로 보고한다.
- **TPR/FPR/F1:** 정답 레이블은 송신 측에서 붙인다. 공격과 정상 트래픽을 서로 다른 출발지 대역(예: 198.18.1.0/24 공격, 198.18.2.0/24 정상)에서 보내거나, pcap 재생 + 플로우 레이블 파일을 쓴다. `verdicts.csv`와 조인해 **플로우 단위**로 계산한다. 패킷 단위 차단율은 XDP 카운터(`flow_drop`, rule stats)와 송신량으로 계산한다.
- **만료 검증:** TTL을 T로 설치하고, `t_install + T` 이후 해당 출발지 패킷이 다시 통과하거나 재샘플되는지 확인한다.

---

## 5. daemon 스레드 모델과 경계 계약

### 5.1 제안 구조

```
main 태스크 (tokio, !Send BPF 객체 소유)
 ├─ serve(): accept 루프 + BpfJob 처리   ← BpfJob 채널 생성을 main으로 끌어올림
 ├─ telemetry_loop
 ├─ expire_reaper (신규, interval)
 └─ 시그널
sg-inspect 스레드 (std::thread, 1개로 시작)
 ├─ perf_buffer__new(samples_fd) / poll(100ms)       ← libbpf_sys 직접, fd만 받음
 ├─ WasmManager.inspect(...)  (Arc, Send+Sync)
 ├─ bpf_map_update_elem(flow_verdict_fd, …)          ← 플로우 캐시 직접
 ├─ bpf_tx.blocking_send(BpfJob{AddRule…})           ← LPM 동적 룰
 └─ verdicts.csv writer
(a)를 고를 경우: 큐별 xsk 스레드 ×Q, 스레드별 WASM 인스턴스 필요
```

### 5.2 경계 계약 변경 요약

| 계약 | (b) 1단계 | (d) 2단계 | rate limit 3단계 |
|---|---|---|---|
| `swift_guard.h` 구조체 | `sg_sample_meta`, `sg_inspect_cfg` 추가 | `sg_flow_key`, `sg_flow_state` 추가 | `filter_rule` 88→104 |
| 액션 상수 | `ACTION_INSPECT` (5, `VALID_ACTIONS` 확장) | — | — |
| BPF 맵 | `samples`(PERF_EVENT_ARRAY), `inspect_cfg` | `flow_verdict`(LRU_HASH) | — |
| `bpf_layout.rs` | meta 디코드, cfg 인코드 | flow key/state 인코드·디코드 | 크기·offset 갱신 |
| API (`common/api.rs` ↔ `cli/src/api.rs`) | `InspectConfig{mode, first_n, snaplen, …}`, `InspectStats` | `ListFlows{limit}`(선택) | `rate_limit`/`expire` 거부 해제 |
| WASM ABI | v1 그대로 (≠0 → drop) | v2 + `abi_version` | v2 `RATE_LIMIT` |
| CLI | `inspect config/stats`, `add-rule --action inspect` | `flows` | — |

### 5.3 수명·종료 순서

맵 fd는 `MapManager` 안의 `Object`가 drop될 때 닫힌다. 그러므로 **`sg-inspect` 스레드를 `MapManager`보다 먼저 정지·join해야 한다**. stop 플래그나 poll 타임아웃이 끝나는 것을 확인하는 방식이다. 이렇게 하지 않으면 닫힌 fd 번호가 재사용되어 엉뚱한 fd에 쓰는 버그가 날 수 있다. 대안은 스레드에 넘기기 전에 `dup()`해서 스레드가 자기 fd를 소유하게 하는 것이다(권장).

---

## 6. 비교 표

등급: ◎ 우수, ○ 양호, △ 문제 있음, × 부적합. 각 칸 아래 괄호는 근거.

| 기준 | (a) AF_XDP | (b) perf/ringbuf 사본 | (c) veth/tap | (d) 플로우 하이브리드 | (e) NFQUEUE |
|---|---|---|---|---|---|
| R1 비대상 처리량 | ○ (XSKMAP 분기 하나) | ◎ (INSPECT 매치 때만 비용) | ○ | ◎ | ○ (XDP는 PASS, netfilter 규칙 평가 비용) |
| R2 대상 처리량 | △ (WASM이 상한, 큐 수에 비례) | ○ (원본은 PASS 경로, 사본은 샘플링에 따라) | × (skb+복사) | ◎ (DECIDED 이후 XDP 속도) | × (패킷마다 사용자 공간) |
| R3 추가 지연 | △ (WASM 시간 + 재주입) | ◎ (원본 지연 없음) | × | ◎ (SAMPLING 중에도 대기 정책 pass면 없음) | × |
| R4 판정 방식 | 인라인 동기 | 비동기 사후 | 인라인/미러 | 비동기 + 플로우 캐시 | 인라인 동기 |
| R5 커버리지 | ◎ 전체(용량 범위 안) | ○ 1:K 또는 전체(저속) | ○ | ○ 플로우 첫 N + 재샘플 | ◎ 전체 |
| R6 복잡도 | × (UMEM, 큐, 재주입, libxdp) | ◎ (BPF 약 50줄, 스레드 1개) | ○ | ○ ((b) + LRU 맵, 경합 처리) | ○ (iptables 설정 + nfq) |
| R7 커널/NIC | △ (ZC 드라이버, 큐 스티어링) | ◎ (perf: 5.15 OK, generic도 가능) | ○ | ◎ | ◎ |
| R8 verifier | ◎ (단순) | ○ (perf는 쉬움, ringbuf 가변 복사는 까다로움) | ◎ | ○ | — |
| R9 Rust 생태계 | △ (xsk-rs 0.11 + libxdp-sys, libbpf 중복 [확인 필요]) | ◎ (libbpf-sys 1.5 바인딩만으로) | ◎ | ◎ | ○ (nfq 0.2.5, 2022년 이후 갱신 없음) |
| R10 실험 적합성 | ○ (인라인 WASM 오버헤드를 정의대로 측정. 반응 시간 개념은 약함) | ○ (2.3·3.1 측정 가능, 누출 정의 필요) | △ (XDP 주장과 불일치) | ◎ (2.3·3.1·반응 시간·누출·rate limit 모두) | ○ (기준선용) |
| R11 장애 | △ (다운 시 open [확인 필요], 멈춤 시 closed) | ◎ fail-open | × (인라인이면 블랙홀) | ◎ 정책 선택 가능 | △ (`--queue-bypass` 없으면 closed) |

---

## 7. 추천안과 단계별 구현 계획

### 추천
**(d) 플로우 하이브리드를 목표 구조로 하고, 운반 계층은 (b) perf buffer를 쓴다.** 비동기 판정에 따른 누출은 `pkts_before_verdict`와 반응 시간으로 정량화해 논문 기여(XDP 속도를 유지하면서 WASM 확장성 확보, 자가 적응 반응 시간)로 내세운다. 인라인 동기 검사 비교가 꼭 필요하면 (e) NFQUEUE를 기준선으로, (a) AF_XDP를 선택적 4단계로 둔다.

### Phase 0 — 선행 (01 계획, 이 문서 범위 밖) — **완료** (`bb5179f`)
- L4 IHL 파싱 수정, 미구현 옵션 거부, XDP 전체 카운터.
- 검증: 01 계획의 Tier 2 절차(`tools/test/e2e_check.sh` 9·10·11·13단계).

### Phase 1 — 최소 실험 가능 버전: (b) 패킷 단위 사본 + 출발지 자동 차단
- **산출물**
  - 운반: perf buffer(결정, 8장 Q3). API는 Unix 소켓(`/run/swift-guard/api.sock`, 2026-10-16 변경)을 그대로 쓴다. 새 요청 변형도 같은 접근 제어를 받는다. 새 변경 요청 변형(`InspectConfig` 등)은 daemon의 감사 로그(`API <Variant> from <peer>`, info) 대상 목록에 추가한다.
  - BPF: `ACTION_INSPECT`, `samples` perf 맵, `inspect_cfg`(mode=1, `sample_every_k`, snaplen), 카운터 `inspect_matched/sample_sent/sample_lost`.
  - daemon: `sg-inspect` 스레드(fd dup, `perf_buffer__new`), `WasmManager::inspect_packet` 연결(v1 ABI), 차단 시 출발지 `/32` drop 룰을 `BpfJob`으로 설치(label `auto-<module>-<ip>`, 같은 prefix에 기존 룰이 있으면 건너뜀), `expire` reaper, `verdicts.csv`.
  - API/CLI: `add-rule --action inspect`, `inspect config`, `inspect stats`. `expire`는 auto 룰에만 허용(사용자 API 해제는 3단계).
  - 도구: 공격/정상 트래픽 송신 스크립트(출발지 대역으로 레이블링), `verdicts.csv` → TPR/FPR/F1·반응 시간을 계산하는 분석기 확장.
- **검증**
  - macOS: `cargo test -p swift-guard-common`(레이아웃).
  - Docker: `linux_check.sh bpf` / `e2e`(verifier, 사본 수신, 자동 룰 설치·만료).
  - veth 랩: `http_inspector`로 SQLi 페이로드를 보냈을 때 `auto-*` 룰이 생기고 이후 패킷이 drop되는지, TTL 이후 해제되는지.
- **대략 작업량:** BPF 약 80줄, Rust 약 600~800줄(테스트 포함), 도구 약 300줄. **1~2주(1인)**. 추정이며 근거는 현재 파일 규모 비교뿐이다.
- **측정 가능해지는 poc-plan 시나리오**
  - 2.3 WASM 오버헤드: (i) INSPECT 범위 트래픽의 XDP pps를 `mode=0` 대비 `mode=1`, `k=1/10/100`에서 비교, (ii) WASM 검사 용량 `1/t_wasm`, (iii) `sample_lost` 곡선.
  - 3.1 TPR/FPR/F1: 샘플 단위·출발지 단위로 정의.
  - 3.2 반응 시간 t3−t0, 차단율.
  - 비교 기준선: `mode=0`의 vanilla XDP.

### Phase 2 — (d) 플로우 판정 캐시 + ABI v2
- **산출물:** `flow_verdict` LRU 맵, `mode=2`, first-N·대기 정책·재샘플, 스레드가 플로우 캐시에 직접 쓰기, ABI v2(`abi_version`, verdict 코드, 메타 헤더), `http_inspector`를 v2로 옮기고 길이 규칙에 `pkt_len` 사용, 다중 모듈 판정 합성 규칙, `ListFlows`(선택).
- **검증:** e2e에 "같은 5-tuple 2번째 플로우 패킷부터 캐시 drop", "expire_ns 이후 재샘플", "daemon SIGSTOP 중 fail-open/closed 정책" 추가. WASM 게스트 단위 테스트(`rustc --test`).
- **작업량:** BPF 약 120줄, Rust 약 500줄, WASM 약 150줄. **1~2주.**
- **측정:** 플로우 단위 TPR/FPR/F1, **누출 패킷 수 분포**(N과 대기 정책에 따라), 캐시 히트 시 처리량(2.2 방식), 플로우 생성률 대비 `sample_lost`(SYN flood 한계 실험), 장애 시 동작 실험.

### Phase 3 — Rate limit 판정 반영
- **산출물:** `filter_rule` 104B(`rl_*`), per-rule·per-source 고정 창, 플로우 `RATE_LIMIT` verdict, `rate_limit`·`expire` API 거부 해제(01 계획 되돌림), 카운터 `rl_drop`.
- **검증:** 레이아웃 테스트, e2e "pps 설정 대비 실측 통과율 ±오차", 오차 표 작성.
- **작업량:** 약 1주.
- **측정:** DDoS(UDP/SYN flood) 완화 실험(공격 pps 대비 통과 pps, 정상 트래픽 보존율), rate limit 정확도.

### Phase 4 (선택) — 인라인 비교군
- (e) NFQUEUE 기준선(약 3~5일) 또는 (a) AF_XDP 인라인 모드(약 3~4주. 큐 스티어링, libxdp, 재주입 포함). Q1의 결정에 따라 진행한다.
- **측정:** 인라인 WASM 오버헤드(정의상 "기본 XDP 대비 10–15%" 가설을 직접 검증할 수 있는 유일한 구성), P50/P99 지연(별도 지연 측정 도구 필요, poc-plan 6장).

---

## 8. 결정이 필요한 질문 (교수·팀)

1. **Q1 (최우선) 논문의 "WASM 오버헤드 10–15%" 가설을 무엇으로 정의할 것인가.** 비동기 구조에서는 원본 경로의 처리량 저하가 거의 없을 것으로 예상된다. 그러면 오버헤드는 "검사 용량"과 "누출·반응 시간"으로 옮겨 간다. 인라인 동기 오버헤드가 꼭 필요하면 Phase 4(NFQUEUE 또는 AF_XDP)가 필수가 된다.
2. **Q2 판정 전 대기 정책의 기본값:** pass(fail-open, 누출 있음)인가, drop(fail-closed, TCP 핸드셰이크 지연이나 실패 위험)인가. 그리고 N(플로우당 사본 수)과 snaplen 기본값.
3. **Q3 목표 커널의 최소 버전 — 결정됨 (2026-10-16): 최소 5.15.** 근거: Ubuntu 22.04 GA 커널, 5.12+ BPF_CMPXCHG/BPF_FETCH, ringbuf 5.8+. 5.18은 22.04 GA를 제외하고 `bpf_xdp_load_bytes` 도입 버전이 미확인 **[확인 필요]**이라 채택하지 않았다. 결과: Phase 1은 perf buffer 유지(3(b)), Phase 3은 fetch-add 반환값·cmpxchg 사용(4.4), BPF 빌드는 `-mcpu=v3`. (이전 선택지: 5.10 유지 — perf buffer, cmpxchg 없음 / 5.18+ — ringbuf + `bpf_xdp_load_bytes`.)
4. **Q4 자동 룰의 범위:** 플로우만 차단할지, 출발지 `/32`까지 차단할지. 같은 prefix에 운영자 룰이 있을 때 우선순위(LPM은 prefix당 룰 1개).
5. **Q5 탐지율 정의:** 플로우 단위인지 패킷 단위인지. 샘플링 비율을 보고하는 방식.
6. **Q6 여러 WASM 모듈의 판정 합성:** 가장 강한 판정(drop > rate_limit > redirect > alert > pass)인가, 첫 번째 비PASS인가.
7. **Q7 상태형 탐지(포트 스캔, 저속 DDoS):** WASM 안에서 할지(인스턴스 상태 공유 문제), daemon 집계로 할지.
8. **Q8 wasmtime 12 → 최신 업그레이드:** 측정 전에 할지 여부(결과 재현성과 보안 패치 사이의 선택).

## 9. 위험과 완화

| 위험 | 영향 | 완화 |
|---|---|---|
| 비동기 판정 누출 때문에 "차단"을 주장하기 약해짐 | 리뷰어 지적 | 누출을 1급 지표로 보고하고, 대기 정책 drop 실험과 Phase 4 인라인 비교군 |
| 사본 포화(플로우 생성률 공격) | 탐지 공백 | `sample_lost` 카운터, 1:K 샘플링, rate limit과 출발지 룰로 계층 방어, 한계를 실험으로 제시 |
| `WasmManager` 단일 Mutex 직렬화 | 검사 용량 상한 | Phase 1은 스레드 1개로 측정. 필요하면 스레드별 `Store`/`Instance`(Engine·Module 공유) |
| `http_inspector` 패턴(`;`, `&`, `--`, 길이 4096 초과)의 높은 오탐 가능성 | FPR이 나쁘게 나옴 | 평가용 모듈 규칙을 정비(wasm-module-dev 작업)하고 snaplen 잘림을 `pkt_len`으로 보정 |
| fd 수명과 종료 순서 | 닫힌 fd에 쓰기 | 스레드에 `dup()` fd, `MapManager` drop 전에 join |
| 동적 룰과 운영자 룰 충돌(prefix당 1개) | 운영자 룰 덮어쓰기 | auto 룰은 같은 prefix가 이미 있으면 건너뛰고 로그. label 접두사 `auto-` |
| 고정 창 rate limit 오차 | 정확도 논란 | 5.15 확정 → fetch-add 반환값·CAS 리셋 사용(Phase 3). 고정 창 경계 오차는 측정·보고 |
| AF_XDP 선택 시 libxdp/libbpf 중복 링크 | 빌드·런타임 충돌 | Phase 4로 미루고, 별도 바이너리(feature flag)로 격리 |
| 01 계획과의 순서 의존(옵션 거부 → 해제) | API 혼선 | 3단계에서 거부 해제를 명시적 작업으로 두고 변경 이력 기록 |

## 10. 참고 자료

- Linux kernel, *AF_XDP*: https://docs.kernel.org/networking/af_xdp.html (큐 바인딩, copy/zero-copy, need_wakeup, shared UMEM 근거)
- Linux kernel, *BPF ring buffer*: https://docs.kernel.org/bpf/ringbuf.html (reserve 상수 크기, 가득 참 시 실패, 다중 생산자 순서)
- bpf-helpers(7): https://man7.org/linux/man-pages/man7/bpf-helpers.7.html (`bpf_redirect_map` 폴백 하위 2비트, `bpf_ktime_get_ns`)
- libbpf UAPI `include/uapi/linux/bpf.h`(libbpf-sys 1.5.0 번들본): `bpf_perf_event_output`의 XDP 페이로드 전달, `BPF_F_CTXLEN_MASK`, `bpf_spin_lock` 제약, `bpf_xdp_load_bytes`, `bpf_ringbuf_*` 주석
- libbpf: https://github.com/libbpf/libbpf , libbpf-rs: https://github.com/libbpf/libbpf-rs (0.19.1 `ringbuf.rs`, `map.rs` 로컬 소스로 API 확인)
- xsk-rs: https://github.com/DouglasGray/xsk-rs , libxdp-sys: https://github.com/chenhengqi/libxdp-sys , xdp-tools(libxdp): https://github.com/xdp-project/xdp-tools
- xdp-tutorial(AF_XDP·perf 샘플 예제): https://github.com/xdp-project/xdp-tutorial
- T. Høiland-Jørgensen et al., "The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel," ACM CoNEXT 2018 (XDP 설계 배경. 수치 인용 시 원문 확인 필요)
- wasmtime epoch interruption: https://docs.wasmtime.dev/ (현재 사용 12.0.2)
- 레지스트리 조회(2026-10-14): https://crates.io/crates/xsk-rs , https://crates.io/crates/afxdp , https://crates.io/crates/libxdp-sys , https://crates.io/crates/nfq , https://crates.io/crates/libbpf-rs

## 변경 이력
- 2026-10-14 초안 (HEAD 42d4eea 기준).
- 2026-10-16 Q3 결정(최소 커널 5.15), 3(b)/4.4/R7/9장 정리, Phase 1 운반 계층 perf buffer 확정, Phase 1에 API Unix 소켓·접근 제어 한 줄 (HEAD fc42b65 기준).
- 2026-10-16 사실 서술만 갱신(HEAD 5d98195 기준): 1장 현재 구조(IHL 파서·조각 정책, `xdp_stats_map`, `-mcpu=v3`·5.15, Unix 소켓 API·감사 로그·자원 상한, 미구현 옵션 거부, WASM 제한 설정), 4.2 카운터 슬롯 확정, `ACTION_INSPECT`=5, Phase 0 완료 표시. 설계 판단·비교는 바꾸지 않음.
