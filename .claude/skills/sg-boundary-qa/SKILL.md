---
name: sg-boundary-qa
description: Swift-Guard 경계면 교차 검증 체크리스트와 스크립트. BPF C 구조체 ↔ Rust 맵 직렬화 레이아웃, common ↔ cli API 타입 drift, daemon ↔ WASM ABI, CLI 명령 ↔ README/벤치 스크립트 일치를 검사하고 macOS/Docker 빌드 검증을 실행한다. 구현 후 QA, "정합성 검사", "레이아웃 확인", "API 불일치 확인", "빌드 검증" 요청 시 반드시 사용할 것. 새 코드 작성 자체에는 사용하지 않는다.
---

# 경계면 교차 검증 (Swift-Guard)

## 원칙
- 존재 확인이 아니라 **양쪽을 동시에 읽고 비교**한다. 한쪽 정의 → 다른 쪽 사용처를 grep으로 모두 찾는다.
- 스크립트가 잡는 것은 일부다. 스크립트 PASS 후에도 아래 체크리스트를 수동으로 확인한다.
- 실행하지 못한 검증은 "미검증"으로 남긴다. 추정으로 PASS 처리하지 않는다.
- **심각도와 출처는 별개 축이다.** 심각도(BLOCKER/MAJOR/MINOR)는 "이 상태로 Linux에서 실행하면 무엇이 깨지는가"로 매기고, 출처는 `new`(이번 diff) / `pre-existing`으로 따로 표기한다. 판정 FAIL은 `new`인 BLOCKER/MAJOR가 있을 때만이다. 출처는 `git diff`와 원본 비교로 판단한다(`git stash` 금지).
- **Baseline 모드(Round 0):** 계획·diff 없이 전체 감사를 요청받으면 판정은 `N/A (baseline)`, 모든 발견은 `pre-existing`. 심각도는 같은 기준으로 매긴다.
- 작업 시작 시 `mkdir -p _workspace`.

## 스크립트 (`.claude/skills/sg-boundary-qa/scripts/` — 저장소 루트 기준 경로)
| 스크립트 | 용도 | 종료 코드 |
|---------|------|----------|
| `mac_check.sh` | common/cli 빌드·테스트 + API drift + header↔bpf 레이아웃 + WASM 빌드 일괄 | 0 PASS / 1 FAIL |
| `struct_layout.py <file> <struct>...` | C 구조체 offset/size JSON (macOS에서 동작) | |
| `api_drift.py <a.rs> <b.rs>` | 두 파일의 동명 serde 타입 변형/필드 비교 | 0 일치 / 1 drift |
| `linux_check.sh [bpf\|cargo\|test\|all]` | Docker로 BPF 컴파일 + daemon 포함 cargo check/test | 0 PASS / 1 FAIL / 2 알 수 없는 모드(옵션은 별도 인자: `examples -v`) / 3 docker 없음(SKIP) |
| `bpf_unit_check.sh` | privileged Docker에서 Makefile 빌드 → verifier 로드 → `bpf_prog_test_run.py`로 PROG_TEST_RUN 케이스(IHL/조각/tiny fragment/src→dst 우선/결과 카운터 불변식 RX=Σ결과). daemon 없이 가장 빠른 BPF 회귀 검사. src/bpf·include 변경 시 실행 | 0 / 1 / 3 |
| `linux_check.sh bench` | privileged Docker에서 `tools/test/bench_flow_check.sh` — Tier 3 스크립트 흐름(daemon 기동→attach→lab 트래픽→`stats --format csv`→요약 CSV→분석기→정리). 수치는 의미 없음. `tools/bench`, `tools/analysis`, `xdp-filter stats` 변경 시 실행 | 0 / 1 / 3 |
| `systemd_check.sh` | (소켓 0660 root:swift-guard·비멤버 거부·멤버 허용·stop 시 소켓 삭제 포함) systemd를 init으로 띄운 Ubuntu 24.04 컨테이너에서 README 10장(설치→enable→override `-i`+`ExecStartPost`→stop 시 detach→재시작 시 룰 재적용→uninstall)을 실행. rules.sh·override는 **README 본문에서 추출**하므로 문서와 동작이 함께 검증된다. README 10장/service/Makefile 변경 시 실행 | 0 / 1 / 3 |
| `readme_check.sh [22.04 24.04]` | (그룹 생성·소켓 권한·비멤버 거부/멤버 허용 포함) 깨끗한 Ubuntu에서 일반 사용자로 README 4~6장·WASM·예시 회귀·제거를 그대로 실행(초급자 경로). README의 설치/사용 명령이나 Makefile을 바꾸면 실행. README와 `readme_sim_inner.sh`의 단계는 함께 갱신 | 0 / 1 / 3 |
| `linux_check.sh examples [-v]` | privileged Docker에서 `tools/test/examples.sh` — `docs/examples.md` 예시가 문서대로 동작하는지(CLI 출력·에러 문구 포함). CLI/룰 의미/에러 메시지를 바꾸면 실행하고, 출력이 바뀌면 문서도 갱신 | 0 / 1 / 3 |
| `linux_check.sh e2e [--with-ignored]` | privileged Docker에서 `tools/test/e2e_check.sh`(Tier 2: veth+generic XDP, verifier·attach·매치·통계·SIGTERM) | 0 PASS / 1 FAIL / 3 docker 없음 |

먼저 `mac_check.sh`를 실행하고, Docker가 켜져 있으면 `linux_check.sh all` → `linux_check.sh e2e` 순으로 실행한다. 검증 단계(Tier 1 빌드 / Tier 2 커널 E2E / Tier 3 성능) 정의는 `docs/linux-verification.md`.
- macOS에서는 daemon 크레이트와 **루트 패키지 `swift-guard`**(README/Makefile의 `cargo build --release` 대상, libbpf-rs 의존)를 컴파일할 수 없다 → 체크리스트 E로 보완하고 "미검증"으로 남긴다.
- `linux_check.sh all`은 Tier 1만 검증한다. Tier 2는 `linux_check.sh e2e`로 검증한다(x86_64 Docker Desktop 커널 7.x에서 BPF 로드·generic XDP 동작 확인됨. arm64 컨테이너나 bpf()를 막는 커널이면 e2e가 daemon 기동에서 FAIL — 그때는 "미검증"으로 보고하고 Linux VM 사용을 안내). driver 모드와 성능 **수치**(Tier 3)는 항상 "미검증"이다(스크립트 흐름은 `linux_check.sh bench`로 검증).
- 스크립트 출력이 PASS여도 스크립트 자체가 조용히 실패했을 수 있다. 의심스러우면 해당 단계를 단독 실행해 종료 코드를 확인한다.

## 체크리스트

### 0. 엔트리포인트 연결 (가장 먼저)
경계 양쪽이 일치해도 **실제로 연결되어 실행되지 않으면** 의미가 없다.
1. `src/daemon/src/main.rs`가 설정 로드 → BPF 오브젝트 로드 → MapManager → TelemetryCollector → ApiServer(listen) → WASM 매니저를 실제로 생성·실행하는가. CLI·daemon 기본 endpoint가 모두 `common::endpoint::DEFAULT_API_ENDPOINT`를 쓰는가, 문서·스크립트의 주소가 `unix:`/`tcp:<루프백>` 문법인가, 소켓 권한(0660 root:swift-guard)과 비권한 사용자 거부가 검증되는가.
2. `server.rs`의 각 요청 처리가 실제 동작(맵 갱신, attach 등)을 호출하는가, 아니면 아무것도 하지 않고 `Success`만 반환하는가.
3. CLI `main.rs`의 서브커맨드가 모두 ApiClient 호출로 이어지는가.
4. 테스트가 실제로 실행되는가: `cargo test -- --list`에 기대한 테스트가 나오는가(`tests/integration/`은 cargo가 자동 인식하지 않는다 — mac_check가 WARN으로 표시).

### A. BPF 맵 레이아웃 (C ↔ Rust)
1. `struct_layout.py include/swift_guard.h filter_rule prefix_key if_redirect filter_stats sg_counter` 결과와 `src/bpf/xdp_filter.c` 결과가 같은가 (mac_check가 자동 비교).
2. `src/daemon/src/maps.rs`의 `create_filter_rule`이 만드는 바이트를 필드별로 누적 계산해 C offset과 대조한다. 표로 적는다:
   `필드 | C offset/size | Rust 누적 offset/size | 일치`
   총 길이가 C `sizeof`와 다르면 BLOCKER (`Map::update`가 크기 불일치로 실패).
3. `create_prefix_key`, `create_if_redirect`도 동일하게 확인.
4. 읽기 경로(`list_rules`의 stats 파싱, `get_stats`)가 같은 offset을 쓰는가. PERCPU 맵 합산 여부.
5. LPM key addr 바이트 오더: BPF는 `iph->saddr`(네트워크 오더 바이트)로 조회한다. Rust의 `parse_ip_prefix` 반환값 → `to_le_bytes`/`to_be_bytes` 결과 바이트가 `Ipv4Addr::octets()` 순서인지 실제 값(예: 192.168.1.100)으로 손계산한다.
6. 액션/프로토콜/플래그 상수: `swift_guard.h`, `xdp_filter.c`, `common/types.rs`, `common/utils.rs`(이름↔숫자), CLI 파서가 같은 숫자를 쓰는가.

### B. API (CLI ↔ common ↔ daemon)
1. `api_drift.py src/common/api.rs src/cli/src/api.rs` — drift 있으면 그 변형을 CLI가 실제로 보내는지 확인. 보내는데 정의가 다르면 BLOCKER, CLI에 없는 변형이면 기능 누락(MAJOR).
2. `server.rs::process_request`가 모든 `ApiRequest` 변형을 처리하는가, 응답 변형을 CLI가 모두 매칭하는가(`_ =>`로 삼키는 경우 확인).
3. 프레이밍: 양쪽 모두 `u32` **빅엔디안** 길이 + JSON인가.
4. CLI 인자 → ApiRequest 필드 변환(포트 범위, 프로토콜 이름→숫자, 기본값)이 daemon의 해석과 같은가.

### C. WASM ABI (daemon 호스트 ↔ 게스트 모듈)
1. 호스트가 `get_typed_func`로 찾는 이름·시그니처 ↔ 게스트 `#[no_mangle] pub extern "C"` 목록.
2. 호스트 `linker.define` import ↔ 게스트 `extern "C"` 블록.
3. 반환값 의미(0 통과 / ≠0 차단)가 호스트 해석과 일치하는가.
4. 게스트 파서의 인덱싱이 모두 길이 검사 뒤에 있는가(패닉 = trap).
5. 할당/해제 균형(호스트가 deallocate를 부르는가).

### D. 문서·스크립트 ↔ CLI
1. README, `tools/bench/*.sh`, `docs/poc-plan.md`에 나오는 `xdp-filter` 서브커맨드/옵션이 `cli/src/main.rs`의 clap 정의에 존재하는가. 이번 변경으로 CLI가 바뀌었다면 문서 갱신 여부.
2. `config/swift-guard.yaml` 키 ↔ `daemon/src/config.rs` serde 구조체.
5. README의 daemon 통신 명령은 `sudo xdp-filter …`(`--version`/`--help` 제외), 최소 커널 표기는 5.15.
4. 벤치 CSV 계약: `xdp-filter stats --format csv` 헤더 ↔ `tools/bench/*` 파싱 ↔ 요약 CSV 헤더 ↔ `tools/analysis/analyze_performance.py`가 읽는 열 ↔ 문서(poc-plan, README 13장)에 적힌 열 이름을 대조한다.
3. README 설치 절차 재현: 빌드 의존성이나 README/Makefile이 바뀌었으면 `readme_check.sh`를 돌린다(깨끗한 Ubuntu + 일반 사용자 + README 명령 그대로). `linux_check.sh`는 자체 의존성을 설치하므로 README 누락을 잡지 못한다. 복사는 `git clone`이 아니라 작업 트리 기준으로 한다(clone은 커밋된 코드만 가져온다).

### E. 외부 라이브러리 API 계약 (daemon을 macOS에서 컴파일할 수 없으므로)
`Cargo.lock`에 고정된 버전의 소스(`~/.cargo/registry/src/*/<crate>-<ver>/`)를 열어 실제 시그니처와 대조한다.
1. libbpf-rs: `Map::update/delete/lookup`의 `&self`/`&mut self` 여부, PERCPU 맵은 `lookup`이 아니라 `lookup_percpu`가 필요한지, 값 크기 검증 동작.
2. wasmtime: `get_typed_func`/`call`이 `store`를 `&mut`로 빌리는지 소유권을 가져가는지(재사용 시 move 오류), `Linker::define` 시그니처.
3. 새로 쓰인 라이브러리 API는 모두 이 방식으로 확인하고, 확인 방법(실제 컴파일 vs 소스 대조)을 보고서에 적는다.

## 보고서 형식 (`_workspace/03_qa_report.md`)
```markdown
# QA Report — Round N
**판정:** PASS | FAIL | N/A (baseline)   (출처 new인 BLOCKER/MAJOR가 있으면 FAIL)

## 실행한 검증
| 명령 | 결과 | 비고 |

## 발견 (이번 변경)
| # | 심각도 | 출처 | 경계 | 파일:라인 | 문제 | 근거(컴파일/스크립트/소스대조/손계산) | 담당 | 수정 지시 |

## Pre-existing 문제 (참고, 차단 아님)

## 미검증 항목과 사유

## 사용자 Linux 장비 검증 절차
(`docs/linux-verification.md`의 Tier 2 "추가 수동 점검" 중 이번 변경과 관련된 항목, Tier 3 필요 여부)
```
