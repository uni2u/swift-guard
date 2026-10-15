---
name: rust-control-plane
description: Swift-Guard Rust 사용자 공간(src/daemon, src/cli, src/common) 구현 가이드. xdp-filter CLI 명령/옵션 추가, ApiRequest/ApiResponse 변경, daemon API 서버 처리, BPF 맵 바이트 직렬화(maps.rs), 텔레메트리, YAML 설정, libbpf-rs 사용, macOS 빌드 제약 대응을 다룬다. Rust 파일을 수정하거나 CLI↔daemon 통신·맵 직렬화를 다룰 때 반드시 사용할 것. BPF C 코드 변경은 xdp-bpf-dev, WASM 게스트 모듈은 wasm-module-dev를 사용.
---

# Rust 컨트롤 플레인 구현 가이드 (Swift-Guard)

## 구조 (수정 전 실제 파일로 재확인)
```
xdp-filter (cli/src/main.rs, clap derive)
   └─ cli/src/api.rs: ApiClient — Unix 소켓(기본 /run/swift-guard/api.sock) | tcp:<루프백> 옵트인, [u32 BE 길이][JSON] 프레이밍
        ⇅ serde_json, externally-tagged enum
daemon/src/server.rs: handle_connection → process_request(match ApiRequest)
   ├─ maps.rs: MapManager — FilterRule → 수동 바이트 직렬화 → libbpf-rs Map::update
   ├─ bpf.rs: XdpFilterSkel(ObjectBuilder), attach/detach는 `ip link ... xdp obj` 셸 호출
   ├─ telemetry.rs, config.rs(serde_yaml), wasm.rs(wasmtime 12)
common/: api.rs(요청/응답 타입), types.rs(XdpMode/ActionType 등), utils.rs(IP/포트 파싱)
```
- 루트 `Cargo.toml`도 `[[bin]]`으로 같은 main.rs를 가리킨다(워크스페이스 멤버와 이중 빌드). 빌드 대상은 `-p <crate>`로 명시한다.
- daemon은 `swift_guard = { package = "swift-guard-common" }`로 common을 가져온다. CLI는 **common을 의존하면서도 api.rs에 타입을 복제**해 쓴다 → drift의 주원인.

## API 전송·접근 제어
- 주소 문법·기본값의 단일 원천은 `src/common/endpoint.rs`(`DEFAULT_API_ENDPOINT`, `ApiEndpoint` 파서 — 루프백 검사 포함). daemon·CLI·문서·스크립트는 이 문법만 쓴다.
- daemon 소켓 규칙: bind 전 umask 0o177 → chown root:swift-guard → chmod 0660(그룹 없거나 chown 실패 시 0600 root 전용으로 열화+경고), stale 소켓은 connect로 판별 후 삭제, 소켓이 아닌 파일은 지우지 않고 기동 실패, 종료 시 dev/ino 일치하는 자기 소켓만 삭제, 소켓 확보는 BPF 로드보다 먼저. 변경 요청은 SO_PEERCRED로 감사 로그(info).

## API 변경 규칙
serde의 기본 enum 표현(externally tagged)이라 **변형 이름·필드 이름·필드 타입이 곧 와이어 프로토콜**이다.
1. `src/common/api.rs`를 먼저 수정한다(원천).
2. CLI 복제본(`src/cli/src/api.rs`)을 같은 내용으로 맞추거나, 계획이 허용하면 `use swift_guard_common::api::*`로 교체해 복제를 없앤다. 복제를 없앨 때 CLI 전용 `Display` impl은 newtype이나 헬퍼 함수로 옮긴다(orphan rule).
3. `server.rs::process_request`의 match에 새 변형을 처리한다. 빠지면 컴파일 에러가 나므로 daemon 빌드로 확인된다 — 단, macOS에선 daemon 빌드가 안 되므로 `linux_check.sh cargo` 또는 수동 확인.
4. 변경 후 `python3 .claude/skills/sg-boundary-qa/scripts/api_drift.py src/common/api.rs src/cli/src/api.rs`로 drift 0을 확인한다.

## BPF 맵 직렬화 규칙
`create_filter_rule`/`create_prefix_key`/`create_if_redirect`는 C 구조체를 손으로 바이트화한다. 원칙:
- **C의 offset/size가 기준**이다. `struct_layout.py`로 측정한 offset에 맞춰 패딩 바이트를 명시적으로 넣고, 최종 길이가 `sizeof`와 같은지 `debug_assert_eq!` 또는 테스트로 고정한다. (예: 현재 C `filter_rule`은 88바이트이며 tcp_flags 뒤 1바이트, label 뒤 4바이트 패딩이 있다.)
- 더 안전한 대안: `#[repr(C)]` 구조체 + `unsafe` 바이트 뷰(또는 `plain`/`bytemuck`) — 계획이 허용할 때 채택. 그 경우 `std::mem::size_of`/`offset_of!` 테스트로 C 레이아웃과 일치를 고정한다.
- 필드 엔디안: 맵 값의 정수는 호스트 엔디안(`to_ne_bytes`가 의미상 정확, x86/arm64에선 LE와 동일). **LPM key의 addr는 네트워크 오더 바이트**여야 한다 — `parse_ip_prefix`가 반환하는 u32의 의미(호스트 정수 vs 네트워크 오더)를 확인하고, key에는 `Ipv4Addr::octets()` 순서의 바이트가 들어가도록 한다.
- 맵에서 읽을 때(`list_rules`, `get_stats`)도 같은 offset을 쓴다. "끝에서 sizeof(RuleStats) 만큼" 같은 상대 계산은 Rust 구조체 크기와 C 크기가 다르면 깨진다.
- PERCPU 맵 조회는 CPU 수만큼 값이 이어져 나온다. 합산해야 전체 값이 된다(libbpf-rs `lookup_percpu`).
- 라이브러리 API는 `Cargo.lock` 버전 소스로 시그니처를 확인한다(macOS에서 daemon을 컴파일할 수 없으므로 컴파일러가 대신 잡아주지 않는다). 예: libbpf-rs 0.19의 `Map::update/delete`는 `&mut self`, wasmtime `get_typed_func(&mut store, ..)`는 `store`를 빌려서 써야 한다(move 금지).

## 빌드/테스트
| 대상 | macOS | Linux(Docker) |
|------|-------|---------------|
| common, cli | `cargo check -p swift-guard-common -p swift-guard-cli`, `cargo test -p swift-guard-common` | 포함 |
| daemon | **불가** (libbpf-sys 빌드 실패) | `.claude/skills/sg-boundary-qa/scripts/linux_check.sh cargo` |
| 통합 테스트 | 불가 | `tests/integration`은 `#[ignore]`+root 필요 → 사용자 장비 |

- 빠른 일괄 검증: `.claude/skills/sg-boundary-qa/scripts/mac_check.sh`
- 새 로직에는 단위 테스트를 붙인다. 특히 직렬화 함수는 "바이트 길이 == C sizeof"와 "필드 offset" 테스트를 두면 BPF 없이도 macOS에서 회귀를 막을 수 있다 — 단 daemon 크레이트 안이면 macOS에서 못 돌리므로, 순수 직렬화 로직은 common으로 옮기는 것을 고려한다(계획이 허용 시).

## 코드 스타일
- 주석은 기존처럼 한국어, 에러는 `anyhow::Context`로 맥락을 붙인다.
- 기존 파일에 주석 처리된 옛 코드가 많다. 새로 추가하지 말고, 수정 대상 함수 안의 죽은 주석은 정리해도 된다.
- `unwrap()`/`expect()`는 데몬 경로에서 피한다(데몬 크래시 = 필터링 중단).

## 보고서 형식 (`_workspace/02_rust_report.md`)
```markdown
# Rust Report
## 변경 파일
## 경계 계약 이행 (API 변형/필드, 맵 직렬화 offset표)
## 실행한 빌드/테스트 (명령 — 결과, 실패 출력 원문)
## 미검증 항목 (daemon 빌드 등) 과 사유
```
