---
name: wasm-module-dev
description: Swift-Guard WASM 패킷 검사 모듈 개발 가이드. wasm/modules/*.rs 신규 모듈 작성(SQLi/XSS/스캐너/DNS 등 탐지), 기존 http_inspector 탐지 로직 수정, wasm/build.sh 빌드, daemon wasmtime 호스트(src/daemon/src/wasm.rs)와의 ABI(allocate/inspect_packet/init/env.log) 계약을 다룬다. WASM 모듈을 만들거나 고치거나, 호스트-게스트 인터페이스를 바꿀 때 반드시 사용할 것. daemon의 일반 Rust 로직은 rust-control-plane을 사용.
---

# WASM 검사 모듈 가이드 (Swift-Guard)

## 현재 ABI 계약 (원천: src/daemon/src/wasm.rs — 변경 전 재확인)
| 방향 | 이름 | 시그니처 | 의미 |
|------|------|---------|------|
| guest export | `memory` | Memory | 필수. 없으면 로드 실패 |
| guest export | `allocate` | `(size: i32) -> i32` | 선택. 없으면 호스트가 고정 오프셋 1024에 씀 |
| guest export | `inspect_packet` | `(ptr: i32, len: i32) -> i32` | 필수. **0 = 통과, 0이 아니면 차단** |
| guest export | `init` | `() -> ()` | 선택. 로드 직후 1회 |
| guest export | `deallocate` | `(ptr: i32, cap: i32)` | 게스트에 있으나 **호스트가 호출하지 않음** |
| host import | `env.log` | `(ptr: i32, len: i32) -> i32` | UTF-8 메시지 로깅, 0 = 성공 |

입력 바이트는 **이더넷 헤더부터 시작하는 원시 프레임**이다.

### 알려진 ABI 문제 (관련 작업일 때 계획에 따라 처리)
- 호스트가 패킷마다 `allocate`만 하고 `deallocate`를 안 부름 → 게스트 메모리 누수. 해결 방향: 호스트가 검사 후 `deallocate` 호출, 또는 게스트가 고정 크기 정적 버퍼를 재사용.
- 실행 타임아웃(config `execution_timeout_ms`)·메모리 제한이 실제로 걸려 있는지 확인 필요(wasmtime fuel/epoch interruption, `StoreLimits`).

ABI를 바꾸면 **호스트와 모든 게스트 모듈을 동시에** 바꿔야 한다. 계획 문서에 바뀐 표를 남긴다.

## 게스트 작성 원칙
패킷은 공격자가 만든 입력이다. 게스트 패닉 = wasmtime trap = 호스트 에러 경로이므로, 탐지 실패보다 나쁘다.
- 모든 인덱싱 전에 길이 검사. `data[i]` 대신 `data.get(i)?` 패턴의 파서 함수(`Option` 반환)를 쓴다.
- 가변 오프셋(IHL×4, TCP doff×4)은 최소값(20) 검증 후 사용 — ihl<5면 거짓 패킷이다.
- 오프셋 계산은 `checked_add`로 오버플로를 막는다.
- `#![no_std]`는 필수 아님(현재 std 사용). 단 `std::fs`/`std::net` 등 WASI가 필요한 API는 `wasm32-unknown-unknown`에서 동작하지 않는다.
- 로그는 남발하지 않는다(패킷마다 호스트 호출 = 오버헤드, 논문 성능 측정에 영향).
- 탐지 패턴은 대소문자·URL 인코딩 변형을 고려하되, 오탐(FPR)이 평가 지표이므로 규칙마다 근거를 주석으로 단다.

## 모듈 구조 템플릿
```rust
//! <모듈명> WASM 모듈 — <탐지 대상 한 줄>
extern "C" { fn log(ptr: *const u8, len: i32) -> i32; }

#[no_mangle] pub extern "C" fn allocate(size: i32) -> i32 { /* http_inspector와 동일 */ }
#[no_mangle] pub extern "C" fn deallocate(ptr: i32, capacity: i32) { /* 동일 */ }
#[no_mangle] pub extern "C" fn init() {}

#[no_mangle]
pub extern "C" fn inspect_packet(ptr: i32, len: i32) -> i32 {
    if ptr <= 0 || len <= 0 { return 0; }
    let data = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
    match inspect(data) { Some(true) => 1, _ => 0 }
}

fn inspect(data: &[u8]) -> Option<bool> { /* 순수 함수: 파싱 실패는 None → 통과 */ }

#[cfg(test)]
mod tests { /* inspect()를 호스트 타깃에서 단위 테스트 */ }
```
탐지 로직을 순수 함수 `inspect(&[u8])`로 분리하면 wasm 타깃 없이도 macOS 호스트에서 `rustc --test`로 테스트할 수 있다:
`rustc --edition 2021 --test wasm/modules/<m>.rs -o /tmp/<m>_test && /tmp/<m>_test`
(extern `log`가 링크 에러를 내면 테스트용으로 `#[cfg(not(test))]`를 extern 블록과 log 호출 래퍼에 건다.)

## 호스트 import 선언 (필수)
`extern "C" { fn log(..) }`처럼 import 모듈 없이 선언하면 wasm-ld가 같은 이름의 libm 심볼(`log(f64)`)로 링크해 **import가 사라지고** 호출 시 `unreachable` trap이 난다(실제 발생). 항상 다음 형태로 선언한다:
```rust
#[link(wasm_import_module = "env")]
extern "C" { #[link_name = "log"] fn host_log(ptr: *const u8, len: i32) -> i32; }
```
빌드 후 `.wasm`에 `env.log` import가 있는지 확인한다(`linux_check.sh examples`의 WASM 단계가 실제 로드로 검증).

## 빌드
- `cd wasm && ./build.sh` — `modules/*.rs` 각각을 임시 cdylib 크레이트로 빌드해 `modules/<name>.wasm` 생성.
  - 주의: 산출물을 저장소 안(`wasm/modules/*.wasm`)에 쓰고, 타깃 감지 grep 버그로 매번 `rustup target add`(네트워크)를 실행한다. 검증만 할 때는 `mac_check.sh`의 WASM 단계(임시 디렉토리에 `rustc --target wasm32-unknown-unknown`)를 쓴다.
- 필요: `rustup target add wasm32-unknown-unknown` (현재 미설치일 수 있음 — 설치는 사용자 결정, 보고서에 명시).
- export 확인: `wasm-objdump -x` 또는 `wasm-tools print`가 있으면 사용, 없으면 daemon 로드로 확인(Linux).

## 보고서 형식 (`_workspace/02_wasm_report.md`)
```markdown
# WASM Report
## 변경 파일
## ABI 표 (export/import, 계획 대비 일치/이탈)
## 탐지 규칙과 근거, 예상 오탐 사례
## 테스트 (명령 — 결과) / 빌드 (결과 또는 SKIP 사유)
```
