---
name: sg-dev-workflow
description: Swift-Guard 기능 개발·버그 수정 오케스트레이터. 설계(sg-architect) → BPF/Rust/WASM 병렬 구현 → 경계면 QA(sg-qa) → 수정 루프를 조율한다. "기능 추가", "버그 고쳐줘", "CLI 명령 추가", "필터 규칙에 ~ 지원", "WASM 모듈 만들어줘", "맵/구조체 변경", "rate limit 구현", "dst IP 매칭", "통계 수정" 등 Swift-Guard 코드 변경 요청이면 반드시 사용할 것. 후속 요청 — "다시 실행", "재실행", "QA만 다시", "Rust 쪽만 다시", "이전 결과 기반으로 수정", "보완", "업데이트", "결과 개선" — 에도 사용. 코드 한 줄 설명 같은 단순 질문이나, 변경 없이 정합성만 검사하는 요청(sg-boundary-qa 직접 사용)에는 쓰지 않는다.
---

# Swift-Guard 개발 오케스트레이터

**실행 모드:** 서브 에이전트 (파이프라인 + 팬아웃 + 생성-검증)
이 환경에는 TeamCreate/TaskCreate가 없으므로 `Agent` 도구로 서브 에이전트를 호출하고, `_workspace/` 파일로 산출물을 주고받는다. 구현 에이전트끼리 직접 대화하지 않는 대신 **Phase 1에서 경계 계약을 먼저 고정**해 병렬 구현의 어긋남을 막는다.

## 팀 구성
| 에이전트 | 정의 | 스킬 | 담당 |
|---------|------|------|------|
| sg-architect | `.claude/agents/sg-architect.md` | (이 문서의 계획 형식) | 작업 분해, 경계 계약 |
| sg-bpf-engineer | `.claude/agents/sg-bpf-engineer.md` | xdp-bpf-dev | src/bpf, include |
| sg-rust-engineer | `.claude/agents/sg-rust-engineer.md` | rust-control-plane | src/daemon, src/cli, src/common |
| sg-wasm-engineer | `.claude/agents/sg-wasm-engineer.md` | wasm-module-dev | wasm/ (+계획 배정 시 daemon/wasm.rs) |
| sg-qa | `.claude/agents/sg-qa.md` | sg-boundary-qa | 교차 검증, 빌드 |

## 공유 작업 트리 규칙
병렬 트랙은 같은 작업 트리를 공유한다. 모든 에이전트 prompt에 다음을 지킨다고 명시한다: **`git stash`, `git checkout -- <file>`, `git reset`, `git clean` 등 작업 트리를 바꾸는 git 명령 금지**(다른 트랙의 미커밋 변경이 유실된다). 원본 비교는 `git diff`/`git show HEAD:<path>`로만 한다. 커밋은 오케스트레이터만 한다.

## 에이전트 호출 방법
모든 호출은 `Agent` 도구로 `subagent_type: "general-purpose"`, `model: "opus"`를 지정한다. prompt는 다음 틀을 따른다:
```
너는 <에이전트명>이다. 먼저 /Volumes/SSD/work/swift-guard/.claude/agents/<에이전트명>.md 를 읽고 그 역할·원칙을 따르라.
그다음 .claude/skills/<스킬>/SKILL.md 를 읽어라.
작업 디렉토리: /Volumes/SSD/work/swift-guard
입력: <파일 목록>
이번 작업: <요청 요약 / 재호출 시 수정할 QA 항목>
출력: <보고서 경로>에 작성하고, 최종 응답으로 보고서 요약(10줄 이내)을 반환하라.
```

## Phase 0: 컨텍스트 확인
1. `_workspace/` 존재 여부와 내용을 확인한다. 초기 실행이면 `mkdir -p _workspace`로 만든다(에이전트 prompt에는 저장소 루트 기준 전체 경로를 쓴다).
2. 실행 모드 결정:
   - `_workspace/` 없음 → **초기 실행** (Phase 1부터)
   - 있음 + 사용자가 같은 작업의 일부 수정/재검증 요청 → **부분 재실행**: 해당 에이전트만 재호출 (예: "QA만 다시" → Phase 3, "Rust 쪽 고쳐" → Phase 2의 rust만 + Phase 3)
   - 있음 + 새 작업 요청 → `_workspace/`를 `_workspace_prev/`로 이동(기존 `_workspace_prev/`는 삭제 전 사용자 확인) 후 초기 실행
3. git 상태를 확인한다. 작업 트리가 더럽고 이번 작업과 무관한 변경이 있으면 사용자에게 알린다(덮어쓰지 않도록).
4. `_workspace/`는 `.gitignore`에 등록되어 있다(없으면 추가를 제안).
5. `_workspace/03_qa_report.md`에 Round 0(baseline)이 있으면 pre-existing 문제 목록으로 활용한다 — 이번 작업과 같은 코드 영역의 기존 BLOCKER는 계획 단계에서 함께 고칠지 사용자에게 묻는다.

## Phase 1: 설계
**실행 모드:** 서브 에이전트 1개 (sg-architect)
- 입력: 사용자 요청 원문
- 출력: `_workspace/01_architect_plan.md`
- 완료 후 오케스트레이터가 계획을 읽고, **경계 계약이 바뀌거나 변경 파일이 5개 이상이면 사용자에게 계획 요약을 보여주고 확인받는다**(잘못된 계약으로 3개 에이전트가 병렬 작업하면 되돌리기 비싸다). 작은 변경은 바로 진행.

### 계획 문서 형식
```markdown
# Plan: <제목>
## 요청 해석 (한 문단) / 범위 밖
## 영향 계층
| 계층 | 담당 | 변경 여부 | 파일 |
## 경계 계약
### BPF 맵 레이아웃 (변경 시: C 정의 + 기대 offset/size 표)
### API (변경 시: ApiRequest/ApiResponse 변형·필드)
### WASM ABI (변경 시: export/import 표)
## 작업 목록 (에이전트별, 순서·의존성 포함)
## 검증 계획 (macOS / Docker / 사용자 Linux 장비)
## 열린 질문 / 선택 작업
## 변경 이력
```

## Phase 2: 구현
**실행 모드:** 서브 에이전트 병렬 (계획에서 "변경 있음"인 에이전트만)
- 의존 규칙: BPF 구조체 레이아웃이 바뀌면 **sg-bpf-engineer를 먼저** 실행하고 `02_bpf_report.md`의 실측 레이아웃을 sg-rust-engineer 입력에 넣는다. 그 외에는 해당 에이전트들을 한 메시지에서 동시에 호출한다(`run_in_background: true`).
- 담당 파일이 겹치지 않게 계획이 배정했는지 확인한다(특히 `src/daemon/src/wasm.rs`는 rust/wasm 중 한쪽만).
- 출력: `_workspace/02_{bpf,rust,wasm}_report.md`

## Phase 3: QA
**실행 모드:** 서브 에이전트 1개 (sg-qa)
- 입력: 계획, 이번 라운드의 02_* 보고서, `git diff`
- 출력: `_workspace/03_qa_report.md` (라운드 N은 같은 파일에 `## Round N` 섹션 추가)
- BPF·daemon 동작(맵, attach, 서버, 시그널)에 영향이 있는 변경이면 QA prompt에 `linux_check.sh e2e` 실행을 명시한다(Tier 2). 커밋 전 마지막 라운드에서는 항상 실행한다.

## Phase 4: 수정 루프
- QA 판정 FAIL → 발견 항목의 "담당" 에이전트만 재호출(QA 항목 번호와 수정 지시를 prompt에 포함) → Phase 3 재실행.
- 최대 **2회** 루프. 그래도 FAIL이면 멈추고 남은 항목을 사용자에게 보고한다 — 같은 문제가 반복되면 계획(계약) 자체가 틀렸을 가능성이 높으므로, sg-architect 재호출을 제안한다.
- 계약 오류로 판정된 항목(담당: sg-architect)은 계획 수정 → 영향받는 구현 에이전트 재호출 순서로 처리한다.

## Phase 5: 마무리
1. 사용자에게 보고: 변경 파일, QA 판정, 실행한 검증과 결과, **미검증 항목**(Linux 전용), 사용자 Linux 장비에서 돌릴 명령, pre-existing 문제 목록.
2. 커밋은 사용자가 요청할 때만 한다.
3. 피드백을 묻는다: "결과나 에이전트 구성에서 바꾸고 싶은 점이 있나요?" — 피드백은 해당 스킬/에이전트/이 문서에 반영하고 CLAUDE.md 변경 이력에 기록한다.

## 데이터 흐름
```
요청 → [architect] → 01_plan
                       ├→ [bpf] → 02_bpf ─┐ (레이아웃 변경 시 rust보다 먼저)
                       ├→ [rust] → 02_rust ┤
                       └→ [wasm] → 02_wasm ┘
                                   ↓
                 [qa] → 03_qa ──FAIL→ 담당 에이전트 재호출 (≤2회)
                          └PASS→ 사용자 보고
```

## 에러 핸들링
| 상황 | 처리 |
|------|------|
| 에이전트 호출 실패/빈 보고서 | 1회 재시도 → 재실패 시 해당 계층 없이 QA 진행, 보고서에 누락 명시 |
| 구현 에이전트가 계약 이탈 보고 | QA 전에 오케스트레이터가 판단: 타당하면 architect로 계획 갱신 후 영향 에이전트 재호출 |
| Docker 꺼짐 (linux_check exit 3) | 실패가 아니라 "미검증". 사용자에게 Docker 실행 또는 Linux 장비 검증을 안내 |
| wasm32 타깃 미설치 | 설치하지 않고 사용자에게 `rustup target add wasm32-unknown-unknown` 제안 |
| QA와 구현자 보고가 상충 | 삭제하지 말고 둘 다 사용자 보고에 병기, 코드로 사실 확인 |

## 테스트 시나리오
**정상 흐름 — "filter_rule에 dst_ip 매칭을 추가해줘"**
1. Phase 0: `_workspace/` 없음 → 초기 실행
2. architect: BPF(키 구조/매칭 로직), Rust(API는 이미 dst_ip 있음 → maps.rs 직렬화·키 생성), WASM 변경 없음. 레이아웃 변경 → 사용자 확인
3. bpf 먼저 → 실측 레이아웃 → rust 실행
4. qa: mac_check + 레이아웃 표 대조 → PASS(Linux 컴파일 미검증 명시)
5. 보고 + Linux 검증 명령 전달

**에러 흐름 — QA가 직렬화 길이 불일치 발견**
1. qa Round 1 FAIL: "#1 BLOCKER maps.rs create_filter_rule 83B vs C sizeof 88B, 담당 rust"
2. rust만 재호출(항목 #1 지시 포함) → qa Round 2 PASS
3. Round 2도 FAIL이면 루프 1회 더 → 그래도 FAIL이면 중단·보고, architect 재검토 제안

**부분 재실행 — "QA만 다시 돌려줘"**
- Phase 0에서 `_workspace/` 확인 → Phase 3만 실행, Round N+1 추가
