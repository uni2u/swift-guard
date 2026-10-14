## 하네스: Swift-Guard 개발

**목표:** XDP/eBPF · Rust 컨트롤 플레인 · WASM 검사 모듈에 걸친 기능 개발과 버그 수정을, 계층 간 경계 정합성 검증까지 포함해 자동화한다.

**트리거:** Swift-Guard 코드 변경 요청(기능 추가, 버그 수정, CLI/API/맵/WASM 모듈 변경) 시 `sg-dev-workflow` 스킬을 사용하라. 변경 없는 정합성 검사는 `sg-boundary-qa`를 직접 사용한다. 단순 질문은 직접 응답 가능.

**환경 메모:** macOS에서는 daemon 크레이트(libbpf-sys)와 BPF 프로그램이 빌드되지 않는다. 검증은 3단계 — Tier 1 빌드(`linux_check.sh all`), Tier 2 커널 E2E(`linux_check.sh e2e` = privileged Docker에서 `tools/test/e2e_check.sh`), Tier 3 성능(물리 장비). 정의: `docs/linux-verification.md`.

**변경 이력:**
| 날짜 | 변경 내용 | 대상 | 사유 |
|------|----------|------|------|
| 2026-10-14 | 초기 구성 | 전체 | - |
| 2026-10-14 | QA 체크리스트 0(엔트리포인트 연결)·E(라이브러리 API 계약) 추가, baseline 모드·심각도/출처 분리, mac_check/linux_check 버그 수정 | skills/sg-boundary-qa, sg-dev-workflow, rust-control-plane, wasm-module-dev | baseline QA 테스트 실행에서 나온 하네스 피드백 |
| 2026-10-14 | mac_check: SSOT 인식(헤더 include·common API import), 통합 테스트 등록을 cargo metadata로 판정 / linux_check: 바이너리 빌드 확인 추가 / QA 스킬: Docker Desktop bpf() 불가 명시 | skills/sg-boundary-qa | Round 1 수정 작업 중 발견(구조 변경으로 비교 단계 무의미화, QA 피드백) |
| 2026-10-14 | linux_check: 툴체인 사전 설치 로컬 이미지(sg-linux-check) 재사용, apt 캐시 볼륨 제거 | skills/sg-boundary-qa/scripts/linux_check.sh | 병렬 에이전트 동시 실행 시 apt lock 충돌(rc=100) |
| 2026-10-14 | QA 체크리스트 D-3(README 설치 절차 클린 컨테이너 재현) 추가 | skills/sg-boundary-qa | README apt 목록에 libbpf-dev 누락을 linux_check가 못 잡음 |
| 2026-10-14 | Tier 2 E2E 도입: tools/test/e2e_check.sh, linux_check.sh e2e 모드(이미지 v2: iproute2/ping/bpftool), BPF 빌드를 Makefile 경로로 검증+BTF 확인, docs/linux-verification.md | skills/sg-boundary-qa, xdp-bpf-dev, sg-dev-workflow | Docker Desktop(x86_64)에서 BPF 동작 확인, Makefile -g -O2 누락 버그를 E2E로 발견 |
| 2026-10-14 | 사용 예시 체계: docs/examples.md, tools/test/lab.sh(실습 랩), tools/test/examples.sh(문서 회귀), linux_check.sh examples 모드(이미지 v3, 컨테이너 내 wasm 빌드) | skills/sg-boundary-qa, wasm-module-dev | 설치 후 동작 확인 예시 요청. 이 과정에서 WASM import 링크 버그·스크립트 실행 권한 누락·CLI 에러 중복 출력 발견 |
| 2026-10-14 | README 초급자용 전면 재작성. Makefile: install이 빌드하지 않음(sudo cargo 실패 방지)·WASM/systemd 선택화. wasm/build.sh 타깃 감지 수정. readme_check.sh(깨끗한 Ubuntu 22.04/24.04에서 README 그대로 실행) 추가 | README.md, Makefile, wasm/build.sh, skills/sg-boundary-qa | README 상세화 요청 + 초급자 경로 검증 필요 |
