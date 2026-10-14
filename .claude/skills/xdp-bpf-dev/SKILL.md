---
name: xdp-bpf-dev
description: Swift-Guard XDP/eBPF 커널 프로그램(src/bpf/xdp_filter.c, include/swift_guard.h, src/bpf/Makefile) 구현 가이드. 패킷 파싱, BPF 맵(LPM trie/hash/percpu) 정의·변경, filter_rule 구조체 필드 추가, 액션(drop/pass/redirect/count)·rate limit·통계 로직, verifier 오류 대응, BPF 빌드를 다룬다. xdp_filter.c나 swift_guard.h를 수정하거나 verifier/맵 레이아웃 문제를 다룰 때 반드시 사용할 것. Rust daemon 코드만 바꾸는 작업에는 rust-control-plane을 사용.
---

# XDP/eBPF 구현 가이드 (Swift-Guard)

## 현재 구조 (수정 전 반드시 실제 파일로 재확인)
- `src/bpf/xdp_filter.c`: `SEC("xdp") xdp_filter_func` → IPv4면 `handle_ipv4` → `filter_rules`(LPM trie, key=`prefix_key{prefix_len, addr}`)를 src IP로 조회 → 포트/프로토콜/TCP 플래그 매칭 → 액션.
- 맵: `filter_rules`(LPM_TRIE, `BPF_F_NO_PREALLOC`), `redirect_map`(HASH, ifindex→`if_redirect`), `stats_map`(PERCPU_ARRAY 1개, 전역 통계).
- **구조체·상수가 두 곳에 중복 정의됨**: `include/swift_guard.h`(`__u32` 타입)와 `xdp_filter.c` 내부(`uint32_t` 타입). xdp_filter.c는 헤더를 include하지 않는다. 한쪽만 바꾸면 조용히 어긋나므로 **항상 둘 다 수정**하거나, 계획이 허용하면 xdp_filter.c가 헤더를 include하도록 정리한다.
- 알려진 기존 한계(변경 요청과 관련 있을 때만 손댄다): rule별 `stats`는 갱신되지 않고 전역 stats만 증가, `ACTION_COUNT` 미처리, dst_ip 매칭 없음, IP 옵션(ihl>5) 무시하고 `iph+1`로 L4 접근.

## 맵 값 레이아웃 규칙
Rust daemon은 맵 값을 **수동 바이트 직렬화**(`maps.rs::create_filter_rule`)로 만든다. 그래서 C 구조체의 자연 정렬 패딩이 곧 프로토콜이다.
- 필드 추가/재배치 후 레이아웃을 측정한다:
  `python3 .claude/skills/sg-boundary-qa/scripts/struct_layout.py include/swift_guard.h filter_rule prefix_key if_redirect filter_stats`
- 측정 결과(offset/size JSON)를 보고서에 그대로 붙인다. Rust 구현자와 QA가 이것을 기준으로 삼는다.
- 패딩을 줄이려고 필드를 재배치하는 것은 좋지만, 그 경우 계획 문서에 명시된 경우에만 한다(Rust 직렬화 전부를 바꿔야 하므로).
- `__attribute__((packed))`를 맵 값 구조체에 쓰지 않는다 — u64 원자 연산(`__sync_fetch_and_add`)이 비정렬 주소에서 verifier/아키텍처 문제를 일으킨다.

## Verifier 통과 원칙
verifier는 "모든 경로에서 메모리 접근이 증명 가능하게 안전한가"를 본다. 그래서:
- 패킷 포인터 접근 전마다 `if ((void *)(hdr + 1) > data_end) return XDP_PASS;` 형태의 경계 검사를 둔다. 가변 길이(ihl, doff) 오프셋을 쓰면 계산한 포인터로 다시 경계 검사한다.
- `bpf_map_lookup_elem` 결과는 반드시 NULL 검사 후 역참조한다.
- 루프는 상수 상한이 있어야 한다(`#pragma unroll` 또는 bounded loop, 커널 5.3+).
- 헬퍼 함수는 `static __always_inline`. 스택은 512바이트 제한 — 큰 구조체를 스택에 복사하지 말고 맵 값 포인터를 쓴다.
- 비트필드 TCP 헤더 파싱은 엔디안 종속이다. 현재 정의는 little-endian 전제이므로 다른 타깃을 고려하면 `doff_res`/flags 바이트를 직접 마스킹하는 방식을 쓴다.

## 바이트 오더
- `iph->saddr`는 네트워크 바이트 오더 그대로 LPM key에 들어간다. LPM trie는 key의 `data` 바이트를 상위 비트부터 비교하므로 **네트워크 오더**여야 CIDR 매칭이 맞다. Rust 쪽이 key를 만들 때 이 규칙과 일치하는지 QA가 확인한다 — 새 매칭 필드를 추가할 때도 같은 원칙을 문서화한다.
- 포트는 `bpf_ntohs`로 호스트 오더 변환 후 비교한다(맵에 저장되는 port_min/max는 호스트 오더).

## 빌드/검증
| 환경 | 명령 | 비고 |
|------|------|------|
| macOS | 불가 (linux/bpf.h 없음) | 정적 검토 + struct_layout.py만 |
| Docker 사용 가능 | `.claude/skills/sg-boundary-qa/scripts/linux_check.sh bpf` | exit 3 = docker 꺼짐(SKIP) |
| Docker (privileged) | `.claude/skills/sg-boundary-qa/scripts/linux_check.sh e2e` | verifier + 실제 attach/매치/통계 (Tier 2) |
| 사용자 Linux 장비 | `make -C src/bpf` → `sudo bpftool prog load src/bpf/xdp_filter.o /sys/fs/bpf/sgtest && sudo rm /sys/fs/bpf/sgtest` | verifier 실통과 확인 |

verifier 실통과는 커널에 로드해야만 확인된다(`linux_check.sh e2e` 1단계). 컴파일 성공을 verifier 통과로 보고하지 않는다.
- 빌드는 반드시 `make -C src/bpf` 경로로 확인한다. Makefile 플래그(`-g -O2`)가 빠지면 BTF가 없어 libbpf가 BTF 정의 맵(`.maps`)을 열지 못한다 — 직접 clang 호출로는 이 회귀를 못 잡는다.

## 보고서 형식 (`_workspace/02_bpf_report.md`)
```markdown
# BPF Report
## 변경 파일
## 경계 계약 이행 (계획 대비: 일치 / 이탈+사유)
## 측정 레이아웃 (struct_layout.py 출력 JSON)
## Verifier 위험 지점 (파일:라인 — 이유)
## 실행한 검증 (명령 — 결과/ SKIP 사유)
## 사용자 Linux 장비에서 실행할 명령
```
