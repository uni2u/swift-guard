#!/usr/bin/env bash
# macOS(또는 libbpf 없는 호스트)에서 가능한 범위의 빠른 검증 묶음.
#  1) common/cli 크레이트 빌드·테스트
#     (daemon과 루트 패키지 swift-guard는 libbpf-sys 의존 → macOS 불가, linux_check.sh 사용)
#  2) CLI↔common API 타입 drift
#  3) include/swift_guard.h ↔ src/bpf/xdp_filter.c 구조체 레이아웃 일치
#  4) 통합 테스트가 cargo target으로 등록돼 있는지 (미등록이면 --ignored 실행이 0개 → 거짓 통과)
#  5) WASM 모듈 컴파일 (wasm32 타깃이 설치된 경우만, 산출물은 임시 디렉토리 — 저장소에 쓰지 않음)
# 각 단계 결과를 PASS/FAIL/SKIP/WARN로 출력하고, FAIL이 하나라도 있으면 exit 1.
set -uo pipefail

ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
S="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
FAIL=0
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
step() { printf '\n== %s ==\n' "$1"; }
res()  { echo "[$1] $2"; [ "$1" = FAIL ] && FAIL=1; return 0; }

step "cargo check (common, cli)"
cargo check -q -p swift-guard-common -p swift-guard-cli >"$TMP/check.log" 2>&1
rc=$?; grep -E "^error" -A5 "$TMP/check.log" | head -40
[ $rc -eq 0 ] && res PASS "cargo check" || res FAIL "cargo check (exit $rc)"

step "cargo test (common)"
cargo test -q -p swift-guard-common >"$TMP/test.log" 2>&1
rc=$?; grep -E "test result|FAILED|panicked|^error" "$TMP/test.log"
[ $rc -eq 0 ] && res PASS "cargo test common" || res FAIL "cargo test common (exit $rc)"

step "API types: common ↔ cli"
# SSOT 상태(CLI가 common 타입을 import, 자체 정의 없음)면 그것을 판정하고, 복제가 있으면 drift 비교.
if grep -qE "pub (enum|struct) (ApiRequest|ApiResponse)\b" src/cli/src/*.rs; then
  python3 "$S/api_drift.py" src/common/api.rs src/cli/src/api.rs && res PASS "api drift (CLI has copies)" || res FAIL "api drift"
elif grep -rqE "swift_guard_common::api|swift_guard::api" src/cli/src; then
  res PASS "CLI uses common api types (no copies)"
else
  res FAIL "CLI neither defines nor imports ApiRequest/ApiResponse"
fi

step "Struct layout: header ↔ xdp_filter.c"
STRUCTS="filter_rule prefix_key if_redirect filter_stats"
DUP=0; for st in $STRUCTS; do grep -qE "struct[[:space:]]+$st[[:space:]]*\{" src/bpf/xdp_filter.c && DUP=1; done
if grep -qE '#include[[:space:]]+["<](\.\./\.\./include/)?swift_guard\.h[">]' src/bpf/xdp_filter.c && [ $DUP -eq 0 ]; then
  if python3 "$S/struct_layout.py" include/swift_guard.h $STRUCTS >"$TMP/h.json" 2>"$TMP/h.err"; then
    python3 - "$TMP/h.json" <<'PY2'
import json, sys
for k, v in json.load(open(sys.argv[1])).items():
    print("  %s: size=%d" % (k, v["size"]))
PY2
    res PASS "xdp_filter.c includes swift_guard.h, no duplicate struct definitions (SSOT)"
  else cat "$TMP/h.err"; res FAIL "struct_layout.py failed on header"; fi
elif ! python3 "$S/struct_layout.py" include/swift_guard.h $STRUCTS >"$TMP/h.json" 2>"$TMP/h.err"; then
  cat "$TMP/h.err"; res FAIL "struct_layout.py failed on header"
elif ! python3 "$S/struct_layout.py" src/bpf/xdp_filter.c $STRUCTS >"$TMP/c.json" 2>"$TMP/c.err"; then
  cat "$TMP/c.err"; res FAIL "struct_layout.py failed on xdp_filter.c"
elif diff "$TMP/h.json" "$TMP/c.json"; then
  python3 - "$TMP/h.json" <<'PY'
import json, sys
for k, v in json.load(open(sys.argv[1])).items():
    print("  %s: size=%d" % (k, v["size"]))
PY
  res PASS "header == bpf source layouts"
else
  res FAIL "header/bpf layout mismatch"
fi

step "Integration test registration"
# cargo metadata는 컴파일 없이 target 목록을 준다(macOS에서도 동작). tests/integration/*.rs가 각각 test target인지 확인.
TARGETS="$(cargo metadata --no-deps --format-version 1 2>/dev/null | python3 -c '
import json,sys
for p in json.load(sys.stdin)["packages"]:
    for t in p["targets"]:
        if "test" in t["kind"]: print(t["src_path"])')"
for f in tests/integration/*.rs; do
  if echo "$TARGETS" | grep -q "$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"; then res PASS "$(basename "$f" .rs) registered"
  else res WARN "$(basename "$f" .rs) is not a cargo test target → 'cargo test -- --ignored' runs 0 of these"; fi
done

step "WASM modules compile"
if rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
  for m in wasm/modules/*.rs; do
    n="$(basename "$m" .rs)"
    if rustc --edition 2021 --crate-type cdylib --target wasm32-unknown-unknown -O \
         -o "$TMP/$n.wasm" "$m" 2>"$TMP/$n.err"; then res PASS "wasm $n"
    else head -20 "$TMP/$n.err"; res FAIL "wasm $n"; fi
  done
else
  res SKIP "wasm32-unknown-unknown not installed (rustup target add wasm32-unknown-unknown)"
fi

echo
[ $FAIL -eq 0 ] && echo "mac_check: ALL PASS (daemon / root package / BPF compile need linux_check.sh)" || echo "mac_check: FAILURES ABOVE"
exit $FAIL
