#!/usr/bin/env bash
# docs/examples.md 의 예제를 그대로 실행해 기대 결과(OK/BLOCKED, 통계 등)를 검증한다.
# 문서와 실제 동작이 어긋나지 않게 하는 회귀 테스트다.
#
# 사용법: sudo tools/test/examples.sh [-v]
#   -v  각 예제의 CLI 출력도 보여준다 (문서 갱신용)
# 바이너리 위치: 설치본(/usr/local/bin, /usr/local/lib/swift-guard)이 있으면 그것을, 없으면 저장소 빌드본을 쓴다.
#   SG_BIN_DIR, SG_BPF_OBJ 환경변수로 덮어쓸 수 있다.
# 종료 코드: 0 = 전부 기대대로, 1 = 불일치, 2 = 환경 문제
set -uo pipefail

VERBOSE=0; [ "${1:-}" = -v ] && VERBOSE=1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LAB="$ROOT/tools/test/lab.sh"
if [ -z "${SG_BIN_DIR:-}" ]; then
  if [ -x /usr/local/bin/xdp-filter ]; then SG_BIN_DIR=/usr/local/bin; else SG_BIN_DIR="$ROOT/target/release"; fi
fi
if [ -z "${SG_BPF_OBJ:-}" ]; then
  if [ -f /usr/local/lib/swift-guard/xdp_filter.o ]; then SG_BPF_OBJ=/usr/local/lib/swift-guard/xdp_filter.o; else SG_BPF_OBJ="$ROOT/src/bpf/xdp_filter.o"; fi
fi
XF="$SG_BIN_DIR/xdp-filter"; DAEMON="$SG_BIN_DIR/swift-guard-daemon"
TMP="$(mktemp -d /tmp/sg-ex.XXXXXX)"; DPID=""
PASS=0; FAIL=0

[ "$(id -u)" -eq 0 ] || { echo "root 필요" >&2; exit 2; }
for f in "$XF" "$DAEMON" "$SG_BPF_OBJ"; do [ -e "$f" ] || { echo "$f 없음 (빌드 또는 설치 필요)" >&2; exit 2; }; done
for t in ip ping curl python3; do command -v $t >/dev/null || { echo "$t 없음" >&2; exit 2; }; done

cleanup() { [ -n "$DPID" ] && kill -TERM "$DPID" 2>/dev/null && wait "$DPID" 2>/dev/null; "$LAB" down >/dev/null 2>&1; rm -rf "$TMP"; }
trap cleanup EXIT

title() { printf '\n### %s\n' "$*"; }
x() {  # CLI 실행 (출력은 -v일 때만)
  local out rc; out="$("$XF" "$@" 2>&1)"; rc=$?
  [ $VERBOSE -eq 1 ] && { echo "\$ xdp-filter $*"; echo "$out" | sed 's/^/  /'; }
  return $rc
}
expect() {  # expect <OK|BLOCKED> <lab 명령...>
  local want="$1"; shift
  local got; got="$("$LAB" "$@" 2>/dev/null | tail -1)"
  if [ "$got" = "$want" ]; then echo "[PASS] lab $* → $got"; PASS=$((PASS+1))
  else echo "[FAIL] lab $* → $got (기대: $want)"; FAIL=$((FAIL+1)); fi
}
check() { if eval "$2"; then echo "[PASS] $1"; PASS=$((PASS+1)); else echo "[FAIL] $1"; FAIL=$((FAIL+1)); fi; }
pkts() { "$XF" list-rules --stats 2>/dev/null | grep -A1 -E "^$1[[:space:]]" | grep -oE 'Packets: [0-9]+' | grep -oE '[0-9]+' | head -1; }

# ------------------------------------------------------------ 0. 준비
title "0. 랩 + daemon + attach"
"$LAB" up >/dev/null || exit 2
"$DAEMON" --bpf-obj "$SG_BPF_OBJ" --config "$TMP/none.yaml" >"$TMP/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 50); do x list-rules >/dev/null 2>&1 && break; sleep 0.1; done
check "daemon 응답" 'x list-rules >/dev/null 2>&1'
check "attach sg-lab0 (generic)" 'x attach sg-lab0 --mode generic'
expect OK ping 10.200.0.2
expect OK http 10.200.0.2

# ------------------------------------------------------------ 1. 호스트 전체 차단
title "1. 특정 호스트의 모든 트래픽 차단"
check "add-rule block-host" 'x add-rule --src-ip 10.200.0.2 --action drop --label block-host'
expect BLOCKED ping 10.200.0.2
expect BLOCKED http 10.200.0.2
expect OK ping 10.200.0.3
x delete-rule --label block-host
expect OK ping 10.200.0.2

# ------------------------------------------------------------ 2. 특정 서비스(포트)만 차단
title "2. 특정 호스트의 웹(TCP 8080) 접근만 차단"
check "add-rule block-web" 'x add-rule --src-ip 10.200.0.3 --protocol tcp --dst-port 8080 --action drop --label block-web'
expect BLOCKED http 10.200.0.3
expect OK ping 10.200.0.3
x delete-rule --label block-web

# ------------------------------------------------------------ 3. 포트 범위
title "3. 포트 범위 차단 (TCP 8000-8100)"
check "add-rule block-range" 'x add-rule --src-ip 10.200.0.4 --protocol tcp --dst-port 8000-8100 --action drop --label block-range'
expect BLOCKED http 10.200.0.4 8080
expect OK udp 10.200.0.4
x delete-rule --label block-range

# ------------------------------------------------------------ 4. UDP
title "4. UDP 서비스 차단 (UDP 5353)"
check "add-rule block-udp" 'x add-rule --src-ip 10.200.0.3 --protocol udp --dst-port 5353 --action drop --label block-udp'
expect BLOCKED udp 10.200.0.3
expect OK http 10.200.0.3
x delete-rule --label block-udp

# ------------------------------------------------------------ 5. SYN
title "5. 새 TCP 연결(SYN)만 차단"
check "add-rule block-syn" 'x add-rule --src-ip 10.200.0.3 --protocol tcp --dst-port 8080 --tcp-flags SYN --action drop --label block-syn'
expect BLOCKED syn 10.200.0.3
expect OK ping 10.200.0.3
x delete-rule --label block-syn

# ------------------------------------------------------------ 6. 대역 차단 + 예외
title "6. 대역(/24) 차단 + 한 호스트만 예외 허용"
check "add-rule block-subnet" 'x add-rule --src-ip 10.200.0.0/24 --action drop --label block-subnet'
check "add-rule allow-admin" 'x add-rule --src-ip 10.200.0.5 --action pass --label allow-admin'
expect BLOCKED ping 10.200.0.2
expect BLOCKED http 10.200.0.4
expect OK ping 10.200.0.5
expect OK http 10.200.0.5
x list-rules
x delete-rule --label allow-admin
x delete-rule --label block-subnet

# ------------------------------------------------------------ 7. count
title "7. 차단 없이 트래픽 집계 (count)"
check "add-rule watch-host" 'x add-rule --src-ip 10.200.0.4 --action count --label watch-host'
expect OK ping 10.200.0.4
expect OK http 10.200.0.4
P="$(pkts watch-host)"; check "watch-host 집계 ≥ 3 (실제 ${P:-0})" '[ "${P:-0}" -ge 3 ]'
x list-rules --stats
STATS="$(timeout 3 "$XF" stats --interval 1 2>/dev/null || true)"
[ $VERBOSE -eq 1 ] && echo "$STATS" | head -8 | sed 's/^/  /'
check "전역 통계 출력" 'echo "$STATS" | grep -q "Total packets"'
x delete-rule --label watch-host

# ------------------------------------------------------------ 8. redirect
title "8. 검사 인터페이스로 리다이렉트"
RX0="$("$LAB" insp-rx)"
check "add-rule to-inspect" 'x add-rule --src-ip 10.200.0.5 --protocol icmp --action redirect --redirect-if sg-lab-insp0 --label to-inspect'
expect BLOCKED ping 10.200.0.5
RX1="$("$LAB" insp-rx)"; check "sg-lab-insp1 수신 ≥ 3 (실제 $((RX1-RX0)))" '[ $((RX1-RX0)) -ge 3 ]'
expect OK http 10.200.0.5
x delete-rule --label to-inspect

# ------------------------------------------------------------ 9. 잘못된 입력
title "9. 거부되는 입력 (에러 메시지 확인)"
check "src-ip 없음 → 거부" '! x add-rule --protocol tcp --dst-port 80 --action drop --label bad1'
check "dst-ip 지정 → 거부" '! x add-rule --src-ip 10.200.0.2 --dst-ip 10.200.0.1 --action drop --label bad2'
x add-rule --src-ip 10.200.0.2 --action drop --label dup-a >/dev/null 2>&1
check "같은 src prefix 중복 → 거부" '! x add-rule --src-ip 10.200.0.2 --protocol tcp --action pass --label dup-b'
check "없는 인터페이스로 redirect → 거부" '! x add-rule --src-ip 10.200.0.3 --action redirect --redirect-if nope0 --label bad3'
check "drop 룰에 --redirect-if → 거부" '! x add-rule --src-ip 10.200.0.3 --action drop --redirect-if sg-lab-insp0 --label bad4'
check "redirect인데 --redirect-if 없음 → 거부" '! x add-rule --src-ip 10.200.0.3 --action redirect --label bad5'
x delete-rule --label dup-a

# ------------------------------------------------------------ 10. WASM
title "10. WASM 모듈 관리"
WASM=""
for w in /usr/local/lib/swift-guard/wasm/http_inspector.wasm "$ROOT/wasm/modules/http_inspector.wasm"; do [ -f "$w" ] && { WASM="$w"; break; }; done
if [ -n "$WASM" ]; then
  check "wasm load" 'x wasm load --name http-inspector --file "$WASM"'
  check "wasm list" 'x wasm list && "$XF" wasm list | grep -q http-inspector'
  check "wasm stats" 'x wasm stats --name http-inspector'
  check "wasm unload" 'x wasm unload --name http-inspector'
else
  echo "[SKIP] http_inspector.wasm 없음 (cd wasm && ./build.sh)"
fi

# ------------------------------------------------------------ 11. 정리
title "11. 정리 (detach, 종료)"
check "detach" 'x detach sg-lab0'
check "XDP 해제 확인" '! ip -d link show dev sg-lab0 | grep -qE "xdp(generic)?[ /]|prog/xdp"'
expect OK ping 10.200.0.2

echo
echo "examples: PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ] && { echo "RESULT: ALL EXAMPLES BEHAVE AS DOCUMENTED"; exit 0; }
tail -20 "$TMP/daemon.log"; exit 1
