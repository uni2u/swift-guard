#!/usr/bin/env bash
# Swift-Guard E2E 커널 기능 검증 (Tier 2)
#
# 물리 NIC 없이 veth + network namespace + generic XDP로 실제 커널 동작을 검증한다.
#   [netns sg-e2e-src] sg-e2e-peer (10.200.0.2) <==veth==> sg-e2e-dut (10.200.0.1, 10.200.0.11) [root ns, XDP 부착]
#                                                         sg-e2e-rd0 <==veth==> sg-e2e-rd1 (redirect 대상)
#
# 검증 항목: verifier 로드, attach/detach, drop/count/redirect 매치, CIDR(LPM 바이트 오더),
#           목적지 룰(dst_rules: drop/count/redirect, 출발지 룰 우선, 조건 불일치 시 넘어감, 맵별 중복),
#           룰별·전역 통계, 입력 거부(에러 응답·문구), WASM 모듈 관리(빌드돼 있으면), SIGTERM 정리.
#
# 요구: Linux 커널 5.10+ (Docker Desktop/macOS 불가 — bpf() 미지원), root, iproute2, ping.
#       Linux VM(Lima/UTM/Multipass), 클라우드 VM, Linux 호스트 모두 가능.
# 사용법: sudo tools/test/e2e_check.sh [--build] [--with-ignored] [--keep]
#   --build         실행 전 make -C src/bpf && cargo build --release
#   --with-ignored  마지막에 cargo test -- --ignored (root 통합 테스트) 실행
#   --keep          실패해도 정리하지 않고 남김 (디버깅용)
# 종료 코드: 0 = 전부 PASS, 1 = FAIL 있음, 2 = 실행 환경 부적합
set -uo pipefail

BUILD=0; WITH_IGNORED=0; KEEP=0
for a in "$@"; do
  case "$a" in
    --build) BUILD=1 ;; --with-ignored) WITH_IGNORED=1 ;; --keep) KEEP=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 2
NS=sg-e2e-src; DUT=sg-e2e-dut; PEER=sg-e2e-peer; RD0=sg-e2e-rd0; RD1=sg-e2e-rd1
SRC_IP=10.200.0.2; DUT_IP=10.200.0.1; DUT_IP2=10.200.0.11
API=127.0.0.1:17654
DAEMON="$ROOT/target/release/swift-guard-daemon"
CLI="$ROOT/target/release/xdp-filter"
BPF_OBJ="$ROOT/src/bpf/xdp_filter.o"
TMP="$(mktemp -d /tmp/sg-e2e.XXXXXX)"
DAEMON_PID=""
PASS=0; FAIL=0; SKIP=0

c()    { "$CLI" --api-server "$API" "$@"; }
step() { printf '\n== %s ==\n' "$*"; }
ok()   { echo "[PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "[FAIL] $*"; FAIL=$((FAIL+1)); }
skip() { echo "[SKIP] $*"; SKIP=$((SKIP+1)); }
die()  { echo "[ENV] $*" >&2; exit 2; }

# ping_ok/ping_lost [목적지] — 기본 $DUT_IP
ping_ok()   { ip netns exec "$NS" ping -c 3 -i 0.2 -W 1 "${1:-$DUT_IP}" >/dev/null 2>&1; }
ping_lost() { ! ip netns exec "$NS" ping -c 3 -i 0.2 -W 1 "${1:-$DUT_IP}" >/dev/null 2>&1; }
xdp_on()    { ip -d link show dev "$DUT" | grep -qE 'xdp(generic)?[ /]|prog/xdp'; }
# 출력 → 첫 숫자만. pipefail/timeout 종료 코드가 기본값과 섞이지 않도록 변수에 담은 뒤 파싱한다.
first_num() { local n; n="$(grep -oE "$1 [0-9]+" | head -1 | grep -oE '[0-9]+' || true)"; echo "${n:-0}"; }
rule_pkts() { local out; out="$(c list-rules --stats 2>/dev/null || true)"; echo "$out" | grep -A1 -E "^$1[[:space:]]" | first_num 'Packets:'; }

cleanup() {
  local rc=$?
  if [ $KEEP -eq 1 ] && [ $FAIL -gt 0 ]; then
    echo "--keep: 정리 생략. daemon log: $TMP/daemon.log"; return $rc
  fi
  [ -n "$DAEMON_PID" ] && kill -TERM "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null
  ip link set dev "$DUT" xdpgeneric off 2>/dev/null; ip link set dev "$DUT" xdp off 2>/dev/null
  ip link del "$DUT" 2>/dev/null; ip link del "$RD0" 2>/dev/null
  ip netns del "$NS" 2>/dev/null
  rm -rf "$TMP"
  return $rc
}
trap cleanup EXIT

# ---------------------------------------------------------------- preflight
step "Preflight"
[ "$(uname -s)" = Linux ] || die "Linux 전용 (macOS/Docker Desktop은 bpf() 미지원 → Linux VM 사용)"
[ "$(id -u)" -eq 0 ] || die "root 필요: sudo $0 $*"
for t in ip ping; do command -v $t >/dev/null || die "$t 없음 (iproute2, iputils-ping 설치)"; done
KVER="$(uname -r)"; KMAJ="${KVER%%.*}"; KMIN="$(echo "$KVER" | cut -d. -f2)"
if [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "$KMIN" -lt 10 ]; }; then die "커널 5.10+ 필요 (현재 $KVER)"; fi
echo "kernel $KVER, arch $(uname -m)"

if [ $BUILD -eq 1 ]; then
  SUDO_U="${SUDO_USER:-}"
  echo "building BPF + release binaries..."
  make -C src/bpf >/dev/null || die "make -C src/bpf 실패"
  if [ -n "$SUDO_U" ]; then sudo -u "$SUDO_U" -H bash -lc "cd '$ROOT' && cargo build --release -q" || die "cargo build 실패"
  else cargo build --release -q || die "cargo build 실패"; fi
fi
for f in "$DAEMON" "$CLI" "$BPF_OBJ"; do [ -e "$f" ] || die "$f 없음 → --build 로 실행하거나 먼저 빌드"; done
# 이전 실행 잔여물 제거
ip netns del "$NS" 2>/dev/null; ip link del "$DUT" 2>/dev/null; ip link del "$RD0" 2>/dev/null

# ---------------------------------------------------------------- verifier
step "1. Verifier load"
if command -v bpftool >/dev/null; then
  PIN=/sys/fs/bpf/sg_e2e_verify
  mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf 2>/dev/null
  if bpftool prog load "$BPF_OBJ" "$PIN" type xdp >"$TMP/verifier.log" 2>&1; then
    ok "verifier accepted xdp_filter.o"; rm -f "$PIN"
  else bad "verifier rejected xdp_filter.o"; tail -30 "$TMP/verifier.log"; fi
else
  skip "bpftool 없음 → daemon 로드(2단계)로 대신 검증"
fi

# ---------------------------------------------------------------- topology
step "2. Topology + daemon"
ip netns add "$NS"
ip link add "$DUT" type veth peer name "$PEER"
ip link set "$PEER" netns "$NS"
ip addr add "$DUT_IP/24" dev "$DUT"; ip addr add "$DUT_IP2/24" dev "$DUT"; ip link set "$DUT" up
ip -n "$NS" addr add "$SRC_IP/24" dev "$PEER"; ip -n "$NS" link set "$PEER" up; ip -n "$NS" link set lo up
ip link add "$RD0" type veth peer name "$RD1"; ip link set "$RD0" up; ip link set "$RD1" up
ping_ok && ok "baseline ping (no XDP)" || bad "baseline ping failed — topology problem"
ping_ok "$DUT_IP2" && ok "baseline ping to $DUT_IP2 (no XDP)" || bad "baseline ping to $DUT_IP2 failed — topology problem"

"$DAEMON" -b "$BPF_OBJ" -c "$TMP/none.yaml" --api-addr "$API" -v >"$TMP/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do
  (exec 3<>/dev/tcp/${API%:*}/${API#*:}) 2>/dev/null && break
  kill -0 "$DAEMON_PID" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$DAEMON_PID" 2>/dev/null && (exec 3<>/dev/tcp/${API%:*}/${API#*:}) 2>/dev/null; then
  ok "daemon up (pid $DAEMON_PID, $API)"
else
  bad "daemon failed to start"; tail -30 "$TMP/daemon.log"; exit 1
fi

# ---------------------------------------------------------------- attach
step "3. Attach (generic)"
if c attach "$DUT" --mode generic >/dev/null && xdp_on; then ok "XDP attached to $DUT"
else bad "attach failed"; ip -d link show dev "$DUT"; tail -20 "$TMP/daemon.log"; exit 1; fi
ping_ok && ok "ping passes with XDP and no rules" || bad "ping blocked with no rules"

# ---------------------------------------------------------------- drop /32
step "4. Drop rule (exact /32)"
c add-rule --src-ip "$SRC_IP" --protocol icmp --action drop --label e2e-drop >/dev/null \
  && ok "add-rule drop accepted" || bad "add-rule drop rejected"
ping_lost && ok "ICMP from $SRC_IP dropped" || bad "ICMP not dropped (LPM key byte order / matching?)"
P=$(rule_pkts e2e-drop); [ "${P:-0}" -ge 3 ] && ok "per-rule stats: $P packets" || bad "per-rule stats not counted ($P)"
STATS_OUT="$(timeout 3 "$CLI" --api-server "$API" stats --interval 1 2>/dev/null || true)"
TOTAL="$(echo "$STATS_OUT" | first_num 'Total packets:')"
[ "${TOTAL:-0}" -gt 0 ] && ok "global stats (percpu sum): $TOTAL packets" || bad "global stats zero"
c delete-rule --label e2e-drop >/dev/null && ok "delete-rule" || bad "delete-rule failed"
ping_ok && ok "traffic restored after delete" || bad "traffic still blocked after delete"

# ---------------------------------------------------------------- CIDR
step "5. Drop rule (CIDR /24 — LPM prefix byte order)"
c add-rule --src-ip 10.200.0.0/24 --protocol any --action drop --label e2e-cidr >/dev/null \
  && ok "add-rule /24 accepted" || bad "add-rule /24 rejected"
ping_lost && ok "10.200.0.0/24 prefix matched" || bad "CIDR rule did not match"
c delete-rule --label e2e-cidr >/dev/null; ping_ok || bad "traffic not restored after CIDR delete"

# ---------------------------------------------------------------- count
step "6. Count rule"
c add-rule --src-ip "$SRC_IP" --protocol icmp --action count --label e2e-count >/dev/null \
  && ok "add-rule count accepted" || bad "add-rule count rejected"
ping_ok && ok "count rule passes traffic" || bad "count rule blocked traffic"
P=$(rule_pkts e2e-count); [ "${P:-0}" -ge 3 ] && ok "count rule counted $P packets" || bad "count rule not counted ($P)"
c delete-rule --label e2e-count >/dev/null

# ---------------------------------------------------------------- redirect
step "7. Redirect rule"
RX0=$(cat /sys/class/net/$RD1/statistics/rx_packets)
if c add-rule --src-ip "$SRC_IP" --protocol icmp --action redirect --redirect-if "$RD0" --label e2e-redir >/dev/null; then
  ok "add-rule redirect accepted"
  ping_lost && ok "redirected ICMP no longer reaches $DUT" || bad "ICMP still answered (redirect not applied)"
  RX1=$(cat /sys/class/net/$RD1/statistics/rx_packets)
  [ $((RX1-RX0)) -ge 3 ] && ok "$RD1 received $((RX1-RX0)) redirected packets" \
    || bad "redirect target got $((RX1-RX0)) packets (expected ≥3)"
  c delete-rule --label e2e-redir >/dev/null
else bad "add-rule redirect rejected"; fi

# ---------------------------------------------------------------- dst rules
step "8. Destination rules (dst_rules)"
# 8a dst drop
if c add-rule --dst-ip "$DUT_IP2" --protocol icmp --action drop --label e2e-dst >/dev/null; then
  ok "add-rule --dst-ip drop accepted"
  ping_lost "$DUT_IP2" && ok "ICMP to $DUT_IP2 dropped (dst rule)" || bad "ICMP to $DUT_IP2 not dropped (dst_rules lookup / key byte order?)"
  ping_ok && ok "other destination $DUT_IP unaffected" || bad "ICMP to $DUT_IP blocked by dst rule for $DUT_IP2"
  P=$(rule_pkts e2e-dst); [ "${P:-0}" -ge 3 ] && ok "dst rule stats: $P packets" || bad "dst rule stats not counted ($P)"
  c list-rules 2>/dev/null | grep -E "^e2e-dst[[:space:]]" | grep -qF "$DUT_IP2" \
    && ok "list-rules shows $DUT_IP2 in DEST" || bad "list-rules does not show $DUT_IP2 for e2e-dst"
  # 8b src 룰 우선: src pass가 매치하면 dst 룰은 평가되지 않는다
  P0=$(rule_pkts e2e-dst)
  c add-rule --src-ip "$SRC_IP" --protocol icmp --action pass --label e2e-src-pass >/dev/null \
    && ok "add-rule src pass accepted" || bad "add-rule src pass rejected"
  ping_ok "$DUT_IP2" && ok "src pass rule wins over dst drop" || bad "dst drop applied despite matching src pass rule"
  P=$(rule_pkts e2e-src-pass); [ "${P:-0}" -ge 3 ] && ok "src pass counted $P packets" || bad "src pass not counted ($P)"
  P1=$(rule_pkts e2e-dst); [ "$P1" -eq "$P0" ] && ok "dst rule not evaluated (counter unchanged: $P1)" || bad "dst counter moved $P0 → $P1 while src rule matched"
  c delete-rule --label e2e-src-pass >/dev/null
  # 8c src 조건 불일치 → dst로 넘어감
  c add-rule --src-ip "$SRC_IP" --protocol tcp --action pass --label e2e-src-tcp >/dev/null \
    && ok "add-rule src tcp pass accepted" || bad "add-rule src tcp pass rejected"
  ping_lost "$DUT_IP2" && ok "src rule mismatch (tcp vs icmp) falls through to dst drop" || bad "ICMP to $DUT_IP2 not dropped after src mismatch"
  c delete-rule --label e2e-src-tcp >/dev/null
  c delete-rule --label e2e-dst >/dev/null && ok "delete dst rule" || bad "delete dst rule failed"
  ping_ok "$DUT_IP2" && ok "traffic to $DUT_IP2 restored after delete" || bad "traffic to $DUT_IP2 still blocked after delete"
else bad "add-rule --dst-ip drop rejected"; fi
# 8d dst count
if c add-rule --dst-ip "$DUT_IP2" --protocol icmp --action count --label e2e-dst-count >/dev/null; then
  ok "add-rule dst count accepted"
  ping_ok "$DUT_IP2" && ok "dst count rule passes traffic" || bad "dst count rule blocked traffic"
  P=$(rule_pkts e2e-dst-count); [ "${P:-0}" -ge 3 ] && ok "dst count rule counted $P packets" || bad "dst count rule not counted ($P)"
  c delete-rule --label e2e-dst-count >/dev/null
else bad "add-rule dst count rejected"; fi
# 8e dst redirect
RX0=$(cat /sys/class/net/$RD1/statistics/rx_packets)
if c add-rule --dst-ip "$DUT_IP2" --protocol icmp --action redirect --redirect-if "$RD0" --label e2e-dst-redir >/dev/null; then
  ok "add-rule dst redirect accepted"
  ping_lost "$DUT_IP2" && ok "redirected ICMP to $DUT_IP2 no longer answered" || bad "ICMP to $DUT_IP2 still answered (dst redirect not applied)"
  RX1=$(cat /sys/class/net/$RD1/statistics/rx_packets)
  [ $((RX1-RX0)) -ge 3 ] && ok "$RD1 received $((RX1-RX0)) dst-redirected packets" \
    || bad "dst redirect target got $((RX1-RX0)) packets (expected ≥3)"
  c delete-rule --label e2e-dst-redir >/dev/null
else bad "add-rule dst redirect rejected"; fi
# 8f 같은 prefix를 src 맵과 dst 맵에 각각 둘 수 있다
c add-rule --src-ip 10.9.9.6 --action count --label e2e-pm-s >/dev/null \
  && ok "src rule 10.9.9.6 accepted" || bad "src rule 10.9.9.6 rejected"
c add-rule --dst-ip 10.9.9.6 --action count --label e2e-pm-d >/dev/null \
  && ok "dst rule for same prefix 10.9.9.6 accepted (per-map duplicate check)" || bad "dst rule for same prefix 10.9.9.6 rejected"
c delete-rule --label e2e-pm-d >/dev/null; c delete-rule --label e2e-pm-s >/dev/null

# ---------------------------------------------------------------- rejection
step "9. Input rejection (daemon must answer Error, CLI exit≠0)"
expect_fail() { local d="$1"; shift; if c "$@" >/dev/null 2>&1; then bad "$d accepted (should be rejected)"; else ok "$d rejected"; fi; }
# expect_fail_msg "<설명>" "<기대 문구>" <cli 인자...> : 거부되고 출력에 문구가 있어야 PASS
expect_fail_msg() {
  local d="$1" want="$2" out; shift 2
  if out="$(c "$@" 2>&1)"; then bad "$d accepted (should be rejected)"
  elif printf '%s\n' "$out" | grep -qF -- "$want"; then ok "$d rejected ('$want')"
  else bad "$d rejected with unexpected message: $out (expected '$want')"; fi
}
expect_fail_msg "rule without --src-ip/--dst-ip" "src_ip or dst_ip is required" \
  add-rule --protocol tcp --dst-port 80 --action drop --label e2e-n1
expect_fail_msg "rule with both --src-ip and --dst-ip" "specify either src_ip or dst_ip, not both" \
  add-rule --src-ip "$SRC_IP" --dst-ip "$DUT_IP" --action drop --label e2e-n2
expect_fail "unknown --redirect-if"     add-rule --src-ip 10.9.9.9 --action redirect --redirect-if sg-nope0 --label e2e-n3
expect_fail "--redirect-if on drop"     add-rule --src-ip 10.9.9.8 --action drop --redirect-if "$RD0" --label e2e-n4
c add-rule --src-ip 10.9.9.7 --action drop --label e2e-dup1 >/dev/null
expect_fail "duplicate prefix"          add-rule --src-ip 10.9.9.7 --action pass --label e2e-dup2
expect_fail "label reused across maps"  add-rule --dst-ip 10.9.9.4 --action drop --label e2e-dup1
c delete-rule --label e2e-dup1 >/dev/null
c add-rule --dst-ip 10.9.9.5 --action drop --label e2e-dupd1 >/dev/null
expect_fail_msg "duplicate dst prefix" "a rule for dst 10.9.9.5/32 already exists (label 'e2e-dupd1')" \
  add-rule --dst-ip 10.9.9.5 --action pass --label e2e-dupd2
c delete-rule --label e2e-dupd1 >/dev/null
kill -0 "$DAEMON_PID" 2>/dev/null && ok "daemon alive after rejected requests" || bad "daemon died"

# ---------------------------------------------------------------- wasm
step "10. WASM module management"
WASM="$ROOT/wasm/modules/http_inspector.wasm"
if [ -f "$WASM" ]; then
  c wasm load --name e2e-http --file "$WASM" >/dev/null && ok "wasm load" || bad "wasm load"
  c wasm list 2>/dev/null | grep -q e2e-http && ok "wasm list shows module" || bad "wasm list"
  c wasm stats --name e2e-http >/dev/null && ok "wasm stats" || bad "wasm stats"
  c wasm unload --name e2e-http >/dev/null && ok "wasm unload" || bad "wasm unload"
else
  skip "wasm/modules/http_inspector.wasm 없음 (cd wasm && ./build.sh 후 재실행)"
fi

# ---------------------------------------------------------------- detach
step "11. Detach via CLI"
c detach "$DUT" >/dev/null && ! xdp_on && ok "detached" || bad "detach failed"

# ---------------------------------------------------------------- SIGTERM
step "12. SIGTERM cleanup (DetachGuard)"
c attach "$DUT" --mode generic >/dev/null && xdp_on || bad "re-attach failed"
kill -TERM "$DAEMON_PID"
for _ in $(seq 1 50); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$DAEMON_PID" 2>/dev/null; then bad "daemon did not exit within 5s of SIGTERM"
else
  wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
  xdp_on && bad "XDP still attached after SIGTERM" || ok "daemon exited and detached XDP on SIGTERM"
fi

# ---------------------------------------------------------------- ignored tests
if [ $WITH_IGNORED -eq 1 ]; then
  step "13. cargo test -- --ignored"
  if [ -n "${SUDO_USER:-}" ]; then
    sudo -E -u "$SUDO_USER" -H bash -lc "cd '$ROOT' && cargo build -q" >/dev/null 2>&1
  fi
  cargo test --workspace -- --ignored --test-threads=1 >"$TMP/ignored.log" 2>&1 \
    && ok "ignored integration tests" || { bad "ignored integration tests"; grep -E "FAILED|panicked|test result" "$TMP/ignored.log" | head -20; }
fi

echo
echo "e2e_check: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ $FAIL -eq 0 ] && { echo "RESULT: ALL PASS"; exit 0; }
echo "RESULT: FAILURES (daemon log tail below)"; tail -20 "$TMP/daemon.log" 2>/dev/null
exit 1
