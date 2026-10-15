#!/usr/bin/env bash
# Swift-Guard E2E 커널 기능 검증 (Tier 2)
#
# 물리 NIC 없이 veth + network namespace + generic XDP로 실제 커널 동작을 검증한다.
#   [netns sg-e2e-src] sg-e2e-peer (10.200.0.2) <==veth==> sg-e2e-dut (10.200.0.1, 10.200.0.11) [root ns, XDP 부착]
#                                                         sg-e2e-rd0 <==veth==> sg-e2e-rd1 (redirect 대상)
#
# 검증 항목: verifier 로드, attach/detach, drop/count/redirect 매치, CIDR(LPM 바이트 오더),
#           목적지 룰(dst_rules: drop/count/redirect, 출발지 룰 우선, 조건 불일치 시 넘어감, 맵별 중복),
#           룰별·전역 통계, XDP 전체/결과별 카운터(xdp_stats_map → stats --format csv의 xdp_* 열),
#           L4 파서(IP 옵션·조각·tiny fragment·비정상 IHL: PROG_TEST_RUN 17케이스 + generic XDP live 송신),
#           입력 거부(에러 응답·문구, 미구현 옵션 priority/rate-limit/expire/pkt-len), 카운터 불변식,
#           WASM 모듈 관리(빌드돼 있으면), SIGTERM 정리,
#           API 접근 제어(테스트 전용 Unix 소켓 0660 root:<임시 그룹>, 비멤버 거부·멤버 허용, 감사 로그),
#           소켓 수명(정상 종료 시 삭제, SIGKILL 후 stale 소켓 재사용, 중복 기동·일반 파일 거부, 그룹 없음 → 0600,
#           TCP 옵트인: 비루프백·접두사 없는 주소 거부, tcp:127.0.0.1 동작).
#
# API: 시스템 daemon(/run/swift-guard/api.sock)과 겹치지 않게 테스트 전용 소켓 /run/sg-e2e.XXXXXX/api.sock 과
#      임시 그룹 sg-e2e-api, 임시 사용자 sg-e2e-in(멤버)/sg-e2e-out(비멤버)을 만들고 끝나면 지운다.
#      useradd/groupadd/runuser가 없으면 접근 제어 단계만 SKIP한다.
# 요구: Linux 커널 5.15+ (Docker Desktop/macOS 불가 — bpf() 미지원), root, iproute2, ping.
#       Linux VM(Lima/UTM/Multipass), 클라우드 VM, Linux 호스트 모두 가능.
#       python3·bpftool이 없으면 파서 단계(9·10)만 SKIP한다(FAIL 아님). 패킷은 tools/test/sg_pkt.py가 만든다.
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
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 2
NS=sg-e2e-src; DUT=sg-e2e-dut; PEER=sg-e2e-peer; RD0=sg-e2e-rd0; RD1=sg-e2e-rd1
SRC_IP=10.200.0.2; DUT_IP=10.200.0.1; DUT_IP2=10.200.0.11
# 테스트 전용 API 소켓 (기본 /run/swift-guard/api.sock 과 분리). 디렉토리는 preflight에서 만든다.
SOCK_DIR=""; SOCK=""; API=""
API_GROUP=sg-e2e-api; U_IN=sg-e2e-in; U_OUT=sg-e2e-out
TCP_API=tcp:127.0.0.1:17654
HAVE_USERS=0
AUX_PIDS=""
DAEMON="$ROOT/target/release/swift-guard-daemon"
CLI="$ROOT/target/release/xdp-filter"
BPF_OBJ="$ROOT/src/bpf/xdp_filter.o"
SG_PKT="$ROOT/tools/test/sg_pkt.py"
HAVE_PY=0; HAVE_BPFTOOL=0
TMP="$(mktemp -d /tmp/sg-e2e.XXXXXX)"
BIN_DIR="$TMP/bin"   # 다른 사용자(runuser)가 실행할 CLI 복사본 (저장소가 0700 홈 아래일 수 있다. /run 은 noexec일 수 있다)
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

# ---- XDP 카운터 (stats --format csv 헤더로 열 위치를 찾는다. 열 번호를 하드코딩하지 않는다)
# stats_snap → 헤더 + 데이터 1행. 실패하면 빈 문자열
stats_snap() { c stats --format csv --count 1 2>/dev/null || true; }
# csv_get "<snap>" <열 이름> → 값. 열이 없거나 빈 칸이면 NA
csv_get() {
  printf '%s\n' "$1" | awk -F, -v n="$2" '
    NR == 1 { for (i = 1; i <= NF; i++) if ($i == n) c = i; next }
    c { v = $c }
    END { if (c && v != "") print v; else print "NA" }'
}
# cdelta "<before>" "<after>" <열> → after - before (어느 쪽이 NA면 NA)
cdelta() {
  local a b; a="$(csv_get "$1" "$3")"; b="$(csv_get "$2" "$3")"
  if [ "$a" = NA ] || [ "$b" = NA ]; then echo NA; else echo $((b - a)); fi
}
# check_delta "<설명>" "<before>" "<after>" <열> <ge|eq|le> <값>
check_delta() {
  local d="$1" s0="$2" s1="$3" col="$4" op="$5" want="$6" v
  v="$(cdelta "$s0" "$s1" "$col")"
  if [ "$v" = NA ]; then bad "$d: column '$col' missing (xdp-filter/daemon rebuilt?)"; return; fi
  local pass=0
  case "$op" in
    ge) [ "$v" -ge "$want" ] && pass=1 ;;
    eq) [ "$v" -eq "$want" ] && pass=1 ;;
    le) [ "$v" -le "$want" ] && pass=1 ;;
    *)  bad "check_delta: unknown op '$op'"; return ;;
  esac
  if [ $pass -eq 1 ]; then ok "$d: delta $col=$v ($op $want)"
  else bad "$d: delta $col=$v (expected $op $want)"; fi
}

cleanup() {
  local rc=$?
  if [ $KEEP -eq 1 ] && [ $FAIL -gt 0 ]; then
    echo "--keep: 정리 생략. daemon log: $TMP/daemon.log"; return $rc
  fi
  [ -n "$DAEMON_PID" ] && kill -TERM "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null
  for p in $AUX_PIDS; do kill -KILL "$p" 2>/dev/null && wait "$p" 2>/dev/null; done
  if [ $HAVE_USERS -eq 1 ]; then
    userdel "$U_IN" 2>/dev/null; userdel "$U_OUT" 2>/dev/null; groupdel "$API_GROUP" 2>/dev/null
  fi
  [ -n "$SOCK_DIR" ] && rm -rf "$SOCK_DIR"
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
command -v bpftool >/dev/null && HAVE_BPFTOOL=1
if command -v python3 >/dev/null && [ -f "$SG_PKT" ]; then
  if python3 "$SG_PKT" --selftest >"$TMP/sg_pkt_selftest.log" 2>&1; then HAVE_PY=1
  else bad "sg_pkt.py --selftest (parser steps SKIP)"; grep -F '[FAIL]' "$TMP/sg_pkt_selftest.log" | head -10; fi
fi
echo "python3+sg_pkt.py: $([ $HAVE_PY -eq 1 ] && echo ok || echo 'none → parser steps SKIP'), bpftool: $([ $HAVE_BPFTOOL -eq 1 ] && echo ok || echo 'none → PROG_TEST_RUN SKIP')"
KVER="$(uname -r)"; KMAJ="${KVER%%.*}"; KMIN="$(echo "$KVER" | cut -d. -f2)"; KMIN="${KMIN%%[!0-9]*}"
if [ "$KMAJ" -lt 5 ] || { [ "$KMAJ" -eq 5 ] && [ "${KMIN:-0}" -lt 15 ]; }; then die "커널 5.15+ 필요 (현재 $KVER)"; fi
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
# 테스트 전용 API 소켓 디렉토리 (0755: 비멤버도 디렉토리는 통과하고 소켓 권한에서 막혀야 한다)
SOCK_DIR="$(mktemp -d /run/sg-e2e.XXXXXX)" || die "/run 아래 임시 디렉토리를 만들 수 없다"
chmod 755 "$SOCK_DIR"; SOCK="$SOCK_DIR/api.sock"; API="unix:$SOCK"
# 접근 제어용 임시 그룹·사용자 (이전 실행 잔여물은 먼저 삭제)
if command -v useradd >/dev/null && command -v groupadd >/dev/null && command -v runuser >/dev/null \
   && command -v userdel >/dev/null && command -v groupdel >/dev/null; then
  userdel "$U_IN" 2>/dev/null; userdel "$U_OUT" 2>/dev/null; groupdel "$API_GROUP" 2>/dev/null
  NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
  if groupadd "$API_GROUP" \
     && useradd -M -N -s "$NOLOGIN" -G "$API_GROUP" "$U_IN" \
     && useradd -M -N -s "$NOLOGIN" "$U_OUT"; then
    HAVE_USERS=1
    mkdir -p "$BIN_DIR"; chmod 711 "$TMP"; chmod 755 "$BIN_DIR"
    install -m 0755 "$CLI" "$BIN_DIR/xdp-filter"
  else
    echo "임시 그룹/사용자 생성 실패 → 접근 제어 단계 SKIP"
    userdel "$U_IN" 2>/dev/null; userdel "$U_OUT" 2>/dev/null; groupdel "$API_GROUP" 2>/dev/null
  fi
fi
echo "API: $API (group $API_GROUP), access-control users: $([ $HAVE_USERS -eq 1 ] && echo "$U_IN/$U_OUT" || echo 'none → SKIP')"

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

"$DAEMON" -b "$BPF_OBJ" -c "$TMP/none.yaml" --api-addr "$API" --api-group "$API_GROUP" -v >"$TMP/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 100); do
  [ -S "$SOCK" ] && c list-rules >/dev/null 2>&1 && break
  kill -0 "$DAEMON_PID" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$DAEMON_PID" 2>/dev/null && [ -S "$SOCK" ] && c list-rules >/dev/null 2>&1; then
  ok "daemon up (pid $DAEMON_PID, $API)"
else
  bad "daemon failed to start"; tail -30 "$TMP/daemon.log"; exit 1
fi

# ---------------------------------------------------------------- attach
step "3. Attach (generic)"
if c attach "$DUT" --mode generic >/dev/null && xdp_on; then ok "XDP attached to $DUT"
else bad "attach failed"; ip -d link show dev "$DUT"; tail -20 "$TMP/daemon.log"; exit 1; fi
S0="$(stats_snap)"
ping_ok && ok "ping passes with XDP and no rules" || bad "ping blocked with no rules"
S1="$(stats_snap)"
check_delta "XDP sees every packet" "$S0" "$S1" xdp_rx_packets ge 3
check_delta "no rule → no_match" "$S0" "$S1" xdp_no_match_packets ge 3
check_delta "rule-match total unchanged without rules" "$S0" "$S1" total_packets eq 0

# ---------------------------------------------------------------- access control
step "3b. API access control (Unix socket permissions)"
if [ $HAVE_USERS -eq 0 ]; then
  skip "useradd/groupadd/runuser 없음 또는 생성 실패 → 접근 제어 검증 생략"
else
  MODE="$(stat -c '%a %U %G' "$SOCK" 2>/dev/null)"
  [ "$MODE" = "660 root $API_GROUP" ] && ok "socket mode/owner: $MODE" || bad "socket mode/owner '$MODE' (expected '660 root $API_GROUP')"
  # 비멤버: 조회도 거부되고 sudo/그룹 안내가 나와야 한다
  OUT="$(runuser -u "$U_OUT" -- "$BIN_DIR/xdp-filter" --api-server "$API" list-rules 2>&1)"; rc=$?
  if [ $rc -ne 0 ] && printf '%s\n' "$OUT" | grep -qF 'permission denied' && printf '%s\n' "$OUT" | grep -qF 'sudo'; then
    ok "non-member $U_OUT: list-rules denied with sudo/group hint"
  else bad "non-member $U_OUT: list-rules rc=$rc, output: $OUT (expected 'permission denied' + 'sudo')"; fi
  # 멤버: 허용
  if OUT="$(runuser -u "$U_IN" -- "$BIN_DIR/xdp-filter" --api-server "$API" list-rules 2>&1)"; then
    ok "group member $U_IN: list-rules allowed"
  else bad "group member $U_IN: list-rules failed: $OUT"; fi
  # 비멤버의 변경 시도도 거부되고 룰이 생기지 않아야 한다
  if runuser -u "$U_OUT" -- "$BIN_DIR/xdp-filter" --api-server "$API" \
       add-rule --src-ip 10.9.9.30 --action drop --label e2e-unauth >/dev/null 2>&1; then
    bad "non-member $U_OUT: add-rule accepted (should be denied)"
  else ok "non-member $U_OUT: add-rule denied"; fi
  OUT="$(c list-rules 2>/dev/null || true)"
  printf '%s\n' "$OUT" | grep -qE '^e2e-unauth[[:space:]]' && bad "rule e2e-unauth exists after denied request" \
    || ok "no rule created by denied request"
  # 멤버의 변경 요청 → 감사 로그(uid/gid/pid)
  U_IN_UID="$(id -u "$U_IN")"
  if runuser -u "$U_IN" -- "$BIN_DIR/xdp-filter" --api-server "$API" \
       add-rule --src-ip 10.9.9.31 --action count --label e2e-member >/dev/null 2>&1; then
    ok "group member $U_IN: add-rule allowed"
    sleep 0.2
    grep -qE "API AddRule from uid=$U_IN_UID gid=[0-9]+ pid=" "$TMP/daemon.log" \
      && ok "audit log: 'API AddRule from uid=$U_IN_UID ...'" || bad "audit log line 'API AddRule from uid=$U_IN_UID gid=... pid=...' missing"
    c delete-rule --label e2e-member >/dev/null || bad "delete e2e-member"
  else bad "group member $U_IN: add-rule failed"; fi
  grep -qE "API Attach from uid=0 gid=0 pid=[0-9]+" "$TMP/daemon.log" \
    && ok "audit log: root attach recorded" || bad "audit log line 'API Attach from uid=0 gid=0 pid=...' missing"
fi

# ---------------------------------------------------------------- drop /32
step "4. Drop rule (exact /32)"
c add-rule --src-ip "$SRC_IP" --protocol icmp --action drop --label e2e-drop >/dev/null \
  && ok "add-rule drop accepted" || bad "add-rule drop rejected"
S0="$(stats_snap)"
ping_lost && ok "ICMP from $SRC_IP dropped" || bad "ICMP not dropped (LPM key byte order / matching?)"
S1="$(stats_snap)"
check_delta "drop verdict counter" "$S0" "$S1" xdp_drop_packets ge 3
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
S0="$(stats_snap)"
ping_ok && ok "count rule passes traffic" || bad "count rule blocked traffic"
S1="$(stats_snap)"
check_delta "count verdict counter" "$S0" "$S1" xdp_count_packets ge 3
P=$(rule_pkts e2e-count); [ "${P:-0}" -ge 3 ] && ok "count rule counted $P packets" || bad "count rule not counted ($P)"
c delete-rule --label e2e-count >/dev/null

# ---------------------------------------------------------------- redirect
step "7. Redirect rule"
RX0=$(cat /sys/class/net/$RD1/statistics/rx_packets)
if c add-rule --src-ip "$SRC_IP" --protocol icmp --action redirect --redirect-if "$RD0" --label e2e-redir >/dev/null; then
  ok "add-rule redirect accepted"
  S0="$(stats_snap)"
  ping_lost && ok "redirected ICMP no longer reaches $DUT" || bad "ICMP still answered (redirect not applied)"
  S1="$(stats_snap)"
  check_delta "redirect verdict counter" "$S0" "$S1" xdp_redirect_packets ge 3
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

# ---------------------------------------------------------------- parser (PROG_TEST_RUN)
step "9. Parser (PROG_TEST_RUN: IP options, fragments, invalid headers)"
# daemon이 attach한 프로그램 id. ip link의 prog id가 1순위, 없으면 bpftool에서 daemon pid → 최대 id
attached_prog_id() {
  local id
  id="$(ip -d link show dev "$DUT" 2>/dev/null | grep -oE '(prog/xdp id |xdp(generic|drv|offload)?/id:)[0-9]+' | grep -oE '[0-9]+$' | head -1)"
  if [ -z "$id" ] && [ $HAVE_PY -eq 1 ]; then
    id="$(bpftool -j prog show name xdp_filter_func 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
progs = d if isinstance(d, list) else [d]
pid = int(sys.argv[1])
mine = [p["id"] for p in progs if any(x.get("pid") == pid for x in p.get("pids", []))]
ids = mine or [p["id"] for p in progs if "id" in p]
print(max(ids) if ids else "")' "$DAEMON_PID")"
  fi
  echo "$id"
}
# prog_ret <file> → XDP 반환값 (1=XDP_DROP, 2=XDP_PASS), 실패 시 빈 문자열
prog_ret() {
  local out
  out="$(bpftool prog run id "$PROG_ID" data_in "$1" repeat 1 </dev/null 2>&1 || true)"
  printf '%s\n' "$out" | grep -oE 'Return value: [0-9]+' | grep -oE '[0-9]+$' | head -1
}
if [ $HAVE_PY -eq 0 ] || [ $HAVE_BPFTOOL -eq 0 ]; then
  skip "python3/sg_pkt.py 또는 bpftool 없음 → PROG_TEST_RUN 파서 검증 생략"
else
  PROG_ID="$(attached_prog_id)"
  if [ -z "$PROG_ID" ]; then
    bad "attached XDP program id not found (ip -d link / bpftool prog show)"
  else
    ok "attached program id $PROG_ID"
    PK="$TMP/pkt"; mkdir -p "$PK"
    c add-rule --src-ip 10.77.0.1 --protocol tcp --dst-port 8080 --action drop --label e2e-p-r1 >/dev/null \
      && c add-rule --src-ip 10.77.0.2 --action drop --label e2e-p-r2 >/dev/null \
      && c add-rule --src-ip 10.77.0.3 --protocol tcp --tcp-flags SYN --action drop --label e2e-p-r3 >/dev/null \
      && c add-rule --src-ip 10.77.0.4 --protocol udp --dst-port 5353 --action count --label e2e-p-r4 >/dev/null \
      && ok "parser rules R1-R4 added" || bad "parser rules R1-R4 not all accepted"
    # id | case | src | 기대(1=DROP, 2=PASS) | 추가 옵션 | 설명
    CASES_TBL='P1|tcp|10.77.0.1|1|--dport 8080|R1 port match
P2|tcp-opt|10.77.0.1|1|--dport 8080|IHL=6: L4 read after options (old code: bypass)
P3|tcp-opt-decoy|10.77.0.1|2|--dport 80|option bytes 1f90 not read as dport (old code: false drop)
P4|frag-first-full|10.77.0.1|1|--dport 8080|first fragment with full TCP header
P5|tiny-frag|10.77.0.2|1||tiny fragment -> INVALID before rules (old code: IP rule bypass)
P6|tiny-frag|10.99.0.9|1||tiny fragment with no rule -> INVALID
P7|frag-nonfirst|10.77.0.1|2||non-first fragment does not match port rule
P8|frag-nonfirst|10.77.0.2|1||non-first fragment matches IP-only rule
P9|frag-off1|10.99.0.9|1||TCP fragment offset 1 -> INVALID (RFC 1858)
P10|tcp-trunc|10.77.0.2|1||truncated TCP still matches IP-only rule
P11|tcp-trunc|10.77.0.1|2||truncated TCP does not match port rule
P12|ihl4|10.99.0.9|1||IHL<5 -> INVALID
P13|ihl-trunc|10.99.0.9|1||IHL*4 beyond packet -> INVALID
P14|tcp-opt|10.77.0.3|1|--flags SYN|TCP flags read after options
P15|tcp-opt|10.77.0.3|2|--flags ACK|flag mismatch -> pass
P16|udp-frag-nonfirst|10.77.0.4|2|--dport 5353|non-first UDP fragment does not match port rule
P17|arp|10.99.0.9|2||non-IPv4 -> pass
P18|tiny-frag-pad|10.77.0.2|1||tiny fragment padded to 60B -> INVALID (L4 judged by tot_len, not frame end)
P19|tiny-frag-pad|10.99.0.9|1||padded tiny fragment with no rule -> INVALID
P20|udp-pad|10.77.0.4|2|--dport 5353|short UDP padded to 60B still matches count rule R4'
    R4_0=$(rule_pkts e2e-p-r4)
    S0="$(stats_snap)"
    while IFS='|' read -r id case src want extra desc; do
      f="$PK/$id.bin"
      # shellcheck disable=SC2086  # extra는 의도적으로 단어 분리한다
      if ! python3 "$SG_PKT" build "$case" -o "$f" --src "$src" --dst "$DUT_IP" $extra </dev/null 2>"$TMP/sg_pkt.err"; then
        bad "$id $case: sg_pkt.py build failed: $(cat "$TMP/sg_pkt.err")"; continue
      fi
      got="$(prog_ret "$f")"
      wname=$([ "$want" = 1 ] && echo DROP || echo PASS)
      if [ "$got" = "$want" ]; then ok "$id $case src $src $extra -> $wname ($desc)"
      else bad "$id $case src $src $extra -> ret '${got:-none}', expected $want=$wname ($desc)"; fi
    done <<<"$CASES_TBL"
    S1="$(stats_snap)"
    R4_1=$(rule_pkts e2e-p-r4)
    # R4(count)는 P20(패딩된 정상 UDP)에서만 1 증가해야 한다. P16(UDP 후속 조각)은 매치하지 않는다
    [ $((R4_1 - R4_0)) -eq 1 ] && ok "count rule R4 +1 (P20 padded UDP matched, P16 fragment did not)" \
      || bad "count rule R4 moved $R4_0 -> $R4_1 (expected +1: P20 only; P16 payload read as ports? P20 padding broke L4?)"
    check_delta "parser batch" "$S0" "$S1" xdp_invalid_packets eq 7      # P5 P6 P9 P12 P13 P18 P19
    check_delta "parser batch" "$S0" "$S1" xdp_drop_packets eq 6         # P1 P2 P4 P8 P10 P14
    check_delta "parser batch" "$S0" "$S1" xdp_count_packets eq 1        # P20
    check_delta "parser batch" "$S0" "$S1" xdp_no_match_packets ge 5     # P3 P7 P11 P15 P16 (+배경 IPv4)
    check_delta "parser batch" "$S0" "$S1" xdp_rx_packets ge 20
    check_delta "parser batch" "$S0" "$S1" xdp_non_ipv4_packets ge 1     # P17 (+배경 IPv6 ND)
    check_delta "parser batch" "$S0" "$S1" total_packets eq 7            # 룰 매치 = drop 6 + count 1(P20)
    for l in e2e-p-r1 e2e-p-r2 e2e-p-r3 e2e-p-r4; do c delete-rule --label "$l" >/dev/null || bad "delete $l"; done
  fi
fi

# ---------------------------------------------------------------- parser (live)
step "10. Parser (live AF_PACKET -> generic XDP skb path)"
if [ $HAVE_PY -eq 0 ]; then
  skip "python3/sg_pkt.py 없음 → live 파서 검증 생략"
else
  DUT_MAC="$(cat "/sys/class/net/$DUT/address")"
  send_pkt() {
    ip netns exec "$NS" python3 "$SG_PKT" send "$@" --ifname "$PEER" --dst-mac "$DUT_MAC" \
      --src "$SRC_IP" --dst "$DUT_IP" --count 3 >"$TMP/send.log" 2>&1 \
      || { bad "sg_pkt.py send $*: $(cat "$TMP/send.log")"; return 1; }
  }
  # ① IP 전체 차단 룰이 있어도 tiny fragment는 룰 평가 전에 INVALID로 버려진다.
  #   tiny-frag-pad: 실제 NIC처럼 60B까지 0 패딩(AF_PACKET/veth는 자동 패딩하지 않으므로 명시).
  #   L4 완전성을 프레임 끝(data_end)으로 판단하면 패딩 18B를 TCP 헤더로 오인해 룰 평가로 넘어간다.
  if c add-rule --src-ip "$SRC_IP" --action drop --label e2e-live-ip >/dev/null; then
    for case in tiny-frag tiny-frag-pad; do
      P0=$(rule_pkts e2e-live-ip); S0="$(stats_snap)"
      send_pkt "$case" && sleep 0.3
      S1="$(stats_snap)"; P1=$(rule_pkts e2e-live-ip)
      check_delta "live $case" "$S0" "$S1" xdp_invalid_packets ge 1
      [ "$P1" -eq "$P0" ] && ok "live $case dropped before rule lookup (rule counter unchanged: $P1)" \
        || bad "live $case reached rule lookup (e2e-live-ip $P0 -> $P1)"
    done
    c delete-rule --label e2e-live-ip >/dev/null
  else bad "add-rule e2e-live-ip rejected"; fi
  # ①-b 패딩된 정상 짧은 UDP(60B 프레임, tot_len 28)는 포트 룰에 정상 매치한다
  if c add-rule --src-ip "$SRC_IP" --protocol udp --dst-port 5353 --action count --label e2e-live-udp >/dev/null; then
    P0=$(rule_pkts e2e-live-udp); S0="$(stats_snap)"
    send_pkt udp-pad --dport 5353 && sleep 0.3
    S1="$(stats_snap)"; P1=$(rule_pkts e2e-live-udp)
    [ $((P1 - P0)) -ge 1 ] && ok "live udp-pad dport 5353 matched count rule (+$((P1 - P0)))" \
      || bad "live udp-pad dport 5353 did not match count rule ($P0 -> $P1)"
    check_delta "live udp-pad" "$S0" "$S1" xdp_invalid_packets eq 0
    c delete-rule --label e2e-live-udp >/dev/null
  else bad "add-rule e2e-live-udp rejected"; fi
  # ② IP 옵션(IHL=6)이 있어도 포트 룰이 매치한다
  if c add-rule --src-ip "$SRC_IP" --protocol tcp --dst-port 8080 --action drop --label e2e-live-port >/dev/null; then
    P0=$(rule_pkts e2e-live-port)
    send_pkt tcp-opt --dport 8080 && sleep 0.3
    P1=$(rule_pkts e2e-live-port)
    [ $((P1 - P0)) -ge 1 ] && ok "live tcp-opt (IHL=6) dport 8080 matched port rule (+$((P1 - P0)))" \
      || bad "live tcp-opt dport 8080 did not match port rule ($P0 -> $P1)"
    c delete-rule --label e2e-live-port >/dev/null
  else bad "add-rule e2e-live-port rejected"; fi
fi

# ---------------------------------------------------------------- rejection
step "11. Input rejection (daemon must answer Error, CLI exit≠0)"
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
# 미구현 옵션: 0 이외 값은 daemon이 거부(문구 원천 = daemon), --pkt-len은 CLI가 요청 전에 거부
expect_fail_msg "--priority 5" "priority is not implemented yet: only 0 is accepted (got 5)" \
  add-rule --src-ip 10.9.9.10 --action drop --priority 5 --label e2e-n5
expect_fail_msg "--rate-limit 100" "rate_limit is not implemented yet: only 0 is accepted (got 100)" \
  add-rule --src-ip 10.9.9.10 --action drop --rate-limit 100 --label e2e-n6
expect_fail_msg "--expire 60" "expire is not implemented yet: only 0 is accepted (got 60)" \
  add-rule --src-ip 10.9.9.10 --action drop --expire 60 --label e2e-n7
expect_fail_msg "--pkt-len 64-128" "--pkt-len is not implemented yet" \
  add-rule --src-ip 10.9.9.10 --action drop --pkt-len 64-128 --label e2e-n8
if c add-rule --src-ip 10.9.9.10 --action drop --priority 0 --label e2e-p0 >/dev/null 2>&1; then
  ok "--priority 0 accepted"; c delete-rule --label e2e-p0 >/dev/null
else bad "--priority 0 rejected (0 must stay allowed)"; fi
kill -0 "$DAEMON_PID" 2>/dev/null && ok "daemon alive after rejected requests" || bad "daemon died"

# ---------------------------------------------------------------- wasm
step "12. WASM module management"
WASM="$ROOT/wasm/modules/http_inspector.wasm"
if [ -f "$WASM" ]; then
  c wasm load --name e2e-http --file "$WASM" >/dev/null && ok "wasm load" || bad "wasm load"
  c wasm list 2>/dev/null | grep -q e2e-http && ok "wasm list shows module" || bad "wasm list"
  c wasm stats --name e2e-http >/dev/null && ok "wasm stats" || bad "wasm stats"
  c wasm unload --name e2e-http >/dev/null && ok "wasm unload" || bad "wasm unload"
else
  skip "wasm/modules/http_inspector.wasm 없음 (cd wasm && ./build.sh 후 재실행)"
fi

# ---------------------------------------------------------------- invariant
step "13. XDP counter invariant (rx = sum of verdicts)"
S="$(stats_snap)"
RX="$(csv_get "$S" xdp_rx_packets)"
if [ "$RX" = NA ]; then bad "xdp_rx_packets missing from stats csv"
else
  SUM=0; MISSING=""
  for col in drop pass redirect count no_match invalid non_ipv4 action_error; do
    v="$(csv_get "$S" "xdp_${col}_packets")"
    if [ "$v" = NA ]; then MISSING="$MISSING xdp_${col}_packets"; else SUM=$((SUM + v)); fi
  done
  DIFF=$((RX - SUM)); [ $DIFF -lt 0 ] && DIFF=$((-DIFF))
  if [ -n "$MISSING" ]; then bad "verdict columns missing:$MISSING"
  elif [ $DIFF -le 10 ]; then ok "rx=$RX, sum of verdicts=$SUM (|diff|=$DIFF <= 10)"
  else bad "rx=$RX, sum of verdicts=$SUM (|diff|=$DIFF > 10)"; fi
fi

# ---------------------------------------------------------------- detach
step "14. Detach via CLI"
c detach "$DUT" >/dev/null && ! xdp_on && ok "detached" || bad "detach failed"

# ---------------------------------------------------------------- SIGTERM
step "15. SIGTERM cleanup (DetachGuard)"
c attach "$DUT" --mode generic >/dev/null && xdp_on || bad "re-attach failed"
kill -TERM "$DAEMON_PID"
for _ in $(seq 1 50); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$DAEMON_PID" 2>/dev/null; then bad "daemon did not exit within 5s of SIGTERM"
else
  wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=""
  xdp_on && bad "XDP still attached after SIGTERM" || ok "daemon exited and detached XDP on SIGTERM"
fi

# ---------------------------------------------------------------- socket lifecycle
step "15b. API socket lifecycle (stale / in-use / not-a-socket / no group / TCP opt-in)"
# 보조 daemon은 BPF를 로드하지만 attach하지 않는다. 매번 종료·정리한다.
# aux_start <log> <daemon 추가 인자...> → AUX_PID
aux_start() {
  local log="$1"; shift
  "$DAEMON" -b "$BPF_OBJ" -c "$TMP/none.yaml" -v "$@" >"$log" 2>&1 &
  AUX_PID=$!; AUX_PIDS="$AUX_PIDS $AUX_PID"
}
# aux_ready <endpoint> <pid> → 0 = 응답함 (최대 10초)
aux_ready() {
  local _
  for _ in $(seq 1 100); do
    "$CLI" --api-server "$1" list-rules >/dev/null 2>&1 && return 0
    kill -0 "$2" 2>/dev/null || return 1
    sleep 0.1
  done
  return 1
}
# aux_exited <pid> <초> → 0 = 그 안에 종료함. AUX_RC에 종료 코드
aux_exited() {
  local _ n=$(($2 * 10))
  for _ in $(seq 1 "$n"); do
    if ! kill -0 "$1" 2>/dev/null; then wait "$1" 2>/dev/null; AUX_RC=$?; return 0; fi
    sleep 0.1
  done
  return 1
}
aux_stop() { kill -TERM "$1" 2>/dev/null; aux_exited "$1" 5 || { kill -KILL "$1" 2>/dev/null; wait "$1" 2>/dev/null; }; }
# expect_start_fail "<설명>" <log> <기대 문구> <daemon 인자...> : 5초 안에 비정상 종료 + 로그에 문구
expect_start_fail() {
  local d="$1" log="$2" want="$3"; shift 3
  aux_start "$log" "$@"
  if ! aux_exited "$AUX_PID" 5; then bad "$d: daemon still running after 5s"; aux_stop "$AUX_PID"
  elif [ "$AUX_RC" -eq 0 ]; then bad "$d: daemon exited 0 (expected failure)"
  elif grep -qF -- "$want" "$log"; then ok "$d: refused (exit $AUX_RC, '$want')"
  else bad "$d: exit $AUX_RC without '$want' in log: $(tail -3 "$log" | tr '\n' ' ')"; fi
}

# ① 정상 종료(15단계 SIGTERM) 후 소켓이 지워졌는가
if [ -z "$DAEMON_PID" ]; then
  [ ! -e "$SOCK" ] && ok "API socket removed after SIGTERM" || bad "API socket $SOCK left after SIGTERM"
else skip "main daemon not stopped → socket removal not checked"; fi

# ② SIGKILL → stale 소켓 → 같은 경로로 재기동
AUX="$SOCK_DIR/aux.sock"
aux_start "$TMP/aux1.log" --api-addr "unix:$AUX"; A1=$AUX_PID
if aux_ready "unix:$AUX" "$A1"; then
  ok "aux daemon up on unix:$AUX"
  kill -KILL "$A1"; wait "$A1" 2>/dev/null
  [ -S "$AUX" ] && ok "socket left behind after SIGKILL (stale)" || bad "no socket after SIGKILL (cannot test stale path)"
  aux_start "$TMP/aux2.log" --api-addr "unix:$AUX"; A2=$AUX_PID
  if aux_ready "unix:$AUX" "$A2"; then
    ok "restart on stale socket path answers"
    grep -qF "removed stale API socket $AUX" "$TMP/aux2.log" && ok "log: removed stale API socket" \
      || bad "log line 'removed stale API socket $AUX' missing"
    # ③ 살아 있는 daemon의 경로로 하나 더 기동 → 거부, 기존 daemon은 영향 없음
    expect_start_fail "second daemon on live socket" "$TMP/aux3.log" "already in use" --api-addr "unix:$AUX"
    aux_ready "unix:$AUX" "$A2" && ok "first daemon still answers after refused duplicate" \
      || bad "first daemon stopped answering after duplicate start"
    aux_stop "$A2"
    [ ! -e "$AUX" ] && ok "aux socket removed on SIGTERM" || bad "aux socket left after SIGTERM"
  else bad "restart on stale socket failed: $(tail -3 "$TMP/aux2.log" | tr '\n' ' ')"; aux_stop "$A2"; fi
else bad "aux daemon failed to start: $(tail -3 "$TMP/aux1.log" | tr '\n' ' ')"; aux_stop "$A1"; fi

# ④ 소켓이 아닌 파일 → 삭제하지 않고 기동 실패
FILE_SOCK="$SOCK_DIR/file.sock"; echo keep >"$FILE_SOCK"
expect_start_fail "regular file at socket path" "$TMP/aux4.log" "is not a socket" --api-addr "unix:$FILE_SOCK"
[ "$(cat "$FILE_SOCK" 2>/dev/null)" = keep ] && ok "regular file preserved" || bad "regular file at $FILE_SOCK was modified/removed"

# ⑤ 그룹 없음 → 0600(root 전용)으로 계속 실행
NG="$SOCK_DIR/nogroup.sock"
aux_start "$TMP/aux5.log" --api-addr "unix:$NG" --api-group sg-no-such-group; A5=$AUX_PID
if aux_ready "unix:$NG" "$A5"; then
  M="$(stat -c '%a %U' "$NG" 2>/dev/null)"
  [ "$M" = "600 root" ] && ok "missing group → socket mode $M" || bad "missing group → socket mode '$M' (expected '600 root')"
  grep -qF "group 'sg-no-such-group' not found" "$TMP/aux5.log" && ok "log: group not found warning" \
    || bad "log line \"group 'sg-no-such-group' not found\" missing"
else bad "daemon with missing group failed to start: $(tail -3 "$TMP/aux5.log" | tr '\n' ' ')"; fi
aux_stop "$A5"

# ⑥ TCP 옵트인: 비루프백·접두사 없는 주소는 거부, tcp:127.0.0.1 은 동작
expect_start_fail "daemon --api-addr tcp:0.0.0.0:17654" "$TMP/aux6.log" "non-loopback" --api-addr tcp:0.0.0.0:17654
expect_start_fail "daemon --api-addr 127.0.0.1:17654 (no scheme)" "$TMP/aux7.log" "add a scheme" --api-addr 127.0.0.1:17654
aux_start "$TMP/aux8.log" --api-addr "$TCP_API"; A8=$AUX_PID
if aux_ready "$TCP_API" "$A8"; then
  ok "TCP opt-in: --api-server $TCP_API list-rules"
  grep -qF "TCP API enabled on $TCP_API" "$TMP/aux8.log" && ok "log: TCP no-authentication warning" \
    || bad "log line 'TCP API enabled on $TCP_API' missing"
else bad "TCP opt-in daemon failed: $(tail -3 "$TMP/aux8.log" | tr '\n' ' ')"; fi
aux_stop "$A8"
# CLI도 같은 파서로 거부한다
expect_cli_fail() {
  local d="$1" want="$2" out; shift 2
  if out="$("$CLI" "$@" 2>&1)"; then bad "$d accepted (should be rejected)"
  elif printf '%s\n' "$out" | grep -qF -- "$want"; then ok "$d rejected ('$want')"
  else bad "$d rejected with unexpected message: $out (expected '$want')"; fi
}
expect_cli_fail "CLI --api-server tcp:0.0.0.0:17654" "non-loopback" --api-server tcp:0.0.0.0:17654 list-rules
expect_cli_fail "CLI --api-server 127.0.0.1:17654" "add a scheme" --api-server 127.0.0.1:17654 list-rules
# ⑦ daemon이 없을 때 CLI 안내
expect_cli_fail "CLI with no daemon socket" "daemon is not running" --api-server "unix:$SOCK_DIR/none.sock" list-rules

# ---------------------------------------------------------------- ignored tests
if [ $WITH_IGNORED -eq 1 ]; then
  step "16. cargo test -- --ignored"
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
