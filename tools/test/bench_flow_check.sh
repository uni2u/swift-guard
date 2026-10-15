#!/usr/bin/env bash
# Swift-Guard Tier 3 벤치 스크립트 흐름 검증 (물리 NIC 불필요, 수치는 의미 없음)
#
# 실습 랩(veth) + lab 생성기로 tools/bench 의 전체 흐름을 실제로 돌려 본다:
#   daemon 기동 → stats CSV 계약 확인 → attach → 매치 룰 → lab 트래픽 → xdp-filter stats --format csv(17열)
#   → 요약 CSV(맨 끝 xdp_rx_pps,xdp_rx_pps_peak,xdp_rx_gbps) → tools/analysis/analyze_performance.py
#   (summary.md, matplotlib 있으면 그래프; 이전 형식 결과도 읽는지 포함) → 정리.
# 판정: 요약 CSV 헤더·행 수, pps>0·xdp_rx_pps>0 행 존재, --rule-action none 에서 xdp_rx_pps>0 이고 pps=0,
#       원본 stats CSV 헤더·첫 행 형식, 분석 산출물(처리량 지표 표시), 종료 후 daemon·XDP·lab 잔여물 없음.
#
# 요구: Linux 5.10+, root, iproute2, python3, 빌드 산출물(target/release/{xdp-filter,swift-guard-daemon}, src/bpf/xdp_filter.o)
# 사용법: sudo tools/test/bench_flow_check.sh [--build] [--keep]
#   --build   실행 전 make -C src/bpf && cargo build --release
#   --keep    결과 디렉토리를 지우지 않고 경로를 출력
# 종료 코드: 0 = 전부 PASS, 1 = FAIL 있음, 2 = 실행 환경 부적합
set -uo pipefail

BUILD=0; KEEP=0
for a in "$@"; do
  case "$a" in
    --build) BUILD=1 ;; --keep) KEEP=1 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 2
API=127.0.0.1:17655
LAB_IF=sg-lab0; LAB_NS=sg-lab
# shellcheck disable=SC2034  # 아래 헤더들은 check 의 eval 문자열에서 쓴다
TP_HEADER_V1="packet_size,generator,mode,rule_action,duration_sec,samples,pps,pps_peak,gbps,cpu_util,cpu_softirq,cpu_busiest,if_rx_pps,daemon_rss_kb"
# shellcheck disable=SC2034
TP_HEADER="$TP_HEADER_V1,xdp_rx_pps,xdp_rx_pps_peak,xdp_rx_gbps"
# shellcheck disable=SC2034
RS_HEADER="rule_count,side,packet_size,generator,mode,rule_action,duration_sec,samples,pps,pps_peak,gbps,cpu_util,cpu_softirq,cpu_busiest,if_rx_pps,daemon_rss_kb,rules_added,add_rules_sec,add_rule_us_avg,xdp_rx_pps,xdp_rx_pps_peak,xdp_rx_gbps"
# shellcheck disable=SC2034
STATS_HEADER="timestamp_ms,total_packets,total_bytes,pps,mbps,xdp_rx_packets,xdp_rx_bytes,xdp_rx_pps,xdp_rx_mbps,xdp_drop_packets,xdp_pass_packets,xdp_redirect_packets,xdp_count_packets,xdp_no_match_packets,xdp_invalid_packets,xdp_non_ipv4_packets,xdp_action_error_packets"
# stats CSV 첫 데이터 행: 비율 열(pps, mbps, xdp_rx_pps, xdp_rx_mbps)만 빈 칸
# shellcheck disable=SC2034
STATS_ROW1_RE='^[0-9]+,[0-9]+,[0-9]+,,,[0-9]+,[0-9]+,,,([0-9]+,){7}[0-9]+$'

PASS=0; FAIL=0; SKIP=0
TMP=""

step() { printf '\n== %s ==\n' "$*"; }
ok()   { echo "[PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "[FAIL] $*"; FAIL=$((FAIL+1)); }
skip() { echo "[SKIP] $*"; SKIP=$((SKIP+1)); }
die()  { echo "[ENV] $*" >&2; exit 2; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

cleanup() {
  local rc=$?
  # 벤치 스크립트가 남긴 것이 있으면 강제로 치운다 (판정은 이미 끝난 뒤)
  pkill -INT -f "swift-guard-daemon.*--api-addr $API" 2>/dev/null
  ip netns list 2>/dev/null | grep -qw "$LAB_NS" && "$ROOT/tools/test/lab.sh" down >/dev/null 2>&1
  if [ -n "$TMP" ]; then
    if [ $KEEP -eq 1 ]; then echo "--keep: 결과 $TMP/r"; else rm -rf "$TMP"; fi
  fi
  return $rc
}
trap cleanup EXIT

# ---------------------------------------------------------------- preflight
step "Preflight"
[ "$(uname -s)" = Linux ] || die "Linux 전용"
[ "$(id -u)" -eq 0 ] || die "root 필요: sudo $0 $*"
for t in ip python3 awk; do command -v $t >/dev/null || die "$t 없음"; done
if [ $BUILD -eq 1 ]; then
  echo "building BPF + release binaries..."
  make -C src/bpf >/dev/null || die "make -C src/bpf 실패"
  if [ -n "${SUDO_USER:-}" ]; then sudo -u "$SUDO_USER" -H bash -lc "cd '$ROOT' && cargo build --release -q" || die "cargo build 실패"
  else cargo build --release -q || die "cargo build 실패"; fi
fi
XF="$ROOT/target/release/xdp-filter"
for f in "$XF" "$ROOT/target/release/swift-guard-daemon" "$ROOT/src/bpf/xdp_filter.o"; do
  [ -e "$f" ] || die "$f 없음 → --build 로 실행하거나 먼저 빌드"
done
"$XF" stats --help 2>/dev/null | grep -q -- '--format' || die "xdp-filter 가 stats --format 을 지원하지 않는다 → 다시 빌드"
ip netns list | grep -qw "$LAB_NS" && die "실습 랩이 이미 올라와 있다 → sudo tools/test/lab.sh down 후 실행"
(exec 3<>"/dev/tcp/${API%:*}/${API##*:}") 2>/dev/null && die "$API 를 이미 누가 쓰고 있다"
if python3 -c 'import matplotlib' 2>/dev/null; then HAVE_MPL=1; echo "matplotlib: yes (그래프까지 검증)"
else HAVE_MPL=0; echo "matplotlib: no (summary.md 만 검증)"; fi
TMP="$(mktemp -d /tmp/sg-bench.XXXXXX)"
R="$TMP/r"; R2="$TMP/r2"
BASE=(--generator lab --api-server "$API" --bin-dir "$ROOT/target/release" --bpf-obj "$ROOT/src/bpf/xdp_filter.o")
COMMON=("${BASE[@]}" --output-dir "$R")

# ---------------------------------------------------------------- throughput
step "1. basic_throughput_test.sh --generator lab"
if tools/bench/basic_throughput_test.sh "${COMMON[@]}" --duration 4 --packet-sizes 64,512 >"$TMP/tp.log" 2>&1; then
  ok "basic_throughput_test.sh exit 0"
else bad "basic_throughput_test.sh exit $?"; tail -30 "$TMP/tp.log"; fi
TP="$R/throughput_results.csv"
check "throughput_results.csv 헤더 = 계약 C6" '[ "$(head -1 "$TP" 2>/dev/null)" = "$TP_HEADER" ]'
N=$(($(wc -l <"$TP" 2>/dev/null || echo 1) - 1))
check "throughput_results.csv 행 수 2 (실제 $N)" '[ "$N" -eq 2 ]'
check "throughput: pps>0 인 행 존재" 'awk -F, "NR>1 && \$7>0 {f=1} END {exit !f}" "$TP"'
check "throughput: xdp_rx_pps(15열)>0 인 행 존재" 'awk -F, "NR>1 && \$15>0 {f=1} END {exit !f}" "$TP"'
check "throughput: 모든 행 17열" 'awk -F, "NF!=17 {b=1} END {exit b}" "$TP"'
check "throughput: generator=lab, mode=generic" 'awk -F, "NR>1 && (\$2!=\"lab\" || \$3!=\"generic\") {b=1} END {exit b}" "$TP"'
for s in 64 512; do
  check "throughput/stats_$s.csv 헤더 = 계약 C5 (17열)" '[ "$(head -1 "$R/throughput/stats_$s.csv" 2>/dev/null)" = "$STATS_HEADER" ]'
  check "throughput/stats_$s.csv 첫 행: 비율 열만 빈 칸" 'sed -n 2p "$R/throughput/stats_$s.csv" | grep -qE "$STATS_ROW1_RE"'
  check "throughput/generator_$s.log: sent N packets" 'grep -qE "^sent [0-9]+ packets in" "$R/throughput/generator_$s.log"'
done
check "meta_throughput.txt (generator=lab)" 'grep -qx "generator=lab" "$R/meta_throughput.txt"'
check "daemon.log 생성 (스크립트가 daemon 기동)" '[ -f "$R/daemon.log" ]'
check "흐름 검증 경고 출력" 'grep -q "성능 수치 아님" "$TMP/tp.log"'

# ---------------------------------------------------------------- throughput, rule-action none
step "1b. basic_throughput_test.sh --rule-action none (룰 매치와 무관한 xdp_rx_pps)"
if tools/bench/basic_throughput_test.sh "${BASE[@]}" --output-dir "$R2" --rule-action none --packet-sizes 64 --duration 3 \
     >"$TMP/tp2.log" 2>&1; then
  ok "basic_throughput_test.sh --rule-action none exit 0"
else bad "basic_throughput_test.sh --rule-action none exit $?"; tail -30 "$TMP/tp2.log"; fi
# shellcheck disable=SC2034  # check 의 eval 문자열에서 쓴다
TP2="$R2/throughput_results.csv"
check "none: 헤더 = 계약 C6" '[ "$(head -1 "$TP2" 2>/dev/null)" = "$TP_HEADER" ]'
check "none: rule_action=none, xdp_rx_pps(15열)>0, pps(7열)=0" 'awk -F, "NR==2 && \$4==\"none\" && \$15>0 && \$7==0 {f=1} END {exit !f}" "$TP2"'
check "none: bench-match 룰을 넣지 않음" 'grep -q "rule-action none: 매치 룰 없음" "$TMP/tp2.log" && ! grep -q "매치 룰: bench-match" "$TMP/tp2.log"'

# ---------------------------------------------------------------- rule scaling
step "2. rule_scaling_test.sh --generator lab"
if tools/bench/rule_scaling_test.sh "${COMMON[@]}" --rule-counts 1,10,100 --duration 3 >"$TMP/rs.log" 2>&1; then
  ok "rule_scaling_test.sh exit 0"
else bad "rule_scaling_test.sh exit $?"; tail -30 "$TMP/rs.log"; fi
RS="$R/rule_scaling_results.csv"
check "rule_scaling_results.csv 헤더 = 계약 C6" '[ "$(head -1 "$RS" 2>/dev/null)" = "$RS_HEADER" ]'
N=$(($(wc -l <"$RS" 2>/dev/null || echo 1) - 1))
check "rule_scaling_results.csv 행 수 3 (실제 $N)" '[ "$N" -eq 3 ]'
check "rule_scaling: pps>0 인 행 존재" 'awk -F, "NR>1 && \$9>0 {f=1} END {exit !f}" "$RS"'
check "rule_scaling: xdp_rx_pps(20열)>0 인 행 존재" 'awk -F, "NR>1 && \$20>0 {f=1} END {exit !f}" "$RS"'
check "rule_scaling: 모든 행 22열" 'awk -F, "NF!=22 {b=1} END {exit b}" "$RS"'
check "rule_scaling: rule_count 1,10,100 / rules_added 0,9,90" '[ "$(awk -F, "NR>1 {printf \"%s:%s \", \$1, \$17}" "$RS")" = "1:0 10:9 100:90 " ]'
check "rule_scaling: rules_added>0 행에 add_rule_us_avg 값" 'awk -F, "NR>1 && \$17>0 && \$19==\"\" {b=1} END {exit b}" "$RS"'
for c in 1 10 100; do
  check "rule_scaling/stats_$c.csv 헤더 = 계약 C5 (17열)" '[ "$(head -1 "$R/rule_scaling/stats_$c.csv" 2>/dev/null)" = "$STATS_HEADER" ]'
done
check "throughput 결과가 그대로 공존" '[ "$(head -1 "$TP")" = "$TP_HEADER" ]'

# ---------------------------------------------------------------- analysis
step "3. analyze_performance.py"
AN_ARGS=(--results-dir "$R"); [ $HAVE_MPL -eq 0 ] && AN_ARGS+=(--no-plots)
if python3 tools/analysis/analyze_performance.py "${AN_ARGS[@]}" >"$TMP/an.log" 2>&1; then ok "analyze_performance.py exit 0"
else bad "analyze_performance.py exit $?"; cat "$TMP/an.log"; fi
check "plots/summary.md 존재" '[ -s "$R/plots/summary.md" ]'
check "summary.md 에 FLOW CHECK ONLY 표시" 'grep -q "FLOW CHECK ONLY" "$R/plots/summary.md"'
check "summary.md 처리량 지표 = xdp_rx_pps (섹션 2개)" '[ "$(grep -c "^처리량 지표: \*\*xdp_rx_pps" "$R/plots/summary.md")" -eq 2 ]'
# 이전 형식 결과(xdp_rx_* 열 없음)도 읽어야 한다: 현재 결과에서 마지막 3열을 잘라 구 헤더로 만든다
OLD="$TMP/old"; mkdir -p "$OLD"
{ echo "$TP_HEADER_V1"; tail -n +2 "$TP" | cut -d, -f1-14; } >"$OLD/throughput_results.csv"
python3 tools/analysis/analyze_performance.py --results-dir "$OLD" --no-plots >"$TMP/an_old.log" 2>&1; rc=$?
check "이전 형식 결과 분석 exit 0 (실제 $rc)" '[ "$rc" -eq 0 ]'
check "이전 형식 결과: 처리량 지표 = pps 로 표시" 'grep -q "^처리량 지표: \*\*pps" "$OLD/plots/summary.md"'
if [ $HAVE_MPL -eq 1 ]; then
  for p in throughput.png throughput_cpu.png throughput_timeseries.png rule_scaling.png rule_add_latency.png; do
    check "plots/$p 생성" '[ -s "$R/plots/$p" ]'
  done
else
  skip "그래프 (matplotlib 없음)"
fi
mkdir -p "$TMP/empty"
python3 tools/analysis/analyze_performance.py --results-dir "$TMP/empty" --no-plots >/dev/null 2>&1; rc=$?
check "입력 없는 디렉토리 → exit 1 (실제 $rc)" '[ "$rc" -eq 1 ]'

# ---------------------------------------------------------------- cleanup state
step "4. 정리 상태"
check "daemon 종료됨 ($API 응답 없음)" '! (exec 3<>"/dev/tcp/${API%:*}/${API##*:}") 2>/dev/null'
check "swift-guard-daemon(--api-addr $API) 프로세스 없음" '! pgrep -f "swift-guard-daemon.*--api-addr $API" >/dev/null'
check "$LAB_IF 없음 또는 XDP 해제됨" '! ip -d link show dev "$LAB_IF" 2>/dev/null | grep -qE "xdp(generic)?[ /]|prog/xdp"'
check "lab netns 제거됨" '! ip netns list | grep -qw "$LAB_NS"'

echo
echo "bench_flow_check: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
echo "(lab generator 수치는 흐름 검증용이며 성능 결과가 아니다)"
[ $FAIL -eq 0 ] && { echo "RESULT: ALL PASS"; exit 0; }
echo "RESULT: FAILURES"
for f in "$TMP/tp.log" "$TMP/rs.log"; do [ -f "$f" ] && { echo "--- tail $f"; tail -15 "$f"; }; done
exit 1
