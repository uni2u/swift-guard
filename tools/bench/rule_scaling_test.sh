#!/usr/bin/env bash
# Swift-Guard 룰 스케일링 측정 (Tier 3) — 맵의 룰 수에 따른 XDP 처리 pps 변화, 룰 추가 시간
#
# 사용법: sudo tools/bench/rule_scaling_test.sh [옵션]
#   예) sudo tools/bench/rule_scaling_test.sh --interface enp1s0 --generator external --duration 30
#       sudo tools/bench/rule_scaling_test.sh --generator lab --rule-counts 1,10,100 --duration 3   (흐름 검증)
#
# 절차: daemon·attach·매치 룰(bench-match) 준비 → 단계마다 filler 룰을 누적 추가(벽시계 시간 측정)
#       → 측정(basic_throughput 과 같은 방법) → 다음 단계 → 정리(trap).
#   filler = 198.19.<i/256>.<i%256>/32, label bench-fill-<i>, action pass (트래픽과 매치하지 않음).
#   rule_count = 해당 단계의 bench 룰 총수(매치 룰 포함; --rule-action none 이면 filler 만).
#   룰 조회는 패킷당 /32 LPM 1회(src 맵), src 미스면 dst 맵 1회 추가. prefix당 룰 1개, 맵당 최대 10240.
#   --side dst : 매치 룰과 filler 를 목적지 맵에 넣는다(모든 패킷이 src 미스 후 dst 조회).
#   add_rule_us_avg 는 CLI 프로세스 생성·TCP 연결을 포함한 값이다(순수 맵 갱신 지연이 아님).
#
# 결과 (--output-dir, 기본 ./results):
#   meta_rule_scaling.txt, rule_scaling_results.csv, rule_scaling/stats_<count>.csv, rule_scaling/generator_<count>.log
# 요약 헤더: rule_count,side,packet_size,generator,mode,rule_action,duration_sec,samples,pps,pps_peak,gbps,
#            cpu_util,cpu_softirq,cpu_busiest,if_rx_pps,daemon_rss_kb,rules_added,add_rules_sec,add_rule_us_avg
set -euo pipefail

BENCH_NAME=rule_scaling
BENCH_DEFAULT_DURATION=30
# shellcheck source=tools/bench/bench_lib.sh
. "$(cd "$(dirname "$0")" && pwd)/bench_lib.sh"

RULE_COUNTS=1,10,100,1000,5000,10000
SIDE=src
PACKET_SIZE=64
HEADER="rule_count,side,packet_size,generator,mode,rule_action,duration_sec,$MEASURE_FIELDS,rules_added,add_rules_sec,add_rule_us_avg"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  echo
  echo "rule_scaling 전용:"
  echo "  --rule-counts 1,10,...     오름차순, 각 ≤ $MAX_RULES_PER_MAP. 누적 추가 (기본 $RULE_COUNTS)"
  echo "  --side src|dst             룰을 넣을 맵 (기본 src)"
  echo "  --packet-size <n>          FCS 포함 L2 프레임 크기 (기본 $PACKET_SIZE)"
  echo "  (--duration 기본 ${BENCH_DEFAULT_DURATION}초, lab 은 3–5 권장)"
  echo
  echo "$BENCH_COMMON_USAGE"
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rule-counts) [ $# -ge 2 ] || die "--rule-counts 에 값이 필요하다"; RULE_COUNTS=$2; shift 2 ;;
    --side) [ $# -ge 2 ] || die "--side 에 값이 필요하다"; SIDE=$2; shift 2 ;;
    --packet-size) [ $# -ge 2 ] || die "--packet-size 에 값이 필요하다"; PACKET_SIZE=$2; shift 2 ;;
    *) bench_common_opt "$@"; shift "$BENCH_SHIFT" ;;
  esac
done

case "$SIDE" in src|dst) ;; *) die "--side 는 src|dst: '$SIDE'" ;; esac
check_frame_size "$PACKET_SIZE"
IFS=, read -r -a COUNTS <<<"$RULE_COUNTS"
[ "${#COUNTS[@]}" -gt 0 ] || die "--rule-counts 가 비었다"
prev=0
for c in "${COUNTS[@]}"; do
  is_uint "$c" && [ "$c" -ge 1 ] || die "--rule-counts 값은 1 이상의 정수: '$c'"
  [ "$c" -gt "$prev" ] || die "--rule-counts 는 오름차순이어야 한다: $RULE_COUNTS"
  [ "$c" -le "$MAX_RULES_PER_MAP" ] || die "룰 수 $c > 맵 한도 $MAX_RULES_PER_MAP (MAX_FILTER_RULES)"
  prev=$c
done

bench_finalize_opts
for ip in "$SRC_IP" "$DST_IP"; do
  case "$ip" in 198.19.*) die "--src-ip/--dst-ip ($ip) 가 filler 대역 198.19.0.0/16 과 겹친다" ;; esac
done
MATCH=1; [ "$RULE_ACTION" = none ] && MATCH=0
mkdir -p "$OUT_DIR/rule_scaling"
SUMMARY="$OUT_DIR/rule_scaling_results.csv"

log "interface=$IFACE mode=$MODE generator=$GENERATOR side=$SIDE rule_action=$RULE_ACTION size=${PACKET_SIZE}B duration=${DURATION}s counts=$RULE_COUNTS"
log "src=$SRC_IP dst=$DST_IP output=$OUT_DIR"

bench_start_daemon
bench_attach
bench_add_match_rule "$SIDE"
bench_write_meta "$OUT_DIR/meta_rule_scaling.txt" "side=$SIDE" "packet_size=$PACKET_SIZE" "rule_counts=$RULE_COUNTS"
echo "$HEADER" >"$SUMMARY"

FILLED=0   # 지금까지 넣은 filler 수 (다음 filler 인덱스)
for count in "${COUNTS[@]}"; do
  want=$((count - MATCH))
  added=$((want - FILLED))
  add_sec=""; add_us=""
  if [ "$added" -gt 0 ]; then
    log "--- 룰 ${count}개: filler ${added}개 추가 중 ($SIDE 맵) ---"
    t0=$(now_s)
    while [ "$FILLED" -lt "$want" ]; do
      pfx="198.19.$((FILLED / 256)).$((FILLED % 256))/32"
      bench_add_rule "bench-fill-$FILLED" "--$SIDE-ip" "$pfx" --protocol any --action pass \
        || die "filler 추가 실패 (bench-fill-$FILLED, $pfx) — 맵 한도 또는 기존 룰과 중복?"
      FILLED=$((FILLED + 1))
    done
    t1=$(now_s)
    add_sec="$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", b-a }')"
    add_us="$(awk -v s="$add_sec" -v n="$added" 'BEGIN { printf "%.1f", s/n*1e6 }')"
    log "filler ${added}개 추가: ${add_sec}s (평균 ${add_us}µs/룰, CLI 오버헤드 포함)"
  else
    added=0
    log "--- 룰 ${count}개 (추가 없음) ---"
  fi
  measure_once "$PACKET_SIZE" "$OUT_DIR/rule_scaling/stats_$count.csv" "$OUT_DIR/rule_scaling/generator_$count.log"
  # rules_added=0 이면 add_rules_sec, add_rule_us_avg 는 빈 칸
  echo "$count,$SIDE,$PACKET_SIZE,$GENERATOR,$MODE,$RULE_ACTION,$DURATION,$MEASURE_RESULT,$added,$add_sec,$add_us" >>"$SUMMARY"
  log "룰 ${count}개 → $MEASURE_FIELDS = $MEASURE_RESULT"
done

echo
print_table "$SUMMARY"
echo
[ "$GENERATOR" = lab ] && log "*** lab generator: 흐름 검증용 — 성능 수치 아님 ***"
log "요약: $SUMMARY"
log "분석: python3 tools/analysis/analyze_performance.py --results-dir $OUT_DIR"
