#!/usr/bin/env bash
# Swift-Guard 기본 처리량 측정 (Tier 3) — 프레임 크기별 XDP 처리 pps/Gbps, CPU 사용률
#
# 사용법: sudo tools/bench/basic_throughput_test.sh [옵션]
#   예) 송신 장비 + DUT : sudo tools/bench/basic_throughput_test.sh --interface enp1s0 --generator external
#       단일 호스트     : sudo tools/bench/basic_throughput_test.sh --interface enp1s0 --generator pktgen --tx-dev enp2s0
#       흐름 검증       : sudo tools/bench/basic_throughput_test.sh --generator lab --duration 5   (NIC 불필요, 수치 의미 없음)
#
# 절차: daemon 기동(또는 재사용) → attach → 매치 룰(bench-match) → 크기마다
#       xdp-filter stats --format csv 수집 + 트래픽 + /proc/stat·rx 카운터 → 요약 → 정리(trap).
# 주의: 전역 통계는 룰에 매치한 패킷만 센다 → --rule-action none 이면 pps/gbps 는 0 (if_rx_pps 만 의미).
#       pps/gbps 의 바이트 기준은 XDP가 보는 L2 프레임(FCS·프리앰블·IFG 제외) → 선로 속도가 아니다.
#
# 결과 (--output-dir, 기본 ./results):
#   meta_throughput.txt, throughput_results.csv,
#   throughput/stats_<size>.csv (xdp-filter stats CSV 원본), throughput/generator_<size>.log, daemon.log
# 요약 헤더: packet_size,generator,mode,rule_action,duration_sec,samples,pps,pps_peak,gbps,
#            cpu_util,cpu_softirq,cpu_busiest,if_rx_pps,daemon_rss_kb
# 분석: python3 tools/analysis/analyze_performance.py --results-dir <output-dir>
set -euo pipefail

BENCH_NAME=throughput
BENCH_DEFAULT_DURATION=60
# shellcheck source=tools/bench/bench_lib.sh
. "$(cd "$(dirname "$0")" && pwd)/bench_lib.sh"

PACKET_SIZES=64,128,256,512,1024,1518
HEADER="packet_size,generator,mode,rule_action,duration_sec,$MEASURE_FIELDS"

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
  echo
  echo "basic_throughput 전용:"
  echo "  --packet-sizes 64,128,...  FCS 포함 L2 프레임 크기 목록 (기본 $PACKET_SIZES)"
  echo "  (--duration 기본 ${BENCH_DEFAULT_DURATION}초, lab 은 5 권장)"
  echo
  echo "$BENCH_COMMON_USAGE"
}

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --packet-sizes) [ $# -ge 2 ] || die "--packet-sizes 에 값이 필요하다"; PACKET_SIZES=$2; shift 2 ;;
    *) bench_common_opt "$@"; shift "$BENCH_SHIFT" ;;
  esac
done

IFS=, read -r -a SIZES <<<"$PACKET_SIZES"
[ "${#SIZES[@]}" -gt 0 ] || die "--packet-sizes 가 비었다"
for s in "${SIZES[@]}"; do check_frame_size "$s"; done

bench_finalize_opts
mkdir -p "$OUT_DIR/throughput"
SUMMARY="$OUT_DIR/throughput_results.csv"

log "interface=$IFACE mode=$MODE generator=$GENERATOR rule_action=$RULE_ACTION duration=${DURATION}s sizes=$PACKET_SIZES"
log "src=$SRC_IP dst=$DST_IP output=$OUT_DIR"

bench_start_daemon
bench_attach
bench_add_match_rule src
bench_write_meta "$OUT_DIR/meta_throughput.txt" "packet_sizes=$PACKET_SIZES"
echo "$HEADER" >"$SUMMARY"

for size in "${SIZES[@]}"; do
  log "--- ${size}B: ${DURATION}s 측정 ---"
  measure_once "$size" "$OUT_DIR/throughput/stats_$size.csv" "$OUT_DIR/throughput/generator_$size.log"
  echo "$size,$GENERATOR,$MODE,$RULE_ACTION,$DURATION,$MEASURE_RESULT" >>"$SUMMARY"
  log "${size}B → $MEASURE_FIELDS = $MEASURE_RESULT"
done

echo
print_table "$SUMMARY"
echo
[ "$GENERATOR" = lab ] && log "*** lab generator: 흐름 검증용 — 성능 수치 아님 ***"
log "요약: $SUMMARY"
log "분석: python3 tools/analysis/analyze_performance.py --results-dir $OUT_DIR"
