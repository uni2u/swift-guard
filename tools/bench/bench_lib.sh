# shellcheck shell=bash
# shellcheck disable=SC2034  # 변수 다수는 source 하는 스크립트가 사용한다
# tools/bench 공통 함수. basic_throughput_test.sh / rule_scaling_test.sh 가 source 한다(단독 실행 X).
#
# 제공: 공통 옵션 파싱(bench_common_opt / bench_finalize_opts), daemon 탐지·기동, stats CSV 계약 확인,
#       attach, 매치 룰, measure_once(측정 1회 → MEASURE_RESULT + MEASURE_XDP_RESULT), meta 파일,
#       cleanup(trap EXIT INT TERM).
# 전제: 호출 스크립트가 `set -euo pipefail` 이고 BENCH_NAME, BENCH_DEFAULT_DURATION 을 먼저 정한다.
#
# 측정 원리 (docs/poc-plan.md "측정 전 공통 사항"):
#   `xdp-filter stats --format csv` 한 행에는 두 종류의 카운터가 있다(17열, STATS_CSV_HEADER).
#   - xdp_rx_*  (8·9열 → xdp_rx_pps/xdp_rx_gbps): BPF xdp_stats_map 의 RX 슬롯. XDP가 본 **모든 프레임**을
#     파싱 전에 센다. 룰 매치와 무관하므로 **XDP 처리량의 1차 지표**다.
#   - total_*   (4·5열 → pps/gbps): BPF stats_map. **룰에 매치한 패킷만** 센다(apply_rule 안에서만 증가).
#     매치 룰(label bench-match)의 액션 경로(drop/count)를 거친 패킷 수다.
#   매치 룰은 측정 시나리오를 정한다: drop(기본) = XDP_DROP 경로, count = 룰 매치 후 XDP_PASS,
#   none = 룰 없음(no_match → XDP_PASS, 커널 스택까지 감). 어느 경우든 xdp_rx_pps 로 처리량을 잰다.
#   if_rx_pps(인터페이스 rx 카운터)는 드라이버가 센 참고값이다(XDP_DROP 계수 방식은 드라이버마다 다르다).

BENCH_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$BENCH_LIB_DIR/../.." && pwd)"
LAB="$ROOT/tools/test/lab.sh"
PKTGEN_TX="$BENCH_LIB_DIR/pktgen_tx.sh"
# xdp-filter stats --format csv 헤더 (CLI STATS_CSV_HEADER 와 같은 고정 계약, 17열)
STATS_CSV_HEADER="timestamp_ms,total_packets,total_bytes,pps,mbps,xdp_rx_packets,xdp_rx_bytes,xdp_rx_pps,xdp_rx_mbps,xdp_drop_packets,xdp_pass_packets,xdp_redirect_packets,xdp_count_packets,xdp_no_match_packets,xdp_invalid_packets,xdp_non_ipv4_packets,xdp_action_error_packets"
MEASURE_FIELDS="samples,pps,pps_peak,gbps,cpu_util,cpu_softirq,cpu_busiest,if_rx_pps,daemon_rss_kb"
# 요약 CSV 맨 끝에 붙는 열 (MEASURE_XDP_RESULT 의 순서)
XDP_MEASURE_FIELDS="xdp_rx_pps,xdp_rx_pps_peak,xdp_rx_gbps"
MAX_RULES_PER_MAP=10240
LAB_IF=sg-lab0; LAB_SRC=10.200.0.2; LAB_DST=10.200.0.1

# ---------------------------------------------------------------- 옵션 (기본값은 bench_finalize_opts 에서)
IFACE=""; MODE=""; GENERATOR=external; DURATION=""; SRC_IP=""; DST_IP=""; RULE_ACTION=drop
OUT_DIR=./results; API=unix:/run/swift-guard/api.sock; BPF_OBJ=""; BIN_DIR=""
NO_DAEMON=0; NO_ATTACH=0; FORCE_ATTACH=0; TX_DEV=""; DST_MAC=""; PKTGEN_THREADS=1
NO_PROMPT=0; WARMUP=2

# ---------------------------------------------------------------- 상태 (cleanup 이 사용)
DAEMON_PID=""; DAEMON_STARTED=0; DAEMON_REUSED=0; ATTACHED=0; LAB_STARTED=0
STATS_PID=""; GEN_PID=""; PKTGEN_ACTIVE=0; CLEANED=0
RULES_CREATED=()
MEASURE_RESULT=""; MEASURE_XDP_RESULT=""

log()  { echo "[$BENCH_NAME] $*"; }
warn() { echo "[$BENCH_NAME] WARN: $*" >&2; }
die()  { echo "[$BENCH_NAME] ERROR: $*" >&2; exit 1; }
BENCH_TMPFILES=()

BENCH_COMMON_USAGE='공통 옵션:
  --interface <if>          XDP를 붙일 DUT 인터페이스(수신측). lab이면 sg-lab0 고정, 그 외 필수
  --mode driver|generic     attach 모드 (기본 driver, lab이면 generic)
  --generator pktgen|external|lab
                            트래픽 생성기 (기본 external)
                              pktgen   : 이 호스트의 --tx-dev 에서 커널 pktgen(tools/bench/pktgen_tx.sh)
                              external : 측정만 한다. 송신 장비에서 직접 트래픽을 보낸다
                              lab      : tools/test/lab.sh flood (흐름 검증용 — 성능 수치 아님)
  --duration <초>           크기(또는 룰 수)당 측정 시간
  --src-ip <ip>             트래픽 출발지 IP = 매치 룰 대상 (lab 10.200.0.2, 그 외 198.18.0.2)
  --dst-ip <ip>             트래픽 목적지 IP (lab 10.200.0.1, 그 외 --interface 의 첫 IPv4, 없으면 198.18.0.1)
  --rule-action drop|count|none
                            트래픽에 매치하는 룰(label bench-match)의 액션 (기본 drop).
                            처리량(xdp_rx_pps)은 어느 값이든 룰과 무관하게 측정된다. 액션은 경로를 정한다:
                              drop  XDP_DROP 경로 (대표 지표)
                              count 룰 매치 후 XDP_PASS
                              none  룰 없음 → no_match 로 XDP_PASS (커널 스택 경로). pps/gbps(룰 매치)는 0
  --output-dir <dir>        결과 디렉토리 (기본 ./results)
  --api-server <addr>       daemon API 주소 (기본 unix:/run/swift-guard/api.sock, TCP는 tcp:127.0.0.1:<port>)
  --bpf-obj <path>          daemon 기동 시 BPF 오브젝트 (기본 src/bpf/xdp_filter.o, 없으면 /usr/local/lib/swift-guard/xdp_filter.o)
  --bin-dir <dir>           swift-guard-daemon, xdp-filter 위치 (기본 저장소 target/release, 없으면 PATH)
  --no-daemon               daemon을 띄우지 않는다. API가 응답하지 않으면 에러
  --no-attach               attach/detach 생략 (이미 붙어 있다고 가정)
  --force-attach            attach 실패 시 --force 로 재시도 (스크립트가 띄운 daemon에서만 — 다른 프로그램이 붙인
                            XDP를 교체. 이미 실행 중인 daemon을 재사용할 때는 거부된다: 운영 필터를 떼어내지 않기 위해)
  --tx-dev <dev>            (pktgen 필수) 송신 장치 — DUT NIC와 케이블로 직결된 다른 NIC 또는 veth peer
  --dst-mac <mac>           pktgen 목적지 MAC (기본 --interface 의 MAC)
  --pktgen-threads <n>      pktgen 커널 스레드 수 (기본 1)
  --no-prompt               external 에서 크기별 Enter 대기 생략 (대신 --warmup 초 대기)
  --warmup <초>             external: 트래픽 시작 후 측정 전 대기 (기본 2)
  -h, --help'

# bench_common_opt "$@" : 공통 옵션 하나를 처리하고 소비한 인자 수를 BENCH_SHIFT 에 넣는다.
bench_common_opt() {
  local opt="$1" val="${2:-}"
  BENCH_SHIFT=2
  case "$opt" in
    --interface|--mode|--generator|--duration|--src-ip|--dst-ip|--rule-action|--output-dir|--api-server|\
    --bpf-obj|--bin-dir|--tx-dev|--dst-mac|--pktgen-threads|--warmup)
      [ $# -ge 2 ] && [ -n "$val" ] || die "$opt 에 값이 필요하다" ;;
  esac
  case "$opt" in
    --interface) IFACE=$val ;;
    --mode) MODE=$val ;;
    --generator) GENERATOR=$val ;;
    --duration) DURATION=$val ;;
    --src-ip) SRC_IP=$val ;;
    --dst-ip) DST_IP=$val ;;
    --rule-action) RULE_ACTION=$val ;;
    --output-dir) OUT_DIR=$val ;;
    --api-server) API=$val ;;
    --bpf-obj) BPF_OBJ=$val ;;
    --bin-dir) BIN_DIR=$val ;;
    --tx-dev) TX_DEV=$val ;;
    --dst-mac) DST_MAC=$val ;;
    --pktgen-threads) PKTGEN_THREADS=$val ;;
    --warmup) WARMUP=$val ;;
    --no-daemon) NO_DAEMON=1; BENCH_SHIFT=1 ;;
    --no-attach) NO_ATTACH=1; BENCH_SHIFT=1 ;;
    --force-attach) FORCE_ATTACH=1; BENCH_SHIFT=1 ;;
    --no-prompt) NO_PROMPT=1; BENCH_SHIFT=1 ;;
    *) die "알 수 없는 옵션: $opt (--help 참고)" ;;
  esac
}

is_uint() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }
is_ipv4() {
  local ip="${1:-}" o
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  for o in ${ip//./ }; do [ "$o" -le 255 ] || return 1; done
}
check_frame_size() { is_uint "$1" && [ "$1" -ge 64 ] && [ "$1" -le 1518 ] || die "프레임 크기는 64–1518 (FCS 포함 L2): '$1'"; }

# 기본값 적용 + 검증 + 바이너리/오브젝트 탐색. 옵션 파싱이 끝난 뒤 호출한다.
bench_finalize_opts() {
  trap bench_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  case "$GENERATOR" in pktgen|external|lab) ;; *) die "--generator 는 pktgen|external|lab: '$GENERATOR'" ;; esac
  case "$RULE_ACTION" in drop|count|none) ;; *) die "--rule-action 은 drop|count|none: '$RULE_ACTION'" ;; esac
  if [ "$GENERATOR" = lab ]; then
    [ -n "$IFACE" ] && [ "$IFACE" != "$LAB_IF" ] && warn "lab 생성기는 --interface $LAB_IF 를 쓴다 ('$IFACE' 무시)"
    IFACE=$LAB_IF
    MODE=${MODE:-generic}; SRC_IP=${SRC_IP:-$LAB_SRC}; DST_IP=${DST_IP:-$LAB_DST}
    case "$DST_IP" in 10.200.0.1|10.200.0.11) ;; *) die "lab 생성기의 --dst-ip 는 10.200.0.1 또는 10.200.0.11" ;; esac
  else
    [ -n "$IFACE" ] || die "--interface 가 필요하다 (NIC 없이 흐름만 보려면 --generator lab)"
    MODE=${MODE:-driver}; SRC_IP=${SRC_IP:-198.18.0.2}
  fi
  case "$MODE" in driver|generic) ;; *) die "--mode 는 driver|generic: '$MODE'" ;; esac
  DURATION=${DURATION:-$BENCH_DEFAULT_DURATION}
  is_uint "$DURATION" && [ "$DURATION" -ge 1 ] || die "--duration 은 1 이상의 정수: '$DURATION'"
  is_uint "$WARMUP" || die "--warmup 은 정수: '$WARMUP'"
  is_uint "$PKTGEN_THREADS" && [ "$PKTGEN_THREADS" -ge 1 ] || die "--pktgen-threads 는 1 이상: '$PKTGEN_THREADS'"
  is_ipv4 "$SRC_IP" || die "--src-ip 가 IPv4가 아니다: '$SRC_IP'"
  # 형식만 거른다. 최종 검증(루프백 전용 등)은 xdp-filter/daemon 의 주소 파서가 한다
  case "$API" in
    unix:/*|/*|tcp:*) ;;
    *) die "--api-server 는 unix:/path/to/socket 또는 tcp:<loopback-ip>:<port>: '$API' (예전 host:port 형식이면 앞에 tcp: 를 붙인다)" ;;
  esac

  [ "$(uname -s)" = Linux ] || die "Linux 전용"
  [ "$(id -u)" -eq 0 ] || die "root 필요: sudo $0 ..."
  command -v setsid >/dev/null || die "setsid 없음 (util-linux 설치)"
  local kver kmaj kmin
  kver="$(uname -r)"; kmaj="${kver%%.*}"; kmin="$(echo "$kver" | cut -d. -f2)"; kmin="${kmin%%[!0-9]*}"
  if [ "$kmaj" -lt 5 ] || { [ "$kmaj" -eq 5 ] && [ "${kmin:-0}" -lt 15 ]; }; then
    warn "커널 $kver 은 지원 최소 버전 5.15 보다 낮다 (attach/verifier 가 실패할 수 있다. 벤더 백포트 커널이면 계속 진행)"
  fi

  if [ "$GENERATOR" = lab ]; then
    [ -x "$LAB" ] || die "$LAB 없음"
    if ! ip link show "$LAB_IF" >/dev/null 2>&1; then
      log "실습 랩이 없어 올린다: tools/test/lab.sh up"
      "$LAB" up >/dev/null || die "lab.sh up 실패"
      LAB_STARTED=1
    fi
  fi
  [ -e "/sys/class/net/$IFACE" ] || die "인터페이스 없음: $IFACE"
  if [ -z "$DST_IP" ]; then
    DST_IP="$(ip -4 -o addr show dev "$IFACE" 2>/dev/null | awk '{split($4,a,"/"); print a[1]; exit}')"
    DST_IP=${DST_IP:-198.18.0.1}
  fi
  is_ipv4 "$DST_IP" || die "--dst-ip 가 IPv4가 아니다: '$DST_IP'"
  if [ "$GENERATOR" = pktgen ]; then
    [ -n "$TX_DEV" ] || die "--generator pktgen 에는 --tx-dev 가 필요하다"
    [ -e "/sys/class/net/$TX_DEV" ] || die "--tx-dev 인터페이스 없음: $TX_DEV"
    DST_MAC=${DST_MAC:-$(cat "/sys/class/net/$IFACE/address")}
    modprobe pktgen 2>/dev/null || [ -d /proc/net/pktgen ] \
      || die "커널 pktgen 모듈 없음 — 별도 송신 장비에서 tools/bench/pktgen_tx.sh 를 돌리고 --generator external 사용"
  fi

  # 바이너리: --bin-dir > 저장소 target/release > PATH
  if [ -z "$BIN_DIR" ]; then
    if [ -x "$ROOT/target/release/xdp-filter" ]; then BIN_DIR="$ROOT/target/release"
    elif command -v xdp-filter >/dev/null; then BIN_DIR="$(dirname "$(command -v xdp-filter)")"
    else die "xdp-filter 를 찾지 못함 (cargo build --release 또는 --bin-dir)"; fi
  fi
  XF="$BIN_DIR/xdp-filter"; DAEMON_BIN="$BIN_DIR/swift-guard-daemon"
  [ -x "$XF" ] || die "$XF 없음"
  "$XF" stats --help 2>/dev/null | grep -q -- '--format' \
    || die "$XF 가 'stats --format csv' 를 지원하지 않는다 → cargo build --release 로 다시 빌드"
  if [ -z "$BPF_OBJ" ]; then
    if [ -f "$ROOT/src/bpf/xdp_filter.o" ]; then BPF_OBJ="$ROOT/src/bpf/xdp_filter.o"
    else BPF_OBJ=/usr/local/lib/swift-guard/xdp_filter.o; fi
  fi

  mkdir -p "$OUT_DIR" || die "결과 디렉토리 생성 실패: $OUT_DIR"
  OUT_DIR="$(cd "$OUT_DIR" && pwd)"

  if [ "$GENERATOR" = lab ]; then
    log "*** 흐름 검증용 (lab generator: veth + python 송신) — 성능 수치 아님 ***"
  fi
}

xf() { "$XF" --api-server "$API" "$@"; }
# 전송 방식(Unix/TCP)과 무관하게 CLI로 응답 여부를 본다
api_up() { "$XF" --api-server "$API" list-rules >/dev/null 2>&1; }

# ---------------------------------------------------------------- daemon / attach / 룰
bench_start_daemon() {
  if api_up; then
    DAEMON_REUSED=1
    DAEMON_PID="$(pidof -s swift-guard-daemon 2>/dev/null || true)"
    warn "$API 에서 실행 중인 daemon을 재사용한다(종료하지 않음). 기존 룰이 결과와 룰 한도(맵당 $MAX_RULES_PER_MAP)에 영향을 준다"
    return
  fi
  [ "$NO_DAEMON" -eq 1 ] && die "--no-daemon 인데 $API 가 응답하지 않는다"
  [ -x "$DAEMON_BIN" ] || die "$DAEMON_BIN 없음"
  [ -f "$BPF_OBJ" ] || die "BPF 오브젝트 없음: $BPF_OBJ (make -C src/bpf)"
  # -c 에 존재하지 않는 경로 → 설정 파일 무시(기본값). -i 를 주지 않아 자동 attach 도 하지 않는다.
  "$DAEMON_BIN" -b "$BPF_OBJ" -c /nonexistent/swift-guard-bench.yaml --api-addr "$API" >"$OUT_DIR/daemon.log" 2>&1 &
  DAEMON_PID=$!; DAEMON_STARTED=1
  local _
  for _ in $(seq 1 50); do
    api_up && break
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.1
  done
  if ! api_up; then
    tail -20 "$OUT_DIR/daemon.log" >&2
    die "daemon이 5초 안에 $API 에서 응답하지 않는다 (로그: $OUT_DIR/daemon.log)"
  fi
  log "daemon 기동 (pid $DAEMON_PID, $API, log $OUT_DIR/daemon.log)"
}

# stats CSV 계약 확인 (측정 전에 한 번). 헤더가 다르면 xdp_rx_* 요약이 불가능하므로 중단한다.
bench_check_stats_csv() {
  local out hdr row rx
  out="$(xf stats --format csv --count 1 2>&1)" || die "xdp-filter stats --format csv 실패: $(echo "$out" | tail -1)"
  # 파이프(echo|head) 없이 분리: pipefail 아래에서 head가 먼저 닫으면 SIGPIPE(141)로 실패할 수 있다
  hdr="${out%%$'\n'*}"; row="$(sed -n 2p <<<"$out")"
  [ "$hdr" = "$STATS_CSV_HEADER" ] \
    || die "xdp-filter stats CSV 헤더가 계약(17열)과 다르다 → xdp-filter 재빌드 필요 (cargo build --release). 받은 헤더: $hdr"
  rx="$(echo "$row" | cut -d, -f6)"
  [ -n "$rx" ] \
    || die "daemon이 XDP 카운터를 주지 않는다(xdp_rx_packets 빈 칸) → swift-guard-daemon·xdp_filter.o 재빌드 후 재기동"
}

bench_attach() {
  if [ "$NO_ATTACH" -eq 1 ]; then log "--no-attach: $IFACE 에 이미 붙어 있다고 가정"; return; fi
  # 재사용 daemon이 붙여 둔 XDP를 --force 로 교체하면 정리 단계 detach 가 운영 필터를 떼어낸다 → 거부
  if [ "$FORCE_ATTACH" -eq 1 ] && [ "$DAEMON_REUSED" -eq 1 ]; then
    die "--force-attach 는 이미 실행 중인 daemon($API)을 재사용할 때 쓸 수 없다. 그 daemon이 $IFACE 에 붙여 두었으면 --no-attach 를 쓰고, 교체가 필요하면 그 daemon을 멈춘 뒤 스크립트가 daemon을 띄우게 하라"
  fi
  if xf attach "$IFACE" --mode "$MODE" >/dev/null 2>"$OUT_DIR/.attach.err"; then
    ATTACHED=1
  elif [ "$FORCE_ATTACH" -eq 1 ] && xf attach "$IFACE" --mode "$MODE" --force >/dev/null 2>"$OUT_DIR/.attach.err"; then
    ATTACHED=1
  else
    cat "$OUT_DIR/.attach.err" >&2
    rm -f "$OUT_DIR/.attach.err"
    if [ "$DAEMON_REUSED" -eq 1 ]; then
      die "attach $IFACE --mode $MODE 실패 (driver 미지원이면 --mode generic. 재사용 중인 daemon이 이미 붙여 두었으면 --no-attach)"
    fi
    die "attach $IFACE --mode $MODE 실패 (driver 미지원이면 --mode generic. 다른 프로그램의 XDP가 붙어 있으면 --force-attach 로 교체)"
  fi
  rm -f "$OUT_DIR/.attach.err"
  log "XDP attach: $IFACE ($MODE)"
}

# bench_add_rule <label> <add-rule 인자...> : 성공하면 RULES_CREATED 에 기록 (재사용 daemon 정리용)
bench_add_rule() {
  local label="$1"; shift
  xf add-rule "$@" --label "$label" >/dev/null || return 1
  RULES_CREATED+=("$label")
}

# bench_add_match_rule src|dst : 트래픽(출발지 또는 목적지)에 매치하는 룰 bench-match
bench_add_match_rule() {
  local side="${1:-src}"
  [ "$RULE_ACTION" = none ] && { log "--rule-action none: 매치 룰 없음 → no_match(XDP_PASS) 경로. 처리량은 xdp_rx_pps, pps/gbps(룰 매치)는 0"; return; }
  # 재사용 daemon에 같은 label 이 이미 있으면 지우지 않고 중단한다 (사용자 룰일 수 있다)
  if [ "$DAEMON_REUSED" -eq 1 ] && xf list-rules 2>/dev/null | awk 'NR>2 { print $1 }' | grep -qx bench-match; then
    die "재사용 daemon에 label 'bench-match' 룰이 이미 있다 (이전 실행 잔여물이면 xdp-filter delete-rule --label bench-match 후 다시 실행)"
  fi
  if [ "$side" = dst ]; then
    bench_add_rule bench-match --dst-ip "$DST_IP" --protocol any --action "$RULE_ACTION" \
      || die "매치 룰 추가 실패 (같은 dst prefix 룰이 이미 있나? xdp-filter list-rules)"
    log "매치 룰: bench-match --dst-ip $DST_IP --action $RULE_ACTION"
  else
    bench_add_rule bench-match --src-ip "$SRC_IP" --protocol any --action "$RULE_ACTION" \
      || die "매치 룰 추가 실패 (같은 src prefix 룰이 이미 있나? xdp-filter list-rules)"
    log "매치 룰: bench-match --src-ip $SRC_IP --action $RULE_ACTION"
  fi
}

# ---------------------------------------------------------------- cleanup
# bg_run <cmd...> : 새 세션(프로세스 그룹 = pid)으로 백그라운드 실행. 호출 후 $! 사용
bg_run() { setsid "$@" & }
kill_group() {
  local pid="$1" _
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
  for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  kill -KILL -- "-$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  return 0
}

bench_cleanup() {
  local rc=$? _
  [ ${#BENCH_TMPFILES[@]} -gt 0 ] && rm -f "${BENCH_TMPFILES[@]}"
  [ "$CLEANED" -eq 1 ] && return $rc
  CLEANED=1
  set +e
  # 백그라운드 작업은 setsid 로 각자 프로세스 그룹을 가진다 → 그룹째 종료 (lab.sh → python, pktgen_tx.sh → echo start 포함)
  [ -n "$STATS_PID" ] && kill_group "$STATS_PID"
  [ -n "$GEN_PID" ] && kill_group "$GEN_PID"
  if [ "$PKTGEN_ACTIVE" -eq 1 ] && [ -w /proc/net/pktgen/pgctrl ]; then echo stop >/proc/net/pktgen/pgctrl 2>/dev/null; fi
  if [ "$DAEMON_REUSED" -eq 1 ] && [ "${#RULES_CREATED[@]}" -gt 0 ]; then
    log "정리: 이 스크립트가 넣은 룰 ${#RULES_CREATED[@]}개 삭제"
    for _ in "${RULES_CREATED[@]}"; do xf delete-rule --label "$_" >/dev/null 2>&1 || warn "delete-rule $_ 실패"; done
  fi
  if [ "$ATTACHED" -eq 1 ]; then xf detach "$IFACE" >/dev/null 2>&1 || warn "detach $IFACE 실패"; fi
  if [ "$DAEMON_STARTED" -eq 1 ] && [ -n "$DAEMON_PID" ]; then
    kill -INT "$DAEMON_PID" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$DAEMON_PID" 2>/dev/null && { warn "daemon이 5초 안에 끝나지 않아 SIGKILL"; kill -KILL "$DAEMON_PID" 2>/dev/null; }
    wait "$DAEMON_PID" 2>/dev/null
  fi
  if [ "$LAB_STARTED" -eq 1 ]; then "$LAB" down >/dev/null 2>&1 || warn "lab.sh down 실패"; fi
  return $rc
}

# ---------------------------------------------------------------- 측정 보조
cpu_snap() { grep -E '^cpu[0-9]* ' /proc/stat; }
rx_packets() { cat "/sys/class/net/$IFACE/statistics/rx_packets"; }
now_s() { date +%s.%N; }

# cpu_delta <snapA> <snapB> → "cpu_util,cpu_softirq,cpu_busiest" (%, 소수 1자리)
#   busy = total - idle - iowait,  total = user..steal (guest 는 user 에 이미 포함)
cpu_delta() {
  awk 'NR==FNR { for (i=2;i<=9;i++) a[$1,i]=$i; next }
       { t=0; for (i=2;i<=9;i++) { d[i]=$i-a[$1,i]; t+=d[i] }
         busy = t - d[5] - d[6]
         if ($1=="cpu") { tot=t; tb=busy; ts=d[8] }
         else if (t>0 && busy/t > best) best = busy/t }
       END { if (tot>0) printf "%.1f,%.1f,%.1f", 100*tb/tot, 100*ts/tot, 100*best; else printf "0.0,0.0,0.0" }' "$1" "$2"
}

# summarize_rate <raw_csv> <pps열> <mbps열> → "samples,pps,pps_peak,gbps"
#   samples = 데이터 행 수. pps = 빈 칸이 아니고 0보다 큰 샘플의 평균(3개 이상이면 처음·끝 제외),
#   pps_peak = 최대값, gbps = 같은 샘플의 mbps 평균 / 1000.
summarize_rate() {
  awk -F, -v pc="$2" -v mc="$3" 'NR==1 { next }
           NF>=5 { n++
                   if ($pc != "") { if ($pc+0 > peak) peak=$pc+0
                                    if ($pc+0 > 0) { k++; P[k]=$pc+0; M[k]=$mc+0 } } }
           END { s=1; e=k; if (k>=3) { s=2; e=k-1 }
                 sp=0; sm=0; c=0
                 for (i=s;i<=e;i++) { sp+=P[i]; sm+=M[i]; c++ }
                 if (c>0) printf "%d,%d,%d,%.4f", n, int(sp/c+0.5), peak, sm/c/1000
                 else printf "%d,0,%d,0.0000", n+0, peak+0 }' "$1"
}
# summarize_stats <raw_csv> → "samples,pps,pps_peak,gbps" (4·5열: 룰 매치 기준)
summarize_stats() { summarize_rate "$1" 4 5; }
# summarize_xdp_stats <raw_csv> → "xdp_rx_pps,xdp_rx_pps_peak,xdp_rx_gbps" (8·9열: XDP 전체 기준)
summarize_xdp_stats() { summarize_rate "$1" 8 9 | cut -d, -f2-; }

daemon_rss_kb() {
  [ -n "$DAEMON_PID" ] && [ -r "/proc/$DAEMON_PID/status" ] || { echo ""; return; }
  awk '/^VmRSS:/ { print $2 }' "/proc/$DAEMON_PID/status"
}

# 생성기 준비(측정 전): external 은 안내 + Enter/warmup 대기
gen_prepare() {
  local size="$1"
  [ "$GENERATOR" = external ] || return 0
  log "송신 장비에서 ${size}B 프레임(FCS 포함), dst $DST_IP, src $SRC_IP 로 트래픽을 시작하라 (여기서 packet_size=$size 는 라벨일 뿐이다)"
  log "  예: sudo tools/bench/pktgen_tx.sh --dev <tx-nic> --dst-ip $DST_IP --dst-mac $(cat "/sys/class/net/$IFACE/address") --src-ip $SRC_IP --size $size --duration $((DURATION + WARMUP + 10))"
  if [ -t 0 ] && [ "$NO_PROMPT" -eq 0 ]; then
    read -r -p "[$BENCH_NAME] 트래픽이 시작되면 Enter... " _ || true
  fi
  [ "$WARMUP" -gt 0 ] && sleep "$WARMUP"
  return 0
}

# 생성기 실행(foreground, DURATION 초). 출력은 <gen_log>
gen_run() {
  local size="$1" glog="$2"
  case "$GENERATOR" in
    lab)
      bg_run "$LAB" --to "$DST_IP" flood "$SRC_IP" "$DURATION" "$size" >"$glog" 2>&1
      GEN_PID=$!; wait "$GEN_PID" || warn "lab flood 실패 (로그: $glog)"; GEN_PID="" ;;
    pktgen)
      PKTGEN_ACTIVE=1
      bg_run "$PKTGEN_TX" --dev "$TX_DEV" --dst-ip "$DST_IP" --dst-mac "$DST_MAC" --src-ip "$SRC_IP" \
        --size "$size" --duration "$DURATION" --threads "$PKTGEN_THREADS" >"$glog" 2>&1
      GEN_PID=$!; wait "$GEN_PID" || warn "pktgen_tx.sh 실패 (로그: $glog)"; GEN_PID=""; PKTGEN_ACTIVE=0 ;;
    external)
      echo "external generator: measured ${DURATION}s window at $(date -Iseconds)" >"$glog"
      sleep "$DURATION" ;;
  esac
}

# measure_once <size> <raw_csv> <gen_log>
#   → MEASURE_RESULT="$MEASURE_FIELDS" 순서의 값, MEASURE_XDP_RESULT="$XDP_MEASURE_FIELDS" 순서의 값
measure_once() {
  local size="$1" raw="$2" glog="$3" cA cB rA rB tA tB cpu st if_rx
  cA="$(mktemp)"; cB="$(mktemp)"
  BENCH_TMPFILES+=("$cA" "$cB")   # die 경로에서도 bench_cleanup이 지운다
  gen_prepare "$size"
  bg_run "$XF" --api-server "$API" stats --format csv --interval 1 --count $((DURATION + 3)) >"$raw" 2>"$raw.err"
  STATS_PID=$!
  sleep 1
  cpu_snap >"$cA"; rA=$(rx_packets); tA=$(now_s)
  gen_run "$size" "$glog"
  cpu_snap >"$cB"; rB=$(rx_packets); tB=$(now_s)
  local stats_rc=0
  wait "$STATS_PID" || stats_rc=$?
  STATS_PID=""
  # daemon 사망 등으로 수집이 실패하면 이 측정의 요약 행을 남기지 않고 중단한다 (이전 행은 그대로)
  if [ "$stats_rc" -ne 0 ]; then
    api_up || die "측정 중 daemon이 응답하지 않는다 — 이 측정은 기록하지 않음 (xdp-filter stats rc=$stats_rc: $(head -c 300 "$raw.err"); daemon 로그 확인)"
    die "xdp-filter stats 가 비정상 종료 (rc=$stats_rc: $(head -c 300 "$raw.err")) — 이 측정은 기록하지 않음"
  fi
  [ -s "$raw.err" ] || rm -f "$raw.err"
  [ "$(head -1 "$raw" 2>/dev/null)" = "$STATS_CSV_HEADER" ] \
    || die "$raw 헤더가 계약(17열)과 다르다 → xdp-filter 재빌드 필요 — 이 측정은 기록하지 않음"
  st="$(summarize_stats "$raw")"
  [ "${st%%,*}" -gt 0 ] || die "$raw 에 데이터 행이 없다 — 이 측정은 기록하지 않음"
  cpu="$(cpu_delta "$cA" "$cB")"
  if_rx="$(awk -v a="$rA" -v b="$rB" -v t0="$tA" -v t1="$tB" 'BEGIN { d=t1-t0; if (d>0) printf "%d", (b-a)/d+0.5; else print 0 }')"
  rm -f "$cA" "$cB"
  MEASURE_RESULT="$st,$cpu,$if_rx,$(daemon_rss_kb)"
  MEASURE_XDP_RESULT="$(summarize_xdp_stats "$raw")"
  local pps xrx; pps="$(echo "$st" | cut -d, -f2)"; xrx="${MEASURE_XDP_RESULT%%,*}"
  if [ "$xrx" = 0 ]; then
    warn "xdp_rx_pps=0 — 트래픽이 XDP에 도달하지 않음 (--interface $IFACE, 송신 경로·dst MAC 확인, if_rx_pps=$if_rx)"
  elif [ "$pps" = 0 ] && [ "$RULE_ACTION" != none ]; then
    warn "pps(룰 매치)=0 — bench-match 룰이 트래픽에 매치하지 않음 (--src-ip $SRC_IP / --dst-ip $DST_IP 확인, xdp_rx_pps=$xrx)"
  fi
}

# bench_write_meta <file> [key=value ...]
bench_write_meta() {
  local f="$1"; shift
  local rev drv cpu_model
  rev="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  if [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then rev="$rev-dirty"; fi
  drv=""
  if command -v ethtool >/dev/null; then drv="$(ethtool -i "$IFACE" 2>/dev/null | awk '/^driver:/ { print $2 }')"; fi
  [ -z "$drv" ] && [ -e "/sys/class/net/$IFACE/device/driver" ] && drv="$(basename "$(readlink -f "/sys/class/net/$IFACE/device/driver")")"
  cpu_model="$(awk -F': *' '/^model name/ { print $2; exit }' /proc/cpuinfo)"
  {
    echo "date=$(date -Iseconds)"
    echo "git_rev=$rev"
    echo "kernel=$(uname -r)"
    echo "cpu_model=${cpu_model:-$(uname -m)}"
    echo "nproc=$(nproc)"
    echo "interface=$IFACE"
    echo "driver=$drv"
    echo "mode=$MODE"
    echo "generator=$GENERATOR"
    echo "rule_action=$RULE_ACTION"
    echo "duration=$DURATION"
    echo "src_ip=$SRC_IP"
    echo "dst_ip=$DST_IP"
    echo "daemon_reused=$DAEMON_REUSED"
    local kv; for kv in "$@"; do echo "$kv"; done
  } >"$f"
}

# print_table <csv> : 사람이 읽기 좋게
print_table() { if command -v column >/dev/null; then column -s, -t <"$1"; else cat "$1"; fi; }
