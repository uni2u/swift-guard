#!/usr/bin/env bash
# 커널 pktgen 으로 UDP 트래픽 송신 (송신 장비용, 단독 실행 가능). Swift-Guard 저장소의 다른 파일이 필요 없다.
#
# 사용법: sudo pktgen_tx.sh --dev <tx-nic> --dst-ip <ip> --dst-mac <mac> [--src-ip <ip>]
#                           [--size 64] [--duration 10] [--threads 1]
#   --dev       송신 인터페이스 (DUT NIC와 직결된 NIC, 또는 veth peer)
#   --dst-ip    목적지 IP (DUT 인터페이스 IP)
#   --dst-mac   목적지 MAC (DUT 인터페이스 MAC — 스위치/직결 모두 L2 목적지가 맞아야 DUT가 받는다)
#   --src-ip    출발지 IP (DUT의 매치 룰 --src-ip 와 같게. 생략하면 --dev 의 주소)
#   --size      FCS 포함 L2 프레임 크기 64–1518 (기본 64, pktgen pkt_size = size - 4)
#   --duration  송신 시간(초, 기본 10)
#   --threads   pktgen 커널 스레드 수 (기본 1). >1 이면 <dev>@<n> 장치를 스레드마다 추가
# UDP 목적지 포트 9 고정. 끝나면 장치별 "Result:" 줄을 출력한다. Ctrl+C 시에도 stop + rem_device_all.
# 요구: root, 커널 pktgen 모듈(modprobe pktgen). DUT에서는 basic_throughput_test.sh --generator external 로 측정.
set -euo pipefail

DEV=""; DST_IP=""; DST_MAC=""; SRC_IP=""; SIZE=64; DURATION=10; THREADS=1
PG=/proc/net/pktgen
die() { echo "[pktgen_tx] ERROR: $*" >&2; exit 1; }
usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dev|--dst-ip|--dst-mac|--src-ip|--size|--duration|--threads)
      [ $# -ge 2 ] && [ -n "$2" ] || die "$1 에 값이 필요하다"
      case "$1" in
        --dev) DEV=$2 ;; --dst-ip) DST_IP=$2 ;; --dst-mac) DST_MAC=$2 ;; --src-ip) SRC_IP=$2 ;;
        --size) SIZE=$2 ;; --duration) DURATION=$2 ;; --threads) THREADS=$2 ;;
      esac
      shift 2 ;;
    *) die "알 수 없는 옵션: $1 (--help)" ;;
  esac
done

[ -n "$DEV" ] && [ -n "$DST_IP" ] && [ -n "$DST_MAC" ] || { usage >&2; die "--dev, --dst-ip, --dst-mac 은 필수"; }
[[ "$SIZE" =~ ^[0-9]+$ ]] && [ "$SIZE" -ge 64 ] && [ "$SIZE" -le 1518 ] || die "--size 는 64–1518: '$SIZE'"
[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || die "--duration 은 1 이상의 정수: '$DURATION'"
[[ "$THREADS" =~ ^[1-9][0-9]*$ ]] || die "--threads 는 1 이상의 정수: '$THREADS'"
[[ "$DST_MAC" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || die "--dst-mac 형식: aa:bb:cc:dd:ee:ff"
[ "$(id -u)" -eq 0 ] || die "root 필요"
[ -e "/sys/class/net/$DEV" ] || die "인터페이스 없음: $DEV"
modprobe pktgen 2>/dev/null || true
[ -w "$PG/pgctrl" ] || die "커널 pktgen 모듈 없음 (modprobe pktgen 실패) — pktgen 을 지원하는 커널에서 실행하라"
NCPU=$(nproc)
[ "$THREADS" -le "$NCPU" ] || die "--threads $THREADS > CPU 수 $NCPU"

# pgset <file> <cmd...> : 명령을 쓰고 "Result: OK" 확인 (pgctrl 은 결과 줄이 없다)
pgset() {
  local f="$1"; shift
  echo "$*" >"$f" || die "pktgen 쓰기 실패: $f <- $*"
  if [ "$f" != "$PG/pgctrl" ] && ! grep -q "Result: OK" "$f"; then
    grep "Result:" "$f" >&2 || true
    die "pktgen 명령 거부: $f <- $*"
  fi
}

DEVS=()
cleanup() {
  set +e
  echo stop >"$PG/pgctrl" 2>/dev/null
  [ -n "${START_PID:-}" ] && wait "$START_PID" 2>/dev/null
  for t in $(seq 0 $((THREADS - 1))); do echo rem_device_all >"$PG/kpktgend_$t" 2>/dev/null; done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for t in $(seq 0 $((THREADS - 1))); do
  pgset "$PG/kpktgend_$t" rem_device_all
  if [ "$THREADS" -gt 1 ]; then d="$DEV@$t"; else d="$DEV"; fi
  pgset "$PG/kpktgend_$t" "add_device $d"
  DEVS+=("$d")
  f="$PG/$d"
  pgset "$f" "count 0"
  pgset "$f" "clone_skb 0"
  pgset "$f" "pkt_size $((SIZE - 4))"
  pgset "$f" "delay 0"
  pgset "$f" "dst $DST_IP"
  pgset "$f" "dst_mac $DST_MAC"
  if [ -n "$SRC_IP" ]; then pgset "$f" "src_min $SRC_IP"; pgset "$f" "src_max $SRC_IP"; fi
  pgset "$f" "udp_dst_min 9"
  pgset "$f" "udp_dst_max 9"
done

echo "[pktgen_tx] $DEV x$THREADS → $DST_IP ($DST_MAC) src=${SRC_IP:-<dev addr>} size=${SIZE}B (pkt_size $((SIZE - 4))) ${DURATION}s"
echo start >"$PG/pgctrl" &      # start 는 stop 될 때까지 블록된다
START_PID=$!
sleep "$DURATION"
echo stop >"$PG/pgctrl"
wait "$START_PID" 2>/dev/null || true
START_PID=""
for d in "${DEVS[@]}"; do
  echo "== $d =="
  grep -A2 "Result:" "$PG/$d" || true
done
