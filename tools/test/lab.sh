#!/usr/bin/env bash
# Swift-Guard 실습 랩: 물리 NIC 없이 예제를 따라 해 볼 수 있는 가상 네트워크
#
#   [netns sg-lab]  sg-lab-c0  10.200.0.2 .3 .4 .5  (클라이언트 4대 역할)
#                        ║ veth
#   [root ns]       sg-lab0    10.200.0.1, 10.200.0.11   ← XDP를 붙이는 인터페이스 (서버 IP 2개)
#                   서버(두 IP 각각): HTTP :8080 (python), UDP echo :5353 (python)
#                   sg-lab-insp0 ══veth══ sg-lab-insp1  ← redirect 대상("검사 인터페이스")
#
# 사용법 (root):
#   lab.sh up | down | status
#   lab.sh [--to <dst>] ping <src-ip>          # 클라이언트 → <dst> ICMP 3회, 성공/실패 출력
#   lab.sh [--to <dst>] http <src-ip> [port]   # 클라이언트 → http://<dst>:<port>/ (기본 8080)
#   lab.sh [--to <dst>] udp  <src-ip> [port]   # 클라이언트 → UDP echo (기본 5353)
#   lab.sh [--to <dst>] syn  <src-ip> [port]   # TCP 연결만 시도 (SYN 차단 확인용)
#   lab.sh insp-rx                             # 검사 인터페이스가 받은 패킷 수
#   lab.sh [--to <dst>] flood <src-ip> <seconds> [frame-size]
#                     # <dst>:9 로 UDP를 <seconds>초 동안 최대한 빨리 송신 (tools/bench 흐름 검증용).
#                     # frame-size = FCS 포함 L2 프레임 크기 64–1518 (기본 64, UDP payload = frame-size - 46).
#                     # python 송신이라 성능 수치가 아니다. 마지막 줄: "sent <n> packets in <s>s"
# --to: 목적지 서버 IP. 10.200.0.1(기본) 또는 10.200.0.11만 허용.
# ping/http/udp/syn 은 성공 시 "OK", 실패 시 "BLOCKED"를 출력하고 종료 코드 0/1을 돌려준다.
# 필요: iproute2, iputils-ping, curl, python3
set -uo pipefail

NS=sg-lab; DUT=sg-lab0; CLI_IF=sg-lab-c0; INSP0=sg-lab-insp0; INSP1=sg-lab-insp1
SERVER_IP=10.200.0.1; SERVER_IP2=10.200.0.11; CLIENTS="10.200.0.2 10.200.0.3 10.200.0.4 10.200.0.5"
RUN=/run/sg-lab; mkdir -p "$RUN" 2>/dev/null || RUN=/tmp/sg-lab
mkdir -p "$RUN"

usage() { sed -n '2,23p' "$0"; exit 2; }
need_root() { [ "$(id -u)" -eq 0 ] || { echo "root 필요: sudo $0 ..." >&2; exit 2; }; }
in_ns() { ip netns exec "$NS" "$@"; }
result() { if [ "$1" -eq 0 ]; then echo "OK"; return 0; else echo "BLOCKED"; return 1; fi; }

# start_servers <ip> <suffix>: HTTP :8080, UDP echo :5353 을 <ip>에 바인드. pid 파일 http<suffix>.pid / udp<suffix>.pid
start_servers() {
  local ip=$1 sfx=$2
  python3 -m http.server 8080 --bind "$ip" --directory "$RUN" >"$RUN/http$sfx.log" 2>&1 &
  echo $! >"$RUN/http$sfx.pid"
  python3 - "$ip" >"$RUN/udp$sfx.log" 2>&1 <<'PY' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 5353))
while True:
    d, a = s.recvfrom(2048)
    s.sendto(d, a)
PY
  echo $! >"$RUN/udp$sfx.pid"
}

up() {
  down >/dev/null 2>&1
  ip netns add "$NS"
  ip link add "$DUT" type veth peer name "$CLI_IF"
  ip link set "$CLI_IF" netns "$NS"
  ip addr add "$SERVER_IP/24" dev "$DUT"; ip addr add "$SERVER_IP2/24" dev "$DUT"; ip link set "$DUT" up
  for ip in $CLIENTS; do ip -n "$NS" addr add "$ip/24" dev "$CLI_IF"; done
  ip -n "$NS" link set "$CLI_IF" up; ip -n "$NS" link set lo up
  ip link add "$INSP0" type veth peer name "$INSP1"
  ip link set "$INSP0" up; ip link set "$INSP1" up

  # 서버 IP마다 HTTP/UDP 서버를 하나씩 띄운다 (0.0.0.0 바인드는 쓰지 않는다)
  start_servers "$SERVER_IP" ""
  start_servers "$SERVER_IP2" 2
  echo "swift-guard lab" >"$RUN/index.html"
  sleep 0.5
  echo "lab up: XDP 대상 인터페이스 = $DUT, 서버 = $SERVER_IP $SERVER_IP2 (HTTP 8080, UDP 5353), 클라이언트 = $CLIENTS, redirect 대상 = $INSP0"
}

down() {
  for p in http udp http2 udp2; do [ -f "$RUN/$p.pid" ] && kill "$(cat "$RUN/$p.pid")" 2>/dev/null; rm -f "$RUN/$p.pid"; done
  ip link set dev "$DUT" xdpgeneric off 2>/dev/null; ip link set dev "$DUT" xdp off 2>/dev/null
  ip link del "$DUT" 2>/dev/null; ip link del "$INSP0" 2>/dev/null; ip netns del "$NS" 2>/dev/null
  echo "lab down"
}

status() {
  ip netns list | grep -qw "$NS" && echo "netns $NS: up" || echo "netns $NS: down"
  ip -d link show dev "$DUT" 2>/dev/null | grep -oE 'xdp(generic)?(/id:[0-9]+)?|prog/xdp id [0-9]+' | head -1 | sed 's/^/XDP on '"$DUT"': /' \
    || echo "XDP on $DUT: none"
}

DST=$SERVER_IP
if [ "${1:-}" = "--to" ]; then
  case "${2:-}" in
    "$SERVER_IP"|"$SERVER_IP2") DST=$2 ;;
    *) echo "--to 는 $SERVER_IP 또는 $SERVER_IP2 만 허용: '${2:-}'" >&2; usage ;;
  esac
  shift 2
fi
cmd="${1:-}"; shift || true
case "$cmd" in
  up)     need_root; up ;;
  down)   need_root; down ;;
  status) status ;;
  ping)   need_root; in_ns ping -c 3 -i 0.2 -W 1 -I "${1:?src-ip}" "$DST" >/dev/null 2>&1; result $? ;;
  http)   need_root; in_ns curl -s -o /dev/null -m 2 --interface "${1:?src-ip}" "http://$DST:${2:-8080}/"; result $? ;;
  syn)    need_root; in_ns curl -s -o /dev/null -m 2 --interface "${1:?src-ip}" "telnet://$DST:${2:-8080}" </dev/null; rc=$?
          # telnet:// 은 연결 성공 후 EOF로 끝나면 0, 연결 실패/타임아웃이면 7/28
          result $rc ;;
  udp)    need_root; in_ns python3 - "${1:?src-ip}" "$DST" "${2:-5353}" <<'PY'; result $?
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0)); s.settimeout(1.0)
ok = False
for _ in range(3):
    s.sendto(b"ping", (sys.argv[2], int(sys.argv[3])))
    try:
        if s.recv(64) == b"ping":
            ok = True; break
    except socket.timeout:
        pass
sys.exit(0 if ok else 1)
PY
          ;;
  insp-rx) cat "/sys/class/net/$INSP1/statistics/rx_packets" ;;
  flood)  need_root
          src="${1:-}"; secs="${2:-}"; fsize="${3:-64}"
          [ -n "$src" ] || usage
          [[ "$secs" =~ ^[1-9][0-9]*$ ]] || { echo "flood: <seconds>는 1 이상의 정수: '$secs'" >&2; usage; }
          { [[ "$fsize" =~ ^[0-9]+$ ]] && [ "$fsize" -ge 64 ] && [ "$fsize" -le 1518 ]; } \
            || { echo "flood: frame-size는 64–1518: '$fsize'" >&2; usage; }
          in_ns python3 - "$src" "$DST" "$secs" "$fsize" <<'PY'
import errno, socket, sys, time
src, dst, secs, fsize = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
payload = b"\x00" * (fsize - 46)          # Ethernet 14 + IPv4 20 + UDP 8 + FCS 4
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
s.setblocking(False)
addr = (dst, 9)
n = 0
t0 = time.monotonic()
end = t0 + secs
while time.monotonic() < end:
    for _ in range(256):
        try:
            s.sendto(payload, addr)
            n += 1
        except OSError as e:          # 큐가 차면 버리고 계속
            if e.errno not in (errno.ENOBUFS, errno.EAGAIN, errno.EWOULDBLOCK, errno.ECONNREFUSED):
                raise
print("sent %d packets in %.1fs" % (n, time.monotonic() - t0))
PY
          ;;
  *) usage ;;
esac
