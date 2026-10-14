#!/usr/bin/env bash
# Swift-Guard 실습 랩: 물리 NIC 없이 예제를 따라 해 볼 수 있는 가상 네트워크
#
#   [netns sg-lab]  sg-lab-c0  10.200.0.2 .3 .4 .5  (클라이언트 4대 역할)
#                        ║ veth
#   [root ns]       sg-lab0    10.200.0.1           ← XDP를 붙이는 인터페이스
#                   서버: HTTP :8080 (python), UDP echo :5353 (python)
#                   sg-lab-insp0 ══veth══ sg-lab-insp1  ← redirect 대상("검사 인터페이스")
#
# 사용법 (root):
#   lab.sh up | down | status
#   lab.sh ping <src-ip>             # 클라이언트 → 10.200.0.1 ICMP 3회, 성공/실패 출력
#   lab.sh http <src-ip> [port]      # 클라이언트 → http://10.200.0.1:<port>/ (기본 8080)
#   lab.sh udp  <src-ip> [port]      # 클라이언트 → UDP echo (기본 5353)
#   lab.sh syn  <src-ip> [port]      # TCP 연결만 시도 (SYN 차단 확인용)
#   lab.sh insp-rx                   # 검사 인터페이스가 받은 패킷 수
# 각 트래픽 명령은 성공 시 "OK", 실패 시 "BLOCKED"를 출력하고 종료 코드 0/1을 돌려준다.
# 필요: iproute2, iputils-ping, curl, python3
set -uo pipefail

NS=sg-lab; DUT=sg-lab0; CLI_IF=sg-lab-c0; INSP0=sg-lab-insp0; INSP1=sg-lab-insp1
SERVER_IP=10.200.0.1; CLIENTS="10.200.0.2 10.200.0.3 10.200.0.4 10.200.0.5"
RUN=/run/sg-lab; mkdir -p "$RUN" 2>/dev/null || RUN=/tmp/sg-lab
mkdir -p "$RUN"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "root 필요: sudo $0 ..." >&2; exit 2; }; }
in_ns() { ip netns exec "$NS" "$@"; }
result() { if [ "$1" -eq 0 ]; then echo "OK"; return 0; else echo "BLOCKED"; return 1; fi; }

up() {
  down >/dev/null 2>&1
  ip netns add "$NS"
  ip link add "$DUT" type veth peer name "$CLI_IF"
  ip link set "$CLI_IF" netns "$NS"
  ip addr add "$SERVER_IP/24" dev "$DUT"; ip link set "$DUT" up
  for ip in $CLIENTS; do ip -n "$NS" addr add "$ip/24" dev "$CLI_IF"; done
  ip -n "$NS" link set "$CLI_IF" up; ip -n "$NS" link set lo up
  ip link add "$INSP0" type veth peer name "$INSP1"
  ip link set "$INSP0" up; ip link set "$INSP1" up

  python3 -m http.server 8080 --bind "$SERVER_IP" --directory "$RUN" >"$RUN/http.log" 2>&1 &
  echo $! >"$RUN/http.pid"
  python3 - "$SERVER_IP" >"$RUN/udp.log" 2>&1 <<'PY' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 5353))
while True:
    d, a = s.recvfrom(2048)
    s.sendto(d, a)
PY
  echo $! >"$RUN/udp.pid"
  echo "swift-guard lab" >"$RUN/index.html"
  sleep 0.5
  echo "lab up: XDP 대상 인터페이스 = $DUT, 서버 = $SERVER_IP (HTTP 8080, UDP 5353), 클라이언트 = $CLIENTS, redirect 대상 = $INSP0"
}

down() {
  for p in http udp; do [ -f "$RUN/$p.pid" ] && kill "$(cat "$RUN/$p.pid")" 2>/dev/null; rm -f "$RUN/$p.pid"; done
  ip link set dev "$DUT" xdpgeneric off 2>/dev/null; ip link set dev "$DUT" xdp off 2>/dev/null
  ip link del "$DUT" 2>/dev/null; ip link del "$INSP0" 2>/dev/null; ip netns del "$NS" 2>/dev/null
  echo "lab down"
}

status() {
  ip netns list | grep -qw "$NS" && echo "netns $NS: up" || echo "netns $NS: down"
  ip -d link show dev "$DUT" 2>/dev/null | grep -oE 'xdp(generic)?(/id:[0-9]+)?|prog/xdp id [0-9]+' | head -1 | sed 's/^/XDP on '"$DUT"': /' \
    || echo "XDP on $DUT: none"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  up)     need_root; up ;;
  down)   need_root; down ;;
  status) status ;;
  ping)   need_root; in_ns ping -c 3 -i 0.2 -W 1 -I "${1:?src-ip}" "$SERVER_IP" >/dev/null 2>&1; result $? ;;
  http)   need_root; in_ns curl -s -o /dev/null -m 2 --interface "${1:?src-ip}" "http://$SERVER_IP:${2:-8080}/"; result $? ;;
  syn)    need_root; in_ns curl -s -o /dev/null -m 2 --interface "${1:?src-ip}" "telnet://$SERVER_IP:${2:-8080}" </dev/null; rc=$?
          # telnet:// 은 연결 성공 후 EOF로 끝나면 0, 연결 실패/타임아웃이면 7/28
          result $rc ;;
  udp)    need_root; in_ns python3 - "${1:?src-ip}" "$SERVER_IP" "${2:-5353}" <<'PY'; result $?
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
  *) sed -n '2,20p' "$0"; exit 2 ;;
esac
