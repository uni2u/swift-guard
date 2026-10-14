#!/usr/bin/env bash
# README 10장(systemd 운영) 검증: systemd를 init으로 띄운 Ubuntu 24.04 컨테이너에서
# make install → enable --now → override(-i, ExecStartPost rules.sh) → attach/룰 적용 → stop 시 detach
# → 재시작 시 룰 재적용 → make uninstall 을 실행한다. README 10장이나 service 파일/Makefile을 바꾸면 실행.
# 종료 코드: 0 = ALL OK, 1 = 실패, 3 = docker 없음
set -uo pipefail
ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
docker info >/dev/null 2>&1 || { echo "SKIP: docker daemon not available" >&2; exit 3; }
ART="$(mktemp -d)"; trap 'docker rm -f sg-sd-check >/dev/null 2>&1; rm -rf "$ART"' EXIT
BUILD_IMG=$(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep '^sg-linux-check-v4' | head -1)
[ -n "$BUILD_IMG" ] || { echo "run linux_check.sh once first (builds sg-linux-check-v4 image)"; exit 1; }
echo "== build artifacts"
docker run --rm --platform linux/amd64 -v "$ROOT":/src:ro -v sg-cargo-registry:/usr/local/cargo/registry -v sg-target:/target -v "$ART":/art "$BUILD_IMG" bash -c '
  set -e; mkdir /work && cd /src && git ls-files -co --exclude-standard | while read -r f; do [ -e "$f" ] && echo "$f"; done | tar -cf - -T - | tar -xf - -C /work
  cd /work && make -C src/bpf -s >/dev/null && cargo build --release -q --target-dir /target 2>/dev/null
  cp /target/release/xdp-filter /target/release/swift-guard-daemon src/bpf/xdp_filter.o /art/' || exit 1
if ! docker image inspect sg-systemd-test:24.04 >/dev/null 2>&1; then
  echo "== building sg-systemd-test:24.04 (one-time)"
  docker run -d --name sg-sd-prep --platform linux/amd64 ubuntu:24.04 sleep infinity >/dev/null
  docker exec sg-sd-prep bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus iproute2 make git iputils-ping' >/dev/null
  docker commit sg-sd-prep sg-systemd-test:24.04 >/dev/null; docker rm -f sg-sd-prep >/dev/null
fi
docker run -d --name sg-sd-check --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --platform linux/amd64 \
  -v "$ROOT":/src:ro -v "$ART":/art:ro --tmpfs /run --tmpfs /run/lock sg-systemd-test:24.04 /lib/systemd/systemd >/dev/null
sleep 4
OUT="$(docker exec -i sg-sd-check bash -s 2>&1 <<'IN'
set -u; fail(){ echo "!!!! FAIL: $*"; journalctl -u swift-guard --no-pager -n 30; exit 1; }
xdp_on(){ ip -d link show enp1s0 | grep -qE "xdp(generic)?[ /]|prog/xdp"; }
systemctl is-system-running --wait >/dev/null 2>&1
mkdir -p /root/sg && cd /src && git config --global --add safe.directory /src && git ls-files -co --exclude-standard | while read -r f; do [ -e "$f" ] && echo "$f"; done | tar -cf - -T - | tar -xf - -C /root/sg
cd /root/sg && mkdir -p target/release && cp /art/xdp-filter /art/swift-guard-daemon target/release/ && cp /art/xdp_filter.o src/bpf/
make install >/dev/null 2>&1 && [ -f /etc/systemd/system/swift-guard.service ] || fail "make install / service file"
ip link add enp1s0 type veth peer name enp1s0p; ip link set enp1s0 up; ip link set enp1s0p up
# README 10장의 rules.sh 블록을 그대로 추출해 사용
awk '/^#!\/bin\/bash$/{f=1} f{print} /^exit 0$/{if(f){exit}}' README.md > /etc/swift-guard/rules.sh
grep -q "xdp-filter" /etc/swift-guard/rules.sh || fail "could not extract rules.sh from README"
chmod +x /etc/swift-guard/rules.sh
systemctl enable --now swift-guard >/dev/null 2>&1; sleep 2; systemctl is-active -q swift-guard || fail "enable --now"
mkdir -p /etc/systemd/system/swift-guard.service.d
# README 10장의 마지막 [Service] override 블록(ExecStartPost 포함)을 그대로 추출
awk '/^```ini$/{buf=""; f=1; next} /^```$/{if(f){last=buf}; f=0; next} f{buf=buf $0 "\n"} END{printf "%s", last}' README.md > /etc/systemd/system/swift-guard.service.d/override.conf
grep -q ExecStartPost /etc/systemd/system/swift-guard.service.d/override.conf || fail "override extract"
systemctl daemon-reload; systemctl restart swift-guard; sleep 3
systemctl is-active -q swift-guard || fail "active after override"
xdp_on || fail "-i attach"
R=$(xdp-filter list-rules | grep -cE "block-bad-net|guard-ssh"); [ "$R" -eq 2 ] || fail "ExecStartPost rules ($R)"
systemctl stop swift-guard; sleep 2; xdp_on && fail "XDP left after stop"
systemctl start swift-guard; sleep 3; R=$(xdp-filter list-rules | grep -cE "block-bad-net|guard-ssh"); [ "$R" -eq 2 ] || fail "rules after restart"
make uninstall >/dev/null 2>&1; sleep 1; xdp_on && fail "XDP left after uninstall"
[ -e /usr/local/bin/xdp-filter ] && fail "binary left after uninstall"
echo "SYSTEMD CHAPTER 10: ALL OK"
IN
)"
echo "$OUT" | tail -40
# 본체가 실제로 끝까지 실행됐는지 확인 (stdin 미전달 같은 거짓 통과 방지)
echo "$OUT" | grep -q "SYSTEMD CHAPTER 10: ALL OK" || exit 1
