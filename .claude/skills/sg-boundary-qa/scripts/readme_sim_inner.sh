#!/bin/bash
# readme_check.sh 가 컨테이너 안에서 실행하는 본체. README 명령을 바꾸면 이 파일의 해당 단계도 같이 고친다.
set -u
step(){ echo; echo "######## $*"; }
fail(){ echo "!!!!!!!! README STEP FAILED: $*"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq sudo git >/dev/null      # (컨테이너 전용: 실제 Ubuntu엔 sudo 있음)
useradd -m -s /bin/bash u && echo "u ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/u
mkdir -p /home/u/swift-guard && (cd /src && git config --global --add safe.directory /src && git ls-files -co --exclude-standard | while read -r f; do [ -e "$f" ] && echo "$f"; done | tar -cf - -T - ) | tar -xpf - -C /home/u/swift-guard
chown -R u:u /home/u
cat > /home/u/run.sh <<'USR'
set -u
fail(){ echo "!!!!!!!! README STEP FAILED: $*"; exit 1; }
step(){ echo; echo "######## $*"; }
step "4-1 packages"
sudo apt update -qq >/dev/null 2>&1
sudo apt install -y -qq build-essential clang llvm libelf-dev libbpf-dev zlib1g-dev pkg-config git curl ca-certificates iproute2 iputils-ping python3 >/dev/null 2>&1 || fail "apt install"
clang --version | head -1; ls /usr/include/bpf/bpf_helpers.h || fail "bpf_helpers.h"
step "4-2 rust"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q >/dev/null 2>&1 || fail rustup
source "$HOME/.cargo/env"; cargo --version || fail cargo
step "4-3 (clone simulated: working tree copied)"; cd ~/swift-guard || fail cd
step "4-4 make build"
make build >/tmp/build.log 2>&1 || { tail -30 /tmp/build.log; fail "make build"; }
grep -i "skipping WASM" /tmp/build.log
ls -l src/bpf/xdp_filter.o target/release/xdp-filter target/release/swift-guard-daemon || fail "build outputs"
step "4-6 sudo make install"
sudo make install >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "sudo make install"; }
grep -E "skipping|Installation complete|No built WASM" /tmp/install.log
step "5-1"
xdp-filter --version || fail version; xdp-filter --help | head -4; swift-guard-daemon --help | head -3
step "5-2 e2e"
sudo tools/test/e2e_check.sh 2>&1 | grep -E "^\[FAIL|e2e_check:|RESULT" ; sudo tools/test/e2e_check.sh >/dev/null 2>&1 || fail "e2e_check"
step "6 tutorial"
sudo tools/test/lab.sh up || fail "lab up"
sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o >/tmp/d.log 2>&1 &
sleep 2
xdp-filter attach sg-lab0 --mode generic || fail attach
[ "$(sudo tools/test/lab.sh ping 10.200.0.2)" = OK ] || fail "ping before"
[ "$(sudo tools/test/lab.sh http 10.200.0.2)" = OK ] || fail "http before"
xdp-filter add-rule --src-ip 10.200.0.2 --action drop --label my-first-rule || fail add
[ "$(sudo tools/test/lab.sh ping 10.200.0.2)" = BLOCKED ] || fail "blocked"
[ "$(sudo tools/test/lab.sh ping 10.200.0.3)" = OK ] || fail "other ok"
xdp-filter list-rules --stats
xdp-filter delete-rule --label my-first-rule || fail del
[ "$(sudo tools/test/lab.sh ping 10.200.0.2)" = OK ] || fail "restored"
xdp-filter detach sg-lab0 || fail detach
sudo pkill -INT -f swift-guard-daemon; sleep 1
sudo tools/test/lab.sh down
step "4-5 wasm + reinstall"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || fail "rustup target"
make build-wasm >/tmp/w.log 2>&1 || { tail /tmp/w.log; fail build-wasm; }
ls wasm/modules/*.wasm || fail "wasm out"
sudo make install >/dev/null 2>&1 || fail reinstall
ls /usr/local/lib/swift-guard/wasm/ || fail "wasm installed"
step "examples.sh (installed binaries, incl. 12-1 wasm load from /usr/local)"
sudo tools/test/examples.sh 2>&1 | grep -E "FAIL|SKIP|examples:|RESULT"; sudo tools/test/examples.sh >/dev/null 2>&1 || fail examples
step "15 uninstall"
sudo make uninstall >/tmp/un.log 2>&1 || { cat /tmp/un.log; fail uninstall; }
ls /usr/local/bin/xdp-filter /usr/local/bin/swift-guard-daemon /usr/local/lib/swift-guard 2>/dev/null && fail "still installed" || echo "uninstalled OK"
echo; echo "######## README SIMULATION: ALL STEPS OK"
USR
chown u:u /home/u/run.sh
su - u -c "bash /home/u/run.sh"
