#!/usr/bin/env bash
# Docker 기반 Linux 빌드 검증: BPF 오브젝트 컴파일 + cargo check/test --workspace.
# macOS에서는 libbpf-sys가 빌드되지 않으므로 daemon 크레이트 검증은 이 스크립트로만 가능하다.
# XDP 실제 로드/트래픽 테스트는 하지 않는다(물리 NIC/권한 필요 → 사용자 Linux 장비에서 수행).
#
# 사용법: linux_check.sh [bpf|cargo|test|all|e2e|examples]   (기본: all)
#   examples: --privileged 컨테이너에서 tools/test/examples.sh (docs/examples.md 예제 회귀 검증).
#   e2e: --privileged 컨테이너에서 release 빌드 후 tools/test/e2e_check.sh 실행(veth+netns+generic XDP).
#        x86_64 Docker Desktop(커널 7.x linuxkit)에서 BPF 로드/attach 동작 확인됨. 커널이 bpf()를 막으면 e2e_check가 실패로 알린다.
# 환경변수: SG_RUST_IMAGE (기본 rust:1.83-bookworm)
#           SG_PLATFORM (기본 linux/amd64 — 논문 타깃(x86_64 Xeon)과 같은 아키텍처. Apple Silicon에선 에뮬레이션이라 느림)
# 한계(항상 "미검증"으로 보고): driver/offload 모드, 물리 NIC 성능(Tier 3).
set -euo pipefail

MODE="${1:-all}"
ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
IMAGE="${SG_RUST_IMAGE:-rust:1.83-bookworm}"
PLATFORM="${SG_PLATFORM:-linux/amd64}"

if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon not available — Linux 검증 불가. 사용자에게 Linux 장비에서 실행할 명령을 전달하라." >&2
  exit 3
fi

# 툴체인을 미리 설치한 로컬 이미지를 1회 빌드해 재사용한다.
# (실행마다 apt를 돌리면 동시 실행 시 공유 apt 캐시 lock 충돌(rc=100)이 난다)
LOCAL_IMAGE="sg-linux-check-v3:$(echo "$IMAGE" | tr ':/' '--')-$(echo "$PLATFORM" | tr '/' '-')"
if ! docker image inspect "$LOCAL_IMAGE" >/dev/null 2>&1; then
  echo "== building $LOCAL_IMAGE (one-time) =="
  docker build -q --platform "$PLATFORM" -t "$LOCAL_IMAGE" - <<EOF >/dev/null
FROM $IMAGE
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang llvm libelf-dev libbpf-dev linux-libc-dev zlib1g-dev pkg-config make iproute2 iputils-ping bpftool procps curl python3 >/dev/null && rm -rf /var/lib/apt/lists/*
EOF
fi

read -r -d '' INNER <<'EOS' || true
set -e
ARCH_INC="/usr/include/$(uname -m)-linux-gnu"
case "$MODE" in bpf|all)
  echo "== BPF compile =="
  # README/Makefile 경로 그대로 빌드한다(직접 clang 호출은 Makefile 플래그 누락을 못 잡는다)
  rm -rf /tmp/bpfb && mkdir -p /tmp/bpfb && cp -r src include /tmp/bpfb/ && make -C /tmp/bpfb/src/bpf -s
  O=/tmp/bpfb/src/bpf/xdp_filter.o
  llvm-objdump -h "$O" | grep -E "xdp|maps|license|\.BTF"
  llvm-objdump -h "$O" | grep -q "\.BTF" || { echo "BTF section missing (libbpf will refuse BTF-defined maps)"; exit 1; }
  echo "BPF OK";;
esac
case "$MODE" in cargo|all)
  echo "== cargo check --workspace =="
  cargo check --workspace --all-targets --target-dir /target 2>&1 | grep -E "^(error|warning: unused)|^error\[|could not compile|Finished" || true
  cargo check --workspace --target-dir /target -q;;
esac
case "$MODE" in cargo|all)
  echo "== cargo build (default-members → 배포 바이너리 존재 확인) =="
  cargo build --target-dir /target -q
  for b in xdp-filter swift-guard-daemon; do test -x /target/debug/$b && echo "bin OK: $b" || { echo "bin MISSING: $b"; exit 1; }; done;;
esac
case "$MODE" in test|all)
  echo "== cargo test --workspace (ignored 제외) =="
  cargo test --workspace --target-dir /target -q;;
esac
EOS

if [ "$MODE" = e2e ] || [ "$MODE" = examples ]; then
  SCRIPT=tools/test/e2e_check.sh; [ "$MODE" = examples ] && SCRIPT=tools/test/examples.sh
  # 저장소를 쓰기 가능하게 마운트하지 않는다: 작업 트리를 컨테이너 내부로 복사해 빌드/실행.
  docker run --rm --privileged --platform "$PLATFORM" \
    -v "$ROOT":/src:ro \
    -v sg-cargo-registry:/usr/local/cargo/registry \
    -v sg-target:/target \
    -e SCRIPT="$SCRIPT" \
    "$LOCAL_IMAGE" bash -c '
      set -e
      mkdir /work && cd /src && git ls-files -co --exclude-standard | while read -r f; do [ -e "$f" ] && echo "$f"; done | tar -cf - -T - | tar -xf - -C /work
      cd /work && make -C src/bpf -s && cargo build --release -q --target-dir /target
      # WASM 예제용 모듈: 컨테이너 툴체인에만 wasm32 타깃을 추가해 빌드(실패해도 계속, 해당 단계는 SKIP)
      (rustup target add wasm32-unknown-unknown >/dev/null 2>&1 && cd wasm && ./build.sh >/dev/null 2>&1) || echo "wasm build skipped"
      mkdir -p target && ln -s /target/release target/release
      "$SCRIPT" "$@"' _ "${@:2}"
  exit $?
fi

docker run --rm --platform "$PLATFORM" \
  -v "$ROOT":/src -w /src \
  -v sg-cargo-registry:/usr/local/cargo/registry \
  -v sg-target:/target \
  -e MODE="$MODE" \
  "$LOCAL_IMAGE" bash -c "$INNER"
