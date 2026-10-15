#!/usr/bin/env bash
# BPF 단위 검증: privileged Docker에서 xdp_filter.o를 Makefile로 빌드한 뒤 verifier 로드 + PROG_TEST_RUN으로
# 파싱·매칭·카운터 의미(IHL/조각/tiny fragment/src→dst 우선/결과 카운터)를 케이스별로 검증한다.
# daemon 없이 커널만으로 도는 가장 빠른 BPF 회귀 검사. src/bpf, include 변경 시 실행.
# 종료 코드: 0 PASS / 1 FAIL / 3 docker 없음
set -uo pipefail
ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
HERE="$(cd "$(dirname "$0")" && pwd)"
docker info >/dev/null 2>&1 || { echo "SKIP: docker daemon not available" >&2; exit 3; }
IMG=$(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep '^sg-linux-check-v4' | head -1)
[ -n "$IMG" ] || { echo "run linux_check.sh once first (builds sg-linux-check-v4 image)"; exit 1; }
docker run --rm --privileged --platform linux/amd64 -v "$ROOT":/src:ro -v "$HERE":/h:ro "$IMG" bash -c '
  set -e; mkdir /w && cd /src && git ls-files -co --exclude-standard | while read -r f; do [ -e "$f" ] && echo "$f"; done | tar -cf - -T - | tar -xf - -C /w
  if ! make -C /w/src/bpf -s >/tmp/make.log 2>&1; then echo "BPF BUILD FAILED:"; cat /tmp/make.log; exit 1; fi
  python3 /h/bpf_prog_test_run.py /w/src/bpf/xdp_filter.o'
