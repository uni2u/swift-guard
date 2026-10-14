#!/usr/bin/env bash
# README 초급자 경로 검증: 깨끗한 Ubuntu 컨테이너에서 sudo 가능한 일반 사용자로 README 4~6장, 4-5(WASM),
# 예시 회귀(examples.sh), 15장(제거)을 그대로 실행한다. README의 설치/사용 명령을 바꾸면 반드시 실행.
# 사용법: readme_check.sh [ubuntu 버전...]   (기본: 22.04 24.04, 병렬)
# 소요: 버전당 약 10~15분(rustup + 첫 빌드). 종료 코드: 0 = 전 버전 ALL STEPS OK
set -uo pipefail
ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
HERE="$(cd "$(dirname "$0")" && pwd)"
VERS=("$@"); [ ${#VERS[@]} -eq 0 ] && VERS=(22.04 24.04)
docker info >/dev/null 2>&1 || { echo "SKIP: docker daemon not available" >&2; exit 3; }
LOGDIR="$(mktemp -d)"; rc=0
for v in "${VERS[@]}"; do
  ( docker run --rm --privileged --platform linux/amd64 -v "$ROOT":/src:ro -v "$HERE":/s:ro "ubuntu:$v" \
      bash /s/readme_sim_inner.sh >"$LOGDIR/$v.log" 2>&1; echo "exit=$?" >>"$LOGDIR/$v.log" ) &
done
wait
for v in "${VERS[@]}"; do
  echo "===== Ubuntu $v  (log: $LOGDIR/$v.log)"
  grep -E "^########|!!!!|e2e_check:|examples:|uninstalled|ALL STEPS OK" "$LOGDIR/$v.log"
  grep -q "ALL STEPS OK" "$LOGDIR/$v.log" || rc=1
done
exit $rc
