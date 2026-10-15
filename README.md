# Swift-Guard

**S**ecure **W**ebAssembly **I**nspection **F**ramework for **T**raffic using **Guard**

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange.svg)](https://www.rust-lang.org/)
[![XDP](https://img.shields.io/badge/XDP-enabled-green.svg)](https://www.iovisor.org/technology/xdp)

Swift-Guard는 리눅스 커널의 **XDP(eXpress Data Path)** 로 네트워크 패킷을 아주 이른 단계에서 걸러내는 패킷 필터링·리다이렉트 프레임워크다. 명령 한 줄로 "이 IP에서 오는 트래픽 차단", "이 포트만 차단", "이 트래픽은 검사 장비로 보내기" 같은 룰을 실시간으로 넣고 뺄 수 있다.

> **처음이라면** [3. 시작하기 전에](#3-시작하기-전에) → [4. 설치](#4-설치) → [5. 설치 확인](#5-설치-확인-5분) → [6. 처음 사용해 보기](#6-처음-사용해-보기-10분) 순서로 따라 하면 된다. 모든 단계에 **"이렇게 나오면 성공"** 이 적혀 있다.

---

## 목차

0. [한눈에 보기 (자주 쓰는 명령)](#0-한눈에-보기-자주-쓰는-명령)
1. [Swift-Guard란?](#1-swift-guard란)
2. [동작 구조](#2-동작-구조)
3. [시작하기 전에](#3-시작하기-전에)
4. [설치](#4-설치)
5. [설치 확인 (5분)](#5-설치-확인-5분)
6. [처음 사용해 보기 (10분)](#6-처음-사용해-보기-10분)
7. [명령어 레퍼런스](#7-명령어-레퍼런스)
8. [룰 작성 가이드](#8-룰-작성-가이드)
9. [실제 네트워크 인터페이스에 적용하기](#9-실제-네트워크-인터페이스에-적용하기)
10. [systemd 서비스로 운영하기](#10-systemd-서비스로-운영하기)
11. [설정 파일](#11-설정-파일)
12. [WASM 검사 모듈](#12-wasm-검사-모듈)
13. [테스트와 검증](#13-테스트와-검증)
14. [문제 해결 (FAQ)](#14-문제-해결-faq)
15. [업데이트와 제거](#15-업데이트와-제거)
16. [프로젝트 구조](#16-프로젝트-구조)
17. [성능](#17-성능)
18. [라이선스와 참고 자료](#18-라이선스와-참고-자료)
19. [용어 설명](#19-용어-설명)

---

## 0. 한눈에 보기 (자주 쓰는 명령)

설치를 마친 뒤 자주 쓰는 명령이다. 각 명령의 자세한 설명은 [7. 명령어 레퍼런스](#7-명령어-레퍼런스)에 있다.

```bash
# daemon 시작 (백그라운드) / 상태 / 종료
sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o > /tmp/swift-guard.log 2>&1 &
pidof swift-guard-daemon                       # 숫자(PID)가 나오면 실행 중
sudo kill -INT $(pidof swift-guard-daemon)     # 종료 (붙였던 XDP 자동 해제)

# 인터페이스에 연결 / 해제
xdp-filter attach eth0 --mode generic          # 실제 NIC는 --mode driver 권장 (9장)
xdp-filter detach eth0

# 룰 추가 (출발지 기준 / 목적지 기준)
xdp-filter add-rule --src-ip 203.0.113.7 --action drop --label block-attacker
xdp-filter add-rule --src-ip 203.0.113.0/24 --action drop --label block-net
xdp-filter add-rule --dst-ip 192.0.2.80 --protocol tcp --dst-port 22 --action drop --label guard-ssh

# 조회 / 삭제 / 통계
xdp-filter list-rules --stats
xdp-filter delete-rule --label block-attacker
xdp-filter stats                               # Ctrl+C 로 종료 (룰 매치 총계 + XDP가 본 전체 패킷·결과별 카운터)
xdp-filter stats --count 5                     # 1초 간격 5개 샘플 후 종료
xdp-filter stats --format csv --count 60 > stats.csv   # 1초 간격 60개 샘플(CSV)

# 서비스로 운영 중이라면
sudo systemctl start|stop|restart swift-guard
journalctl -u swift-guard -f
```

---

## 1. Swift-Guard란?

### 할 수 있는 것
| 기능 | 예 |
|------|----|
| 출발지 IP / 대역 차단 | `203.0.113.7` 또는 `203.0.113.0/24`에서 오는 모든 패킷 drop |
| 목적지 IP / 대역 매칭 | 내 서버 IP `192.0.2.80`으로 오는 TCP 80만 차단. 출발지 룰이 매치하지 않을 때 평가된다 |
| 프로토콜·포트 단위 차단 | 특정 호스트의 TCP 8080 접근만 차단, UDP 5353만 차단, 포트 범위 `8000-8100` |
| TCP 플래그 매칭 | 새 연결 시도(SYN)만 차단 |
| 예외 허용 | `/24` 대역은 차단하되 관리자 IP 하나(`/32`)는 허용 |
| 모니터링 | 차단하지 않고 패킷·바이트 수만 집계(`count`) |
| 리다이렉트 | 특정 트래픽을 다른 인터페이스(IDS, 분석 장비 등)로 보냄 |
| 실시간 통계 | 룰별 / 룰 매치 전체 패킷 수, **XDP가 본 전체 패킷(룰과 무관)과 결과별 카운터**(drop/pass/redirect/count/no_match/invalid/non_ipv4/action_error), 초당 패킷 수, 대역폭 |
| WASM 모듈 관리 | WebAssembly 보안 검사 모듈 로드/조회/언로드 |
| 안전한 종료 | daemon이 정상 종료(Ctrl+C, `systemctl stop`)하면 붙였던 XDP를 자동으로 해제 |

### 아직 할 수 없는 것 (현재 버전의 한계)
- 룰 하나는 **출발지 또는 목적지 중 한쪽** prefix만 쓴다(둘을 함께 거는 AND 조건은 불가). 출발지 룰이 항상 먼저 평가된다.
- 같은 출발지 prefix(또는 같은 목적지 prefix)에는 **룰을 하나만** 둘 수 있다.
- `--priority`, `--rate-limit`, `--expire`, `--pkt-len`은 **미구현**이다. `--priority/--rate-limit/--expire`에 0이 아닌 값을 주거나 `--pkt-len`을 지정하면 룰 추가가 **거부**된다([8-3](#8-3-거부되는-입력과-에러-메시지)).
- IPv4만 처리한다. IPv6와 ARP는 그대로 통과한다.
- **VLAN(802.1Q) 태그가 붙은 프레임은 검사 없이 통과한다**(통계의 `non_ipv4`로 집계). NIC의 VLAN 오프로드로 태그가 떼어진 상태로 XDP에 도착하면 검사된다.
- IP 조각(fragment)은 무상태로 처리한다. **후속 조각에는 포트·TCP 플래그 조건 룰이 매치하지 않는다**(IP/프로토콜만 쓰는 룰은 매치). L4 헤더가 잘린 첫 조각(tiny fragment)은 룰과 무관하게 차단한다([8-1](#8-1-매칭-규칙-꼭-알아야-할-것)).
- WASM 모듈은 관리(load/list/stats/unload)만 된다. XDP에서 WASM으로 패킷을 넘기는 경로는 아직 연결되지 않았다.

---

## 2. 동작 구조

```
            ┌───────────────────────── 사용자 공간 ──────────────────────────┐
  사용자 ──▶ │  xdp-filter (CLI)  ──TCP 127.0.0.1:7654──▶  swift-guard-daemon  │
            │                                              │  ├ 룰 관리 (BPF 맵 갱신)
            │                                              │  ├ 통계 수집
            │                                              │  └ WASM 런타임 (wasmtime)
            └──────────────────────────────────────────────┼─────────────────┘
                                                           │ 맵 읽기/쓰기, attach
            ┌──────────────────────── 커널 (XDP) ──────────▼─────────────────┐
  패킷 ────▶ │ xdp_filter.o : 출발지/목적지 룰 조회 → 프로토콜/포트/플래그 확인 │ ──▶ 통과 / 차단 / 리다이렉트
            └───────────────────────────────────────────────────────────────┘
```

| 구성 요소 | 파일 | 역할 |
|----------|------|------|
| XDP 프로그램 | `xdp_filter.o` (C, `src/bpf/`) | 커널에서 패킷마다 실행되어 룰을 적용한다 |
| daemon | `swift-guard-daemon` (Rust, `src/daemon/`) | XDP 프로그램을 로드·연결하고 룰과 통계를 관리한다. **root 권한 필요** |
| CLI | `xdp-filter` (Rust, `src/cli/`) | daemon에 명령을 보낸다. 일반 사용자도 실행할 수 있다 |
| WASM 모듈 | `*.wasm` (`wasm/modules/`) | 선택 기능. 패킷 검사 로직을 플러그인 형태로 제공한다 |

**핵심:** daemon이 먼저 실행 중이어야 CLI 명령이 동작한다.

---

## 3. 시작하기 전에

### 3-1. 요구 사항

| 항목 | 요구 사항 | 확인 명령 |
|------|----------|----------|
| 운영체제 | Linux. **Ubuntu 22.04 / 24.04**, Debian 12 권장 | `cat /etc/os-release` |
| 커널 | **5.10 이상** (5.15 이상 권장) | `uname -r` |
| CPU | x86_64 (arm64는 빌드는 되지만 검증하지 않았다) | `uname -m` |
| 권한 | `sudo`를 쓸 수 있는 계정 | `sudo -v` |
| 디스크 / 메모리 | 여유 공간 약 3GB(빌드용), RAM 2GB 이상 | `df -h ~`, `free -h` |
| 네트워크 | 설치할 때 인터넷 연결 필요(패키지와 Rust 의존성 다운로드) | |
| NIC | **필수 아님.** 처음 사용해 보기와 테스트는 가상 인터페이스로 한다. 실서비스에 붙일 때만 XDP를 지원하는 NIC가 유리하다 | `ip -br link` |

### 3-2. macOS / Windows 사용자
Swift-Guard는 리눅스 커널 기능이라 **리눅스에서만** 동작한다. macOS나 Windows에서는 리눅스 가상머신을 만들어 그 안에서 진행한다.
- macOS: [Multipass](https://multipass.run/) (`multipass launch 22.04 --name sg --disk 20G --memory 4G` → `multipass shell sg`), UTM, Lima
- Windows: Hyper-V나 VirtualBox에 Ubuntu 설치(WSL2는 검증하지 않았다)
- 클라우드 VM(AWS, GCP 등)의 Ubuntu도 된다.

### 3-3. 이 문서의 표기
- `$`로 시작하는 줄은 터미널에 입력하는 명령이다. `$`는 입력하지 않는다. 그 아래 줄은 출력 예시다.
- 출력 중 날짜, 숫자, 버전은 환경마다 다를 수 있다.
- "터미널 1", "터미널 2"라고 하면 터미널 창을 두 개 열어서 쓴다는 뜻이다.

---

## 4. 설치

전체 흐름: **패키지 설치 → Rust 설치 → 소스 받기 → 빌드(`make build`) → 설치(`sudo make install`)**. 약 10~20분 걸린다(대부분 첫 빌드 시간).

### 4-1. 시스템 패키지 설치

```bash
$ sudo apt update
$ sudo apt install -y \
    build-essential clang llvm \
    libelf-dev libbpf-dev zlib1g-dev pkg-config \
    git curl ca-certificates \
    iproute2 iputils-ping python3
```

| 패키지 | 왜 필요한가 |
|--------|------------|
| `clang`, `llvm` | XDP 프로그램(C)을 BPF 바이트코드로 컴파일 |
| `libbpf-dev` | XDP 프로그램이 쓰는 헤더(`bpf/bpf_helpers.h`) |
| `libelf-dev`, `zlib1g-dev`, `pkg-config` | daemon의 libbpf 빌드 |
| `build-essential` | make, gcc 등 기본 빌드 도구 |
| `git`, `curl`, `ca-certificates` | 소스와 Rust 다운로드 |
| `iproute2`, `iputils-ping`, `python3` | 설치 확인과 실습 랩(`tools/test/`)에서 사용 |

**확인**
```bash
$ clang --version | head -1
Ubuntu clang version 14.0.0-1ubuntu1.1      # 10 이상이면 OK
$ ls /usr/include/bpf/bpf_helpers.h
/usr/include/bpf/bpf_helpers.h
```

### 4-2. Rust 설치 (1.78 이상)

배포판의 `apt install rustc`는 버전이 낮을 수 있으므로 **rustup**으로 설치한다. `sudo` 없이 **일반 사용자 계정으로** 실행한다.

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
$ source "$HOME/.cargo/env"
```

**확인**
```bash
$ cargo --version
cargo 1.83.0 (5ffbef321 2024-10-29)        # 1.78 이상이면 OK
```
> 새 터미널을 열었는데 `cargo: command not found`가 나오면 `source "$HOME/.cargo/env"`를 다시 실행한다. 다음부터는 로그인할 때 자동으로 설정된다.

### 4-3. 소스 받기

```bash
$ git clone https://github.com/uni2u/swift-guard.git
$ cd swift-guard
```
이후 모든 명령은 이 `swift-guard` 폴더 안에서 실행한다.

### 4-4. 빌드

**일반 사용자로** 실행한다(`sudo` 없이).
```bash
$ make build
```
처음에는 Rust 의존성을 내려받고 컴파일하느라 몇 분 걸린다.

**확인** — 아래 세 파일이 있으면 성공이다.
```bash
$ ls -l src/bpf/xdp_filter.o target/release/xdp-filter target/release/swift-guard-daemon
-rw-r--r-- 1 user user   ... src/bpf/xdp_filter.o
-rwxr-xr-x 2 user user   ... target/release/swift-guard-daemon
-rwxr-xr-x 2 user user   ... target/release/xdp-filter
```
마지막에 `wasm32-unknown-unknown target not installed: skipping WASM modules (optional).`가 보이는 것은 정상이다. WASM은 선택 기능이다([4-5](#4-5-선택-wasm-모듈-빌드)).

### 4-5. (선택) WASM 모듈 빌드

WASM 검사 모듈을 쓸 때만 필요하다. 건너뛰어도 나머지 기능은 모두 동작한다.
```bash
$ rustup target add wasm32-unknown-unknown
$ make build-wasm
$ ls wasm/modules/*.wasm
wasm/modules/http_inspector.wasm
```

### 4-6. 시스템에 설치

```bash
$ sudo make install
```
설치되는 위치는 다음과 같다.

| 무엇 | 위치 |
|------|------|
| 실행 파일 | `/usr/local/bin/xdp-filter`, `/usr/local/bin/swift-guard-daemon` |
| XDP 프로그램 | `/usr/local/lib/swift-guard/xdp_filter.o` |
| WASM 모듈 (빌드했다면) | `/usr/local/lib/swift-guard/wasm/` |
| 설정 파일 | `/etc/swift-guard/config.yaml` (이미 있으면 덮어쓰지 않음) |
| systemd 서비스 | `/etc/systemd/system/swift-guard.service` (systemd가 없는 환경이면 건너뜀) |

> `sudo make install`은 빌드하지 않는다. `ERROR: ... 가 없습니다. 먼저 일반 사용자로 'make build' 를 실행하세요.`가 나오면 4-4를 먼저 한다.
>
> 설치하지 않고 써도 된다. 그때는 이 문서의 `xdp-filter`를 `./target/release/xdp-filter`로, `swift-guard-daemon`을 `sudo ./target/release/swift-guard-daemon`으로, `/usr/local/lib/swift-guard/xdp_filter.o`를 `src/bpf/xdp_filter.o`로 바꿔 읽는다.

---

## 5. 설치 확인 (5분)

### 5-1. 실행 파일 확인
```bash
$ xdp-filter --version
xdp-filter 0.1.0
$ xdp-filter --help
XDP Filtering Tool

Usage: xdp-filter [OPTIONS] <COMMAND>

Commands:
  attach       XDP 프로그램을 인터페이스에 연결
  detach       XDP 프로그램을 인터페이스에서 분리
  add-rule     필터링 규칙 추가 (--src-ip 또는 --dst-ip 중 하나, prefix당 룰 1개)
  delete-rule  필터링 규칙 삭제
  list-rules   활성 규칙 나열
  stats        성능 통계 표시
  wasm         WASM 검사 모듈 관리
  help         Print this message or the help of the given subcommand(s)
...
$ swift-guard-daemon --help | head -3
Swift-Guard Daemon
...
```

### 5-2. 자동 자가 진단 (권장)
가상 네트워크를 만들어 **XDP 로드부터 차단·통계·리다이렉트·종료 정리까지** 자동으로 점검한다. 실제 네트워크에는 영향이 없고, 끝나면 만든 것을 모두 지운다.
```bash
$ sudo tools/test/e2e_check.sh
...
e2e_check: PASS=69 FAIL=0 SKIP=3
RESULT: ALL PASS
```
- `RESULT: ALL PASS`가 나오면 설치와 커널 기능이 모두 정상이다.
- `SKIP`은 선택 항목이라 괜찮다. 중요한 것은 `FAIL=0`이다. 위 예(4장 절차 그대로 설치한 경우)의 SKIP 3개는 다음과 같다.
  - `bpftool 없음` 2개: verifier 단독 검사와 패킷 파서 단위 검사(PROG_TEST_RUN)를 건너뛴다. 같은 기능은 daemon 로드와 실제 트래픽 단계에서도 확인된다. 모두 돌리려면 bpftool을 설치한다(Ubuntu는 보통 `linux-tools-$(uname -r)` 패키지에 들어 있다).
  - `http_inspector.wasm 없음` 1개: [4-5](#4-5-선택-wasm-모듈-빌드)에서 WASM 모듈을 빌드하면 실행된다.
- `FAIL`이 있으면 출력 끝의 daemon 로그를 보고 [14. 문제 해결](#14-문제-해결-faq)을 참고한다.
- 설치(`make install`)를 하지 않았다면 이 스크립트는 저장소의 `target/release/` 빌드본을 쓴다.

---

## 6. 처음 사용해 보기 (10분)

실제 네트워크를 건드리지 않도록 **가상 실습 랩**에서 진행한다. 랩은 PC 안에 작은 가상 네트워크를 만든다.

```
[가상 클라이언트들]  10.200.0.2  10.200.0.3  10.200.0.4  10.200.0.5
          │ (가상 케이블)
[내 PC]  sg-lab0  10.200.0.1   ← 여기에 Swift-Guard를 붙인다. 웹 서버 :8080, UDP 서버 :5353이 떠 있다
                  10.200.0.11  ← 같은 인터페이스의 두 번째 서버 IP (같은 서비스, 목적지 룰 실습용)
```

### 6-1. 랩 만들기 (터미널 1)
```bash
$ sudo tools/test/lab.sh up
lab up: XDP 대상 인터페이스 = sg-lab0, 서버 = 10.200.0.1 10.200.0.11 (HTTP 8080, UDP 5353), 클라이언트 = 10.200.0.2 10.200.0.3 10.200.0.4 10.200.0.5, redirect 대상 = sg-lab-insp0
```

### 6-2. daemon 실행 (터미널 1)
```bash
$ sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o
[... INFO  swift_guard_daemon] Swift-Guard 데몬 시작 중...
[... INFO  swift_guard_daemon::server] API server listening on 127.0.0.1:7654
```
이 터미널은 daemon 로그를 보여주며 계속 실행된다. **닫지 말고 그대로 둔다.**

### 6-3. 이후 명령은 터미널 2에서
새 터미널을 열고 `swift-guard` 폴더로 이동한다.
```bash
$ cd swift-guard
```

**① 가상 인터페이스에 Swift-Guard 연결**
```bash
$ xdp-filter attach sg-lab0 --mode generic
Success: XDP program attached to sg-lab0 in mode 1
```

**② 아직 룰이 없으니 통신이 된다**
```bash
$ sudo tools/test/lab.sh ping 10.200.0.2
OK
$ sudo tools/test/lab.sh http 10.200.0.2
OK
```

**③ 10.200.0.2를 차단한다**
```bash
$ xdp-filter add-rule --src-ip 10.200.0.2 --action drop --label my-first-rule
Rule added: Rule 'my-first-rule' added successfully
```

**④ 차단됐는지 확인한다**
```bash
$ sudo tools/test/lab.sh ping 10.200.0.2
BLOCKED                                 # 10.200.0.2는 차단됨
$ sudo tools/test/lab.sh ping 10.200.0.3
OK                                      # 다른 호스트는 그대로
```

**⑤ 룰과 통계를 본다**
```bash
$ xdp-filter list-rules --stats
LABEL                ACTION          SOURCE               DEST                 PROTOCOL
------------------------------------------------------------------------------------------
my-first-rule        drop            10.200.0.2           *                    any
  Packets: 3, Bytes: 294
```
`Packets: 3`은 이 룰이 패킷 3개를 막았다는 뜻이다.

**⑥ 룰을 지우면 다시 통신된다**
```bash
$ xdp-filter delete-rule --label my-first-rule
Rule deleted: Rule 'my-first-rule' deleted successfully
$ sudo tools/test/lab.sh ping 10.200.0.2
OK
```

**⑦ 목적지 기준으로 차단해 본다** — 이번에는 "누가 보냈는지"가 아니라 "어느 서버로 가는지"로 막는다. 두 번째 서버 IP(10.200.0.11)의 웹(TCP 8080)만 차단한다.
```bash
$ xdp-filter add-rule --dst-ip 10.200.0.11 --protocol tcp --dst-port 8080 --action drop --label protect-web2
Rule added: Rule 'protect-web2' added successfully
$ sudo tools/test/lab.sh --to 10.200.0.11 http 10.200.0.2
BLOCKED                                 # 10.200.0.11:8080 으로 가는 요청은 차단
$ sudo tools/test/lab.sh --to 10.200.0.11 http 10.200.0.3
BLOCKED                                 # 누가 보내든 같다
$ sudo tools/test/lab.sh http 10.200.0.2
OK                                      # 다른 서버(10.200.0.1)는 그대로
$ xdp-filter delete-rule --label protect-web2
Rule deleted: Rule 'protect-web2' deleted successfully
```
`lab.sh`의 `--to`는 트래픽을 보낼 서버 IP다(생략하면 10.200.0.1).

### 6-4. 정리
```bash
# 터미널 2
$ xdp-filter detach sg-lab0
Success: XDP program detached from sg-lab0
# 터미널 1: Ctrl+C 로 daemon 종료
# 그다음 (아무 터미널에서나)
$ sudo tools/test/lab.sh down
lab down
```

여기까지 됐다면 기본 사용법은 다 익힌 것이다. 포트·대역·SYN 차단, 예외 허용, 모니터링, 리다이렉트, WASM, 목적지(서버 IP) 기준 차단과 출발지 룰 우선 순서 등 **예시 12가지**는 [docs/examples.md](docs/examples.md)에 있다. 같은 랩에서 그대로 따라 할 수 있다.

---

## 7. 명령어 레퍼런스

### 7-1. `swift-guard-daemon` (root로 실행)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-b, --bpf-obj <파일>` | `src/bpf/xdp_filter.o` | XDP 프로그램 경로. **설치본을 쓸 때는 `/usr/local/lib/swift-guard/xdp_filter.o`를 지정한다** |
| `-c, --config <파일>` | `/etc/swift-guard/config.yaml` | 설정 파일. 없으면 기본값으로 실행([11장](#11-설정-파일)) |
| `-i, --interface <이름>` | (없음) | 지정하면 시작할 때 그 인터페이스에 바로 attach. 이때는 `xdp-filter attach`를 다시 하지 않는다 |
| `--api-addr <주소:포트>` | `127.0.0.1:7654` | CLI가 접속할 주소 |
| `-v, --verbose` | | 디버그 로그 출력 |

로그 수준 우선순위: `-v`(debug) > `RUST_LOG` 환경변수(설정돼 있고 비어 있지 않으면) > 설정 파일 `general.log_level` > `info`.

```bash
$ sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o -v      # 디버그 로그
$ sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o -i eth0 # 시작과 동시에 eth0에 연결
```
**백그라운드로 실행하고 종료하기** (서비스로 운영하려면 [10장](#10-systemd-서비스로-운영하기))
```bash
$ sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o > /tmp/swift-guard.log 2>&1 &
$ pidof swift-guard-daemon                    # PID가 출력되면 실행 중
12345
$ tail -f /tmp/swift-guard.log                # 로그 보기 (Ctrl+C로 빠져나옴, daemon은 계속 실행)
$ sudo kill -INT $(pidof swift-guard-daemon)  # 종료
```
- 포그라운드로 실행했다면 `Ctrl+C`로 종료한다. 어떤 방법이든 정상 종료(SIGINT/SIGTERM)하면 붙였던 XDP는 자동으로 해제된다.
- `pkill swift-guard-daemon`은 동작하지 않는다. 프로세스 이름이 15자에서 잘려 `swift-guard-dae`로 보이기 때문이다. `pidof`를 쓴다.

### 7-2. `xdp-filter` (CLI)

공통 옵션: `--api-server <주소:포트>`(기본 `127.0.0.1:7654`), `-v`(상세 로그), `-h`(도움말). 하위 명령마다 `xdp-filter <명령> --help`로 도움말을 볼 수 있다.

| 명령 | 설명 | 예 |
|------|------|----|
| `attach <인터페이스> [--mode driver\|generic\|offload] [--force]` | XDP 연결. 기본 모드는 `driver`. 가상 인터페이스나 드라이버 미지원 NIC는 `generic` | `xdp-filter attach eth0 --mode generic` |
| `detach <인터페이스>` | XDP 해제 | `xdp-filter detach eth0` |
| `add-rule ...` | 룰 추가 (아래 표) | |
| `delete-rule --label <이름>` | 룰 삭제 | `xdp-filter delete-rule --label block-web` |
| `list-rules [--stats]` | 룰 목록. `--stats`를 붙이면 룰별 패킷·바이트 수도 표시 | `xdp-filter list-rules --stats` |
| `stats [--interval <초>] [--count <N>] [--format text\|csv]` | 전체 통계를 `--interval`초(기본 1) 간격으로 출력. `--count N`이면 N개 샘플 후 종료, 생략(0)하면 `Ctrl+C`까지. `Total packets/bytes`는 **룰에 매치한 패킷만** 센다. `XDP rx`는 **XDP가 본 전체 패킷**(룰과 무관), `XDP verdicts`는 결과별 패킷 수다(아래 표). 초당 값은 CLI가 연속 두 샘플의 총계 차이로 계산하며 첫 샘플은 `n/a`. `--format csv`는 17열 고정 헤더 + 샘플당 1행 — 아래 예 | `xdp-filter stats --count 5` |
| `wasm load --name <이름> --file <경로>` | WASM 모듈 로드 | [12장](#12-wasm-검사-모듈) |
| `wasm list` / `wasm stats --name <이름>` / `wasm unload --name <이름>` | 모듈 조회 / 통계 / 언로드 | |

**`stats` 출력 예** (실습 랩에서 `10.200.0.2`에 `--action count` 룰을 넣고, 10.200.0.2(룰 매치)와 10.200.0.3(룰 없음)에서 ping을 보내며 실행한 실측 결과. `Total`은 매치한 .2의 패킷만, `XDP rx`는 .3의 패킷(`no_match`)과 IPv6 등(`non_ipv4`)까지 모두 센다)
```bash
$ xdp-filter stats --count 3
Collecting 3 samples every 1s...
Timestamp: 2026-10-14 09:36:36
Total packets: 5
Total bytes: 490 (0.00 MB)
Packets/sec: n/a
Bandwidth: n/a
XDP rx packets: 9
XDP rx bytes: 770 (0.00 MB)
XDP rx packets/sec: n/a
XDP rx bandwidth: n/a
XDP verdicts: drop=0 pass=0 redirect=0 count=5 no_match=2 invalid=0 non_ipv4=2 action_error=0
----------------------------------------
Timestamp: 2026-10-14 09:36:37
Total packets: 15
Total bytes: 1470 (0.00 MB)
Packets/sec: 10
Bandwidth: 0.01 Mbps
XDP rx packets: 22
XDP rx bytes: 2044 (0.00 MB)
XDP rx packets/sec: 13
XDP rx bandwidth: 0.01 Mbps
XDP verdicts: drop=0 pass=0 redirect=0 count=15 no_match=5 invalid=0 non_ipv4=2 action_error=0
----------------------------------------
Timestamp: 2026-10-14 09:36:38
Total packets: 25
Total bytes: 2450 (0.00 MB)
Packets/sec: 10
Bandwidth: 0.01 Mbps
XDP rx packets: 36
XDP rx bytes: 3416 (0.00 MB)
XDP rx packets/sec: 14
XDP rx bandwidth: 0.01 Mbps
XDP verdicts: drop=0 pass=0 redirect=0 count=25 no_match=9 invalid=0 non_ipv4=2 action_error=0
----------------------------------------
```

```bash
$ xdp-filter stats --format csv --count 3
timestamp_ms,total_packets,total_bytes,pps,mbps,xdp_rx_packets,xdp_rx_bytes,xdp_rx_pps,xdp_rx_mbps,xdp_drop_packets,xdp_pass_packets,xdp_redirect_packets,xdp_count_packets,xdp_no_match_packets,xdp_invalid_packets,xdp_non_ipv4_packets,xdp_action_error_packets
1791970598931,25,2450,,,36,3416,,,0,0,0,25,9,0,2,0
1791970599933,34,3332,9,0.007,49,4662,13,0.010,0,0,0,34,12,0,3,0
1791970600936,44,4312,10,0.008,62,5936,13,0.010,0,0,0,44,15,0,3,0
```
CSV 헤더(17열, 고정):
```
timestamp_ms,total_packets,total_bytes,pps,mbps,xdp_rx_packets,xdp_rx_bytes,xdp_rx_pps,xdp_rx_mbps,xdp_drop_packets,xdp_pass_packets,xdp_redirect_packets,xdp_count_packets,xdp_no_match_packets,xdp_invalid_packets,xdp_non_ipv4_packets,xdp_action_error_packets
```
| 열 | 뜻 |
|----|----|
| `timestamp_ms` | UNIX epoch 밀리초(CLI를 실행한 장비의 시계) |
| `total_packets`, `total_bytes`, `pps`, `mbps` | **룰에 매치한 패킷** 기준 누적값과 초당 값 |
| `xdp_rx_packets`, `xdp_rx_bytes`, `xdp_rx_pps`, `xdp_rx_mbps` | **XDP가 본 전체 패킷**(룰·파싱과 무관, L2 프레임 길이) 기준 누적값과 초당 값. 처리량의 1차 지표 |
| `xdp_drop_packets` … `xdp_count_packets` | 룰 action(drop/pass/redirect/count)으로 처리된 패킷 |
| `xdp_no_match_packets` | 정상 IPv4인데 매치하는 룰이 없어 통과 |
| `xdp_invalid_packets` | 비정상 IPv4 헤더·tiny fragment 등으로 **무조건 차단**([8-1](#8-1-매칭-규칙-꼭-알아야-할-것) 7번) |
| `xdp_non_ipv4_packets` | IPv6·ARP·VLAN 태그 프레임 등 검사 없이 통과 |
| `xdp_action_error_packets` | 룰은 매치했지만 실행할 수 없어 통과(예: redirect 대상 인터페이스가 사라짐) |

- 트래픽이 멈춘 상태에서 `xdp_rx_packets` = 결과별 8개 열의 합이다(흐르는 중에는 슬롯을 따로 읽어 약간 어긋날 수 있다). redirect는 `bpf_redirect`가 성공을 반환한 수이며 실제 전송 성공을 보장하지 않는다.
- `pps`·`xdp_rx_pps`는 정수, `mbps`·`xdp_rx_mbps`는 소수 3자리다. 첫 행과 총계가 직전보다 줄어든 샘플(daemon 재시작 등)의 초당 값은 빈 칸(text는 `n/a`)이다.
- 이전 버전 daemon에 연결하면 XDP 카운터가 없다. text는 `XDP counters: n/a (daemon does not report them)` 한 줄, CSV는 6–17열이 빈 칸이다.
- stdout에는 헤더와 행만 나가고(로그는 stderr), 행마다 바로 flush되므로 `> stats.csv &`로 돌리다 종료해도 완성된 행만 남는다.

**`add-rule` 옵션**

| 옵션 | 필수 | 형식 | 설명 |
|------|:---:|------|------|
| `--src-ip` | 둘 중 하나 ✅ | `a.b.c.d` 또는 `a.b.c.d/N` | 출발지 IP 또는 대역 |
| `--dst-ip` | 둘 중 하나 ✅ | `a.b.c.d` 또는 `a.b.c.d/N` | 목적지 IP 또는 대역. 출발지 룰이 매치하지 않을 때 평가 |
| `--action` | ✅ | `drop` `pass` `count` `redirect` | 차단 / 허용 / 통과시키며 집계 / 다른 인터페이스로 보냄 |
| `--label` | ✅ | 31바이트 이하 문자열 | 룰 이름. 삭제할 때 쓴다(중복 불가) |
| `--protocol` | | `tcp` `udp` `icmp` `any` | 기본값 `any` |
| `--dst-port` | | `80` 또는 `8000-8100` | 목적지 포트 (TCP/UDP) |
| `--src-port` | | `80` 또는 `1024-65535` | 출발지 포트 (TCP/UDP) |
| `--tcp-flags` | | `SYN`, `SYN,ACK` 등 | 지정한 플래그가 모두 켜진 TCP 패킷만 매치 |
| `--redirect-if` | redirect일 때 ✅ | 인터페이스 이름 | 리다이렉트 대상. redirect가 아닌 룰에 쓰면 거부된다 |
| `--priority`, `--rate-limit`, `--expire` | | 정수 (기본 0) | **미구현** — 0만 허용. 0이 아닌 값은 daemon이 거부한다 |
| `--pkt-len` | | | **미구현** — 지정하면(값과 무관) CLI가 거부한다 |

---

## 8. 룰 작성 가이드

### 8-0. IP 대역 표기 (CIDR) 읽는 법
`/숫자`는 앞에서부터 몇 비트가 같아야 하는지를 뜻한다. 숫자가 클수록 좁은(구체적인) 범위다.

| 표기 | 의미 | 포함되는 주소 |
|------|------|--------------|
| `203.0.113.7` (= `/32`) | 이 IP 하나 | 203.0.113.7 |
| `203.0.113.0/24` | 앞 3자리가 같은 주소 | 203.0.113.0 ~ 203.0.113.255 (256개) |
| `10.20.0.0/16` | 앞 2자리가 같은 주소 | 10.20.0.0 ~ 10.20.255.255 (65,536개) |
| `10.0.0.0/8` | 앞 1자리가 같은 주소 | 10.0.0.0 ~ 10.255.255.255 |
| `0.0.0.0/0` | 모든 주소 | 전부 |

`10.0.0.7/24`처럼 뒷자리가 섞여 있으면 자동으로 `10.0.0.0/24`로 정리된다.

### 8-1. 매칭 규칙 (꼭 알아야 할 것)
1. **출발지 룰 먼저.** 패킷의 출발지 IP에 대해 **가장 긴 prefix**(/32 > /24 > /16 …)의 출발지 룰 하나를 고른다. 그 룰의 세부 조건(프로토콜, 포트, TCP 플래그)이 맞으면 그 액션을 실행한다.
2. **출발지 룰이 없거나 조건이 맞지 않으면 목적지 룰.** 패킷의 목적지 IP에 대해 가장 긴 prefix의 목적지 룰 하나를 고르고, 조건이 맞으면 그 액션을 실행한다.
3. **둘 다 아니면 통과한다.** 같은 맵(출발지 룰끼리, 목적지 룰끼리) 안에서는 더 짧은 prefix의 룰로 되돌아가 다시 찾지 않는다.
4. **prefix당 룰 1개**(출발지·목적지 따로). 같은 prefix를 출발지 룰과 목적지 룰에 각각 둘 수 있다. label은 전체에서 유일해야 한다. 같은 IP에 포트별로 다른 동작이 필요하면 지금은 할 수 없다.
5. **포트·TCP 플래그 조건이 있는 룰은 L4 헤더를 확인할 수 있는 패킷에만 매치한다.** ICMP(ping), IP 조각의 후속 조각, **L4가 짧은 비조각 패킷**(IP 헤더의 `tot_len − IHL×4`가 TCP 20바이트 / UDP 8바이트보다 작음)에는 매치하지 않는다(포트 범위에 0이 들어 있어도 마찬가지다). IP/프로토콜만 쓰는 룰은 이런 패킷에도 매치한다.
6. **IP 옵션은 IHL(헤더 길이)만큼 건너뛰고** 그 뒤에서 포트·플래그를 읽는다.
7. **무조건 차단되는 패킷.** 다음 패킷은 룰을 보기 전에 차단된다(`pass` 룰로도 예외 처리할 수 없다). 통계의 `invalid`로 집계된다. 정상 네트워크 스택은 이런 패킷을 만들지 않으며, 커널도 비정상 헤더는 버린다.
   - IPv4 version≠4, IHL<5, IPv4 헤더가 20바이트 미만, IHL×4가 패킷보다 긺
   - IP 헤더의 전체 길이(`tot_len`)가 IHL×4보다 작거나, 실제로 받은 프레임보다 긺(전송 중 **프레임이 잘린** 패킷)
   - **tiny fragment**: 첫 조각(MF=1, offset 0)인데 TCP 헤더 20바이트 / UDP 헤더 8바이트가 다 들어 있지 않음 (RFC 1858). 이더넷 최소 프레임(60바이트)을 맞추려고 NIC가 붙이는 **패딩은 L4로 치지 않는다**. L4 길이는 프레임 길이가 아니라 `tot_len − IHL×4`로 판단한다
   - offset=1인 TCP 후속 조각 (TCP 헤더 덮어쓰기 공격, RFC 1858)

| 패킷 | 처리 | 통계 |
|------|------|------|
| IPv4, 헤더 정상, 비조각 (IP 옵션 포함) | 룰 평가 | 결과별 |
| 첫 조각, L4 헤더 완전 | 포트·플래그까지 정상 평가 | 결과별 |
| 후속 조각 / L4가 짧은 비조각(`tot_len` 기준) | IP/프로토콜만 쓰는 룰만 매치 | 결과별 |
| tiny fragment, TCP offset=1 조각, 비정상 IPv4 헤더, `tot_len` 불일치(프레임 잘림) | **무조건 차단** | `invalid` |

> **참고 — BIG TCP:** 기본값이 아닌 BIG TCP(IPv4, Linux 6.3+)를 켠 환경에서 `generic` 모드로 붙이면, GRO로 합쳐진 대형 패킷(`tot_len=0`)이 `invalid`로 버려질 수 있다(소스 분석 기준, 실측 안 함). 기본 설정에서는 해당 없다. BIG TCP를 쓰는 환경이라면 `driver` 모드를 쓰거나 BIG TCP를 끈다.
| IPv6, ARP, VLAN 태그 프레임, 14바이트 미만 프레임 | 검사 없이 통과 | `non_ipv4` |

### 8-2. 자주 쓰는 룰
```bash
# 특정 IP 완전 차단
xdp-filter add-rule --src-ip 203.0.113.7 --action drop --label block-attacker

# 대역 차단
xdp-filter add-rule --src-ip 203.0.113.0/24 --action drop --label block-net

# 대역은 차단하되 한 IP는 허용 (가장 긴 prefix 우선)
xdp-filter add-rule --src-ip 10.0.0.0/8  --action drop --label block-internal
xdp-filter add-rule --src-ip 10.1.2.3    --action pass --label allow-admin

# 특정 호스트의 SSH(22) 접근만 차단
xdp-filter add-rule --src-ip 198.51.100.5 --protocol tcp --dst-port 22 --action drop --label no-ssh

# 새 TCP 연결(SYN)만 차단
xdp-filter add-rule --src-ip 198.51.100.6 --protocol tcp --tcp-flags SYN --action drop --label no-new-conn

# UDP 포트 범위 차단
xdp-filter add-rule --src-ip 198.51.100.7 --protocol udp --dst-port 10000-20000 --action drop --label no-udp-range

# 차단 없이 관찰만
xdp-filter add-rule --src-ip 192.0.2.0/24 --action count --label watch
xdp-filter list-rules --stats

# 검사 장비 쪽 인터페이스로 리다이렉트
xdp-filter add-rule --src-ip 192.0.2.10 --action redirect --redirect-if eth1 --label to-ids

# 내 서버(목적지)로 오는 TCP 80만 차단
xdp-filter add-rule --dst-ip 192.0.2.80 --protocol tcp --dst-port 80 --action drop --label protect-web

# 서버 대역 보호 + 관리자 출발지는 예외 (출발지 룰이 먼저 평가된다 — 관리자 룰은 모든 목적지에 적용됨에 주의)
xdp-filter add-rule --dst-ip 192.0.2.0/24 --action drop --label protect-servers
xdp-filter add-rule --src-ip 198.51.100.10 --action pass --label admin-any
```
각 예시를 실습 랩에서 직접 확인하는 방법은 [docs/examples.md](docs/examples.md)에 있다.

### 8-3. 거부되는 입력과 에러 메시지
| 상황 | 메시지 |
|------|--------|
| `--src-ip`와 `--dst-ip` 둘 다 없음 | `Error: src_ip or dst_ip is required` |
| `--src-ip`와 `--dst-ip`를 함께 지정 | `Error: specify either src_ip or dst_ip, not both` |
| 같은 출발지 prefix 중복 | `Error: a rule for 10.200.0.2/32 already exists (label 'dup-a')` |
| 같은 목적지 prefix 중복 | `Error: a rule for dst 10.200.0.11/32 already exists (label 'dup-c')` |
| 없는 인터페이스로 redirect | `Error: unknown interface 'nope0': ENODEV: No such device` |
| redirect가 아닌데 `--redirect-if` | `Error: redirect_if 'eth1' is only allowed with the redirect action` |
| redirect인데 `--redirect-if` 없음 | `Error: Redirect action requires '--redirect-if' parameter` (CLI가 먼저 검사) |
| `--priority`가 0이 아님 | `Error: priority is not implemented yet: only 0 is accepted (got 5)` |
| `--rate-limit`가 0이 아님 | `Error: rate_limit is not implemented yet: only 0 is accepted (got 100)` |
| `--expire`가 0이 아님 | `Error: expire is not implemented yet: only 0 is accepted (got 60)` |
| `--pkt-len` 지정 | `Error: --pkt-len is not implemented yet` (CLI가 검사, 요청을 보내지 않음) |

여러 항목이 동시에 걸리면 첫 번째 하나만 보고된다. daemon 검사 순서는 src/dst → priority → rate_limit → expire → action/protocol/redirect다.

---

## 9. 실제 네트워크 인터페이스에 적용하기

### 9-1. 인터페이스 이름 찾기
```bash
$ ip -br addr
lo               UNKNOWN        127.0.0.1/8
enp1s0           UP             192.168.0.10/24      ← 이 이름을 쓴다 (eth0, ens3 등 환경마다 다름)
```

### 9-2. ⚠️ 원격(SSH)으로 작업 중이라면
잘못된 룰 하나로 **내 SSH 접속이 끊길 수 있다.** 다음을 지킨다.
1. 내 접속 IP부터 확인한다: `echo $SSH_CLIENT` (첫 번째 값)
2. 다른 룰보다 먼저 내 IP를 허용한다: `xdp-filter add-rule --src-ip <내IP> --action pass --label allow-me`
3. 가능하면 콘솔(클라우드 웹 콘솔, IPMI 등) 접근 수단을 확보해 둔다.
4. 처음에는 `--action count`로 넣어 매치되는 트래픽을 확인한 뒤, 룰을 지우고 `drop`으로 다시 넣는다.

### 9-3. 연결과 해제
```bash
$ sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o &
$ xdp-filter attach enp1s0 --mode driver
# driver 모드가 실패하면(드라이버 미지원):
$ xdp-filter attach enp1s0 --mode generic
$ ip -d link show enp1s0 | grep -o 'xdp[a-z]*'      # 연결 확인 → xdp(driver) / xdpgeneric
$ xdp-filter detach enp1s0                          # 해제
```
| 모드 | 특징 |
|------|------|
| `driver` | 가장 빠르다. NIC 드라이버가 XDP를 지원해야 한다(Intel ixgbe/i40e/ice, Mellanox mlx5 등) |
| `generic` | 모든 인터페이스에서 동작하지만 driver 모드보다 느리다. 테스트용이나 미지원 NIC에 쓴다 |
| `offload` | NIC 하드웨어에서 실행한다(지원 NIC만) |

### 9-4. 비상시 수동 해제
daemon이 강제 종료(`kill -9`)되면 XDP가 붙은 채 남을 수 있다.
```bash
$ sudo ip link set dev enp1s0 xdp off           # driver 모드였을 때
$ sudo ip link set dev enp1s0 xdpgeneric off    # generic 모드였을 때
```

### 9-5. ⚠️ 보안: 누가 룰을 바꿀 수 있나
- daemon API(`127.0.0.1:7654`)에는 **인증이 없다.** daemon은 root로 돌지만, 같은 서버에 로그인한 **일반 사용자도 누구나** `xdp-filter`로 룰을 넣고 지우고 XDP를 떼어낼 수 있다. 공용 서버라면 이 점을 감안한다.
- `--api-addr`를 `0.0.0.0` 같은 외부 주소로 바꾸지 않는다. 그러면 네트워크 너머에서 누구나 룰을 바꿀 수 있다.
- daemon은 요청 크기(1 MiB), 동시 연결 수(64), 응답 시간(10초)을 제한하지만, 이것은 오동작을 막기 위한 장치이지 접근 제어가 아니다.

---

## 10. systemd 서비스로 운영하기

`sudo make install`을 하면 서비스 파일이 설치된다. 부팅할 때 자동으로 시작되게 하려면 다음을 실행한다.
```bash
$ sudo systemctl enable --now swift-guard
$ systemctl status swift-guard              # Active: active (running) 이면 정상
$ journalctl -u swift-guard -f              # 로그 실시간 보기 (Ctrl+C로 종료)
```

서비스가 시작될 때 인터페이스에 자동으로 연결하려면 실행 옵션을 덮어쓴다.
```bash
$ sudo systemctl edit swift-guard
```
열린 편집기에 다음을 입력하고 저장한다(`enp1s0`은 실제 인터페이스 이름으로 바꾼다).
```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o -i enp1s0
```
```bash
$ sudo systemctl restart swift-guard
```
- 서비스 파일은 `RUST_LOG`를 설정하지 않는다. 로그 수준은 설정 파일의 `general.log_level`로 정한다([11장](#11-설정-파일)). override에 `Environment=RUST_LOG=...`를 넣으면 그것이 우선한다.
- 룰은 daemon 메모리와 커널 맵에만 있다. **daemon을 재시작하면 룰이 사라진다.** 계속 유지할 룰은 아래처럼 스크립트로 만들어 둔다.

**룰 스크립트로 다시 적용하기**

`/etc/swift-guard/rules.sh` 파일을 만든다(예: `sudo nano /etc/swift-guard/rules.sh`).
```bash
#!/bin/bash
# daemon이 응답할 때까지 최대 10초 기다린 뒤 룰을 넣는다
XF=/usr/local/bin/xdp-filter
for i in $(seq 1 50); do $XF list-rules >/dev/null 2>&1 && break; sleep 0.2; done

$XF add-rule --src-ip 203.0.113.0/24 --action drop --label block-bad-net
$XF add-rule --dst-ip 192.0.2.80 --protocol tcp --dst-port 22 --action drop --label guard-ssh
exit 0
```
```bash
$ sudo chmod +x /etc/swift-guard/rules.sh
$ sudo /etc/swift-guard/rules.sh               # 지금 바로 적용
$ xdp-filter list-rules
```
서비스가 시작될 때마다 자동으로 적용하려면 위의 `sudo systemctl edit swift-guard`에 한 줄을 더 넣는다.
```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o -i enp1s0
ExecStartPost=/etc/swift-guard/rules.sh
```
- 스크립트의 룰 하나가 실패해도(예: label 중복) 나머지는 계속 적용된다. 마지막 줄의 `exit 0` 덕분에 서비스 시작도 실패하지 않는다.
- 중지: `sudo systemctl stop swift-guard` (XDP가 자동으로 해제된다)
- 자동 시작 해제: `sudo systemctl disable swift-guard`

---

## 11. 설정 파일

위치: `/etc/swift-guard/config.yaml` (원본은 `config/swift-guard.yaml`). 파일이 없으면 기본값으로 실행된다. 모든 키는 생략할 수 있고, 생략하면 기본값을 쓴다.

| 키 | 기본값 | 허용 값 | 적용 | 설명 |
|----|--------|---------|:---:|------|
| `general.log_level` | `info` | `off` `error` `warn` `info` `debug` `trace` | ✅ | 로그 수준. 우선순위는 `-v` > `RUST_LOG` > 이 값 > `info` |
| `telemetry.log_stats` | `true` | `true` / `false` | ✅ | 수집한 룰 매치 통계를 주기적으로 로그로 출력 |
| `telemetry.interval` | `10` | 초 (0은 1로 취급) | ✅ | daemon 로그용 통계 주기. `xdp-filter stats`의 비율에는 영향 없음(CLI가 직접 계산) |
| `wasm.modules_dir` | `/usr/local/lib/swift-guard/wasm` | 디렉토리 | ✅ | `auto_load_modules`의 상대경로 기준 |
| `wasm.auto_load` | `false` | `true` / `false` | ✅ | `true`이면 기동 시 `auto_load_modules`를 로드한다 |
| `wasm.auto_load_modules` | `[]` | `.wasm` 경로 목록 | ✅ | 절대경로 또는 `modules_dir` 기준 상대경로. 모듈 이름은 파일 이름에서 확장자를 뺀 것(`http_inspector.wasm` → `http_inspector`) |
| `wasm.execution_timeout_ms` | `10` | 1–10000 | ✅ | 게스트 호출(allocate/inspect_packet/deallocate)마다의 시간 제한. XDP→WASM 데이터 경로가 아직 없으므로 실제 효과는 그 경로가 연결될 때 나타난다 |
| `wasm.memory_limit_mb` | `32` | 1–4096 | ✅ | 모듈당 선형 메모리 상한(MiB). 로드할 때 바로 적용된다 |

- **auto_load**: API 서버가 열린 뒤 백그라운드에서 순서대로 로드한다. 성공하면 `auto-loaded WASM module '<이름>' from <경로>`(info), 실패하면 `failed to auto-load WASM module from <경로>: <원인>`(error)이 로그에 남고 **daemon은 계속 실행된다**. `auto_load: false`인데 목록이 있으면 경고만 하고 로드하지 않는다.
- **삭제된 키**(`general.work_dir`, `general.pid_file`, `telemetry.export_enabled`, `telemetry.export_url`, `interfaces`, `rules`)는 `config key '<키>' is no longer supported and is ignored` 경고 후 무시된다. 이전 버전의 설정 파일도 그대로 동작한다. 인터페이스 자동 연결은 [10장](#10-systemd-서비스로-운영하기)의 `-i` override, 룰 자동 적용은 10장의 `rules.sh` + `ExecStartPost`를 쓴다.
- **모르는 키**는 `unknown config key '<키>' is ignored` 경고 후 무시된다(오타 확인용).
- **잘못된 값**(허용 범위 밖, 알 수 없는 log_level, 타입 오류)은 daemon 기동 실패다. 예: `invalid general.log_level 'loud' (expected one of: off, error, warn, info, debug, trace)`, `wasm.memory_limit_mb must be between 1 and 4096 (got 0)`.

설정을 바꾼 뒤에는 daemon을 재시작한다(`sudo systemctl restart swift-guard`).

---

## 12. WASM 검사 모듈

### 12-1. 사용
```bash
$ xdp-filter wasm load --name http-inspector --file /usr/local/lib/swift-guard/wasm/http_inspector.wasm
Module loaded: WASM module 'http-inspector' loaded
$ xdp-filter wasm list
NAME                     STATE        LOADED_AT
------------------------------------------------------------
http-inspector           loaded       2026-10-14 04:31:33
$ xdp-filter wasm stats --name http-inspector
$ xdp-filter wasm unload --name http-inspector
```
- 모듈을 빌드하는 방법은 [4-5](#4-5-선택-wasm-모듈-빌드)에 있다.
- **신뢰할 수 있는 모듈만 로드한다.** `init`은 1초, 패킷 검사는 기본 10ms의 실행 시간 제한이 있고 메모리는 기본 32MiB로 제한된다. 검사 시간·메모리 제한은 기본값이며 설정 파일(`wasm.execution_timeout_ms`, `wasm.memory_limit_mb`)로 바꿀 수 있다([11장](#11-설정-파일)). API로 동시에 로드할 수 있는 모듈은 2개까지다.
- daemon이 시작할 때 모듈을 자동으로 로드하려면 설정 파일의 `wasm.auto_load`와 `wasm.auto_load_modules`를 쓴다([11장](#11-설정-파일)).
- 현재는 관리 기능만 있다. XDP에서 모듈로 패킷을 넘기는 경로는 아직 연결되지 않았다.

### 12-2. 직접 모듈 만들기 (ABI)
`wasm/modules/http_inspector.rs`를 참고한다. 모듈은 다음을 제공해야 한다.

| 종류 | 이름 | 시그니처 | 설명 |
|------|------|---------|------|
| export (필수) | `memory` | | 선형 메모리 |
| export (필수) | `allocate` | `(size: i32) -> i32` | 호스트가 패킷을 복사할 버퍼 할당 |
| export (필수) | `deallocate` | `(ptr: i32, cap: i32)` | 검사 후 호스트가 호출 |
| export (필수) | `inspect_packet` | `(ptr: i32, len: i32) -> i32` | 이더넷 헤더부터 시작하는 프레임. **0 = 통과, 0이 아니면 차단** |
| export (선택) | `init` | `() -> ()` | 로드 직후 1회 |
| import | `env.log` | `(ptr: i32, len: i32) -> i32` | UTF-8 로그 출력 |

Rust로 작성할 때 호스트 함수는 **반드시 import 모듈을 명시한다.** 명시하지 않으면 같은 이름의 수학 함수 `log`로 링크되어 로드할 때 `unreachable` 오류가 난다.
```rust
#[link(wasm_import_module = "env")]
extern "C" { #[link_name = "log"] fn host_log(ptr: *const u8, len: i32) -> i32; }
```
`wasm/modules/` 폴더에 `.rs` 파일을 넣고 `make build-wasm`을 실행하면 같은 폴더에 `.wasm`이 생긴다.

---

## 13. 테스트와 검증

| 단계 | 확인하는 것 | 필요한 환경 | 명령 |
|------|------------|------------|------|
| 1. 빌드·단위 테스트 | 컴파일, 맵 바이트 레이아웃, API, 단위 테스트 | Linux | `cargo test --workspace` |
| 2. 커널 기능 (E2E) | verifier, attach/detach, 차단·집계·리다이렉트, CIDR, 통계, IP 옵션·조각 파싱(PROG_TEST_RUN과 실제 송신), XDP 카운터, 미구현 옵션 거부, 종료 정리 | Linux 5.10+, root (VM 가능, NIC 불필요) | `sudo tools/test/e2e_check.sh` |
| 2'. 사용 예시 회귀 | [docs/examples.md](docs/examples.md)의 예시 12종이 문서대로 동작하는지 | 위와 같음 | `sudo tools/test/examples.sh -v` |
| 3. 성능 — 처리량 | 패킷 크기별 pps·Gbps, CPU 사용률 (driver 모드) | 물리 서버 + XDP 지원 NIC + 트래픽 생성기(별도 송신 장비 또는 커널 pktgen) | `sudo tools/bench/basic_throughput_test.sh --interface <NIC> --generator external` (같은 호스트의 다른 NIC로 보낼 때는 `--generator pktgen --tx-dev <송신 NIC>`) |
| 3. 성능 — 룰 스케일링 | 룰 수(1–10000) 증가에 따른 pps, 룰 추가 시간 | 위와 같음 | `sudo tools/bench/rule_scaling_test.sh --interface <NIC> --generator external` |
| 3'. 성능 스크립트 흐름 검증 | daemon 기동→attach→(매치 룰)→트래픽→stats CSV→요약 CSV→분석→정리가 끝까지 도는지, `--rule-action none`에서도 `xdp_rx_pps`가 측정되는지 (**수치는 의미 없음**) | 2단계와 같음 (NIC 불필요) | `sudo tools/test/bench_flow_check.sh` |

자세한 내용은 [docs/linux-verification.md](docs/linux-verification.md)에, 시나리오와 결과 파일 형식은 [docs/poc-plan.md](docs/poc-plan.md)에 있다. 처리량의 1차 지표는 **`xdp_rx_pps`**(XDP가 본 전체 패킷, 룰과 무관)다. 벤치 스크립트는 기본으로 트래픽 출발지(`--src-ip`)에 매치하는 drop 룰을 넣는데(`--rule-action drop`), 이것은 XDP drop 경로를 측정 시나리오로 정하기 위한 것이다. `--rule-action none`이면 룰 없이 XDP_PASS 경로(커널 스택까지 감)를 잰다. 룰 매치 기준 `pps`도 함께 기록된다. 결과는 `./results/`의 CSV로 남고, `python3 tools/analysis/analyze_performance.py --results-dir results`로 그래프와 `summary.md`를 만든다(`pip install -r tools/analysis/requirements.txt` — matplotlib만 필요, 없으면 `summary.md`만 생성). 지연(P50/P99)은 측정 도구가 아직 없고, WASM 오버헤드·보안 효과성은 XDP→WASM 데이터 경로가 없어 현재 측정할 수 없다.

---

## 14. 문제 해결 (FAQ)

| 증상 | 원인과 해결 |
|------|-----------|
| `cargo: command not found` | Rust 환경이 로드되지 않았다. `source "$HOME/.cargo/env"`를 실행한다. `sudo cargo …`처럼 쓰지 않는다(빌드는 일반 사용자로) |
| `make build` 중 `bpf/bpf_helpers.h: No such file or directory` | `sudo apt install -y libbpf-dev` |
| `make build` 중 `gnu/stubs-32.h` | 이전 버전 소스다. 최신 소스를 받는다(`git pull`) |
| `sudo make install`에서 `ERROR: ... 가 없습니다` | 먼저 일반 사용자로 `make build`를 실행한다 |
| `Failed to connect` / `Connection refused` | daemon이 실행 중이 아니다. 터미널 1에서 daemon을 실행했는지, `--api-addr`와 `--api-server`가 같은지 확인한다 |
| daemon: `Permission denied` / `Operation not permitted` | daemon은 `sudo`로 실행해야 한다 |
| daemon: `BPF object load failed` / `BTF is required` | `--bpf-obj` 경로가 맞는지 확인한다. 설치본은 `/usr/local/lib/swift-guard/xdp_filter.o`다. `make build`로 다시 빌드한다. 커널 5.10 이상인지(`uname -r`) 확인한다 |
| daemon: `Address already in use` | 다른 daemon이 이미 실행 중이다(`pgrep -a swift-guard`). 그것을 쓰거나 종료한다. 포트를 바꾸려면 `--api-addr 127.0.0.1:7655`(CLI는 `--api-server`로 맞춘다) |
| `attach` 실패 (driver 모드) | NIC 드라이버가 XDP를 지원하지 않는다. `--mode generic`으로 다시 시도한다 |
| `already attached ... (use --force to replace)` | 이미 연결돼 있다. 그대로 쓰거나 `xdp-filter detach <if>` 후 다시 연결한다. daemon을 `-i`로 실행했다면 attach를 할 필요가 없다 |
| 룰을 넣었는데 차단이 안 됨 | ① 출발지 IP가 맞는지(NAT, 프록시 뒤라면 다를 수 있다) ② 같은 IP에 더 긴 prefix 룰이 있는지 ③ 프로토콜·포트 조건이 맞는지(포트 룰은 ICMP·후속 조각에 매치하지 않는다) ④ 목적지 룰이라면 같은 패킷에 매치하는 출발지 룰이 먼저 적용되지 않았는지 ⑤ VLAN 태그 프레임이 아닌지(`xdp-filter stats`의 `non_ipv4`가 늘면 검사 없이 통과한 것) 확인한다. `xdp-filter list-rules --stats`로 매치 수를 본다. [8-1](#8-1-매칭-규칙-꼭-알아야-할-것)을 참고한다 |
| daemon: `BPF object has no map 'xdp_stats_map'` (또는 `'dst_rules'`) / `BPF map 'xdp_stats_map' value size ... (rebuild xdp_filter.o)` | 오래된 `xdp_filter.o`다. `make build && sudo make install`로 다시 빌드·설치한 뒤 daemon을 다시 실행한다. `--bpf-obj`가 새 파일을 가리키는지도 확인한다 |
| `Error: priority is not implemented yet: ...` (`rate_limit`, `expire`도 같음) / `Error: --pkt-len is not implemented yet` | 미구현 옵션이다. 옵션을 빼거나 0으로 둔다([8-3](#8-3-거부되는-입력과-에러-메시지)). 이전 버전에서는 저장만 되고 적용되지 않았다 |
| daemon 로그: `config key '...' is no longer supported and is ignored` / `unknown config key '...' is ignored` | 동작에는 문제가 없다. 업데이트해도 기존 `/etc/swift-guard/config.yaml`은 덮어쓰지 않으므로 옛 키가 남아 있다. `config/swift-guard.yaml`과 비교해 정리한다([11장](#11-설정-파일)) |
| 출발지와 목적지를 동시에 조건으로 걸고 싶다 | 현재 미지원이다. 한쪽 prefix + 포트/프로토콜 조건으로 표현하거나, 목적지 룰과 출발지 예외 룰을 조합한다([8-2](#8-2-자주-쓰는-룰)) |
| daemon을 재시작했더니 룰이 사라짐 | 정상이다. 룰은 저장되지 않는다([10장](#10-systemd-서비스로-운영하기)) |
| SSH가 끊겼다 | 콘솔로 접속해 `sudo systemctl stop swift-guard`를 실행하거나 [9-4](#9-4-비상시-수동-해제)의 수동 해제 명령을 쓴다 |
| `wasm load`에서 `unreachable` | 오래된 방식으로 빌드한 모듈이다. [12-2](#12-2-직접-모듈-만들기-abi)대로 import를 선언하고 다시 빌드한다 |
| `wasm load`에서 `too many concurrent module loads` | 로드 중인 모듈이 2개다. 잠시 후 다시 시도한다 |
| `tools/test/*.sh: Permission denied` | `chmod +x tools/test/*.sh`, 또는 `sudo bash tools/test/e2e_check.sh` |
| `xdp-filter stats`의 Packets/sec가 `n/a` | 첫 샘플이라 비교할 직전 값이 없다. 정상이다(두 번째 샘플부터 나온다) |
| `xdp-filter stats`의 `Total packets`가 0에서 늘지 않음 | `Total packets`는 **룰에 매치한 패킷만** 센다. 먼저 `XDP rx packets`를 본다. 이것이 늘면 트래픽은 XDP에 도착하고 있고 매치하는 룰이 없는 것이다(`no_match`가 늘어난다). `XDP rx packets`도 늘지 않으면 트래픽이 그 인터페이스로 들어오지 않거나 XDP가 붙어 있지 않다(`ip link show <if>`에 `xdp`/`xdpgeneric` 표시 확인) |
| `e2e_check.sh`에서 daemon 기동 실패 | 커널이 BPF를 막는 환경일 수 있다(일부 컨테이너나 VM). 일반 Ubuntu VM에서 다시 시도한다 |

더 자세한 로그는 daemon을 `-v` 옵션으로 실행하거나, 서비스라면 `journalctl -u swift-guard -n 100`으로 본다.

---

## 15. 업데이트와 제거

### 업데이트
```bash
$ cd swift-guard
$ git pull
$ make build
$ sudo make install
$ sudo systemctl restart swift-guard     # 서비스로 운영 중이라면
```
- `sudo make install`은 기존 `/etc/swift-guard/config.yaml`을 덮어쓰지 않는다. 업데이트 후 daemon 로그에 설정 키 경고가 나오면 `config/swift-guard.yaml`과 비교해 정리한다(경고만 나오고 동작은 그대로다).

### 제거
```bash
$ cd swift-guard
$ sudo make uninstall                    # 실행 파일, XDP 프로그램, 서비스 제거
$ sudo rm -rf /etc/swift-guard           # 설정까지 지우려면
```

---

## 16. 프로젝트 구조

```
swift-guard/
├── README.md                  ← 이 문서
├── Makefile                   빌드(make build)·설치(sudo make install)
├── Cargo.toml                 Rust 워크스페이스
├── include/swift_guard.h      커널·사용자 공간이 공유하는 구조체/상수
├── src/
│   ├── bpf/                   XDP 프로그램 (xdp_filter.c → xdp_filter.o)
│   ├── daemon/                swift-guard-daemon (맵 관리, API 서버, 통계, WASM 런타임)
│   ├── cli/                   xdp-filter (CLI)
│   └── common/                공유 코드 (API 타입, BPF 맵 바이트 레이아웃)
├── wasm/                      WASM 모듈 소스와 빌드 스크립트
├── config/                    설정 파일, systemd 서비스 파일
├── tools/
│   ├── test/                  e2e_check.sh, examples.sh, lab.sh (실습 랩), bench_flow_check.sh, sg_pkt.py (파서 검증용 패킷 생성)
│   ├── bench/                 성능 측정: basic_throughput_test.sh, rule_scaling_test.sh, pktgen_tx.sh
│   └── analysis/              결과 분석: analyze_performance.py, requirements.txt
├── tests/integration/         통합 테스트 (cargo test -- --ignored)
└── docs/
    ├── examples.md            사용 예시 12종
    ├── linux-verification.md  검증 단계 가이드
    ├── poc-plan.md            PoC·벤치마크 계획
    └── evaluation.md          평가 방법론
```

---

## 17. 성능

**목표치(가설, 미측정)** — 아래 수치는 연구 목표이며 이 저장소에는 측정 결과가 없다. 측정 절차는 [13장](#13-테스트와-검증), [docs/poc-plan.md](docs/poc-plan.md), [docs/evaluation.md](docs/evaluation.md)를 따른다.

| 지표 | 목표치(가설, 미측정) | 조건 | 측정 수단 |
|------|--------|------|-----------|
| 패킷 처리 지연 | 2–5 μs | 5-tuple 분류 | 측정 도구 없음 (P50/P99 미구현) |
| 최대 처리량 | 약 10–15 Mpps | 단일 코어 | `tools/bench/basic_throughput_test.sh` → `throughput_results.csv`의 `xdp_rx_pps`(XDP가 본 전체 패킷)·`cpu_busiest` |
| 룰 추가 지연 | < 50 μs | | `tools/bench/rule_scaling_test.sh` → `add_rule_us_avg` (CLI 프로세스 생성·TCP 연결 포함 — 순수 맵 갱신 지연보다 크게 나온다) |
| 메모리 | 약 2–5 MB | 룰 1만 개 | 요약 CSV의 `daemon_rss_kb` + `sudo bpftool map show`(맵 memlock) |

*목표 설정 시 가정한 환경: Intel Xeon E5-2680v4 @ 2.4GHz, Linux 5.15, XDP driver 모드*

---

## 18. 라이선스와 참고 자료

- 라이선스: **GPL-2.0** (`Cargo.toml`, XDP 프로그램의 `SPDX-License-Identifier`)
- 이슈와 기여: https://github.com/uni2u/swift-guard/issues

참고 자료
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [libbpf-rs](https://github.com/libbpf/libbpf-rs)
- [Cilium BPF & XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
- [Proxy-Wasm spec](https://github.com/proxy-wasm/spec)

---

## 19. 용어 설명

| 용어 | 뜻 |
|------|----|
| **XDP** (eXpress Data Path) | 리눅스 커널이 패킷을 받자마자, 일반 네트워크 처리보다 먼저 실행하는 고속 처리 지점. 여기서 패킷을 버리면 비용이 아주 적다 |
| **eBPF / BPF** | 커널 안에서 안전하게 실행되는 작은 프로그램. `xdp_filter.o`가 이것이다 |
| **verifier** | BPF 프로그램을 커널에 올리기 전에 안전한지 검사하는 커널 기능. 통과하지 못하면 로드되지 않는다 |
| **BPF 맵** | BPF 프로그램과 사용자 프로그램이 함께 쓰는 커널 안의 저장소. 룰과 통계가 여기에 들어 있다 |
| **NIC / 인터페이스** | 네트워크 카드 / 그 카드의 이름(`eth0`, `enp1s0` 등). `ip -br link`로 확인한다 |
| **ingress** | 인터페이스로 **들어오는** 방향. Swift-Guard(XDP)는 들어오는 패킷만 처리한다. 서버가 밖으로 보내는 패킷은 처리하지 않는다 |
| **attach / detach** | XDP 프로그램을 인터페이스에 붙이기 / 떼기 |
| **driver / generic 모드** | XDP를 NIC 드라이버 안에서 실행(빠름) / 커널 공통 경로에서 실행(어디서나 동작, 느림) |
| **prefix / CIDR** | IP 대역 표기(`10.0.0.0/24`). [8-0](#8-0-ip-대역-표기-cidr-읽는-법) 참고 |
| **최장 prefix 일치 (LPM)** | 한 IP에 여러 대역 룰이 겹치면 가장 좁은(숫자가 큰) 대역의 룰을 고르는 방식 |
| **출발지 / 목적지** | 패킷을 보낸 쪽 IP / 받을 쪽 IP |
| **daemon** | 백그라운드에서 계속 실행되는 프로그램. 여기서는 `swift-guard-daemon` |
| **WASM** (WebAssembly) | 격리된 환경에서 실행되는 이식성 있는 바이너리 형식. 검사 로직을 플러그인처럼 추가하는 데 쓴다 |
| **redirect** | 패킷을 원래 목적지 대신 다른 인터페이스로 내보내는 것 |
