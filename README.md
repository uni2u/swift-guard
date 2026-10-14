# Swift-Guard

**S**ecure **W**ebAssembly **I**nspection **F**ramework for **T**raffic using **Guard**

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange.svg)](https://www.rust-lang.org/)
[![XDP](https://img.shields.io/badge/XDP-enabled-green.svg)](https://www.iovisor.org/technology/xdp)

Swift-Guard는 리눅스 커널의 **XDP(eXpress Data Path)** 로 네트워크 패킷을 아주 이른 단계에서 걸러내는 패킷 필터링·리다이렉트 프레임워크다. 명령 한 줄로 "이 IP에서 오는 트래픽 차단", "이 포트만 차단", "이 트래픽은 검사 장비로 보내기" 같은 룰을 실시간으로 넣고 뺄 수 있다.

> **처음이라면** [3. 시작하기 전에](#3-시작하기-전에) → [4. 설치](#4-설치) → [5. 설치 확인](#5-설치-확인-5분) → [6. 처음 사용해 보기](#6-처음-사용해-보기-10분) 순서로 따라 하면 된다. 모든 단계에 **"이렇게 나오면 성공"** 이 적혀 있다.

---

## 목차

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

---

## 1. Swift-Guard란?

### 할 수 있는 것
| 기능 | 예 |
|------|----|
| 출발지 IP / 대역 차단 | `203.0.113.7` 또는 `203.0.113.0/24`에서 오는 모든 패킷 drop |
| 프로토콜·포트 단위 차단 | 특정 호스트의 TCP 8080 접근만 차단, UDP 5353만 차단, 포트 범위 `8000-8100` |
| TCP 플래그 매칭 | 새 연결 시도(SYN)만 차단 |
| 예외 허용 | `/24` 대역은 차단하되 관리자 IP 하나(`/32`)는 허용 |
| 모니터링 | 차단하지 않고 패킷·바이트 수만 집계(`count`) |
| 리다이렉트 | 특정 트래픽을 다른 인터페이스(IDS, 분석 장비 등)로 보냄 |
| 실시간 통계 | 룰별 / 전체 패킷 수, 초당 패킷 수, 대역폭 |
| WASM 모듈 관리 | WebAssembly 보안 검사 모듈 로드/조회/언로드 |
| 안전한 종료 | daemon이 정상 종료(Ctrl+C, `systemctl stop`)하면 붙였던 XDP를 자동으로 해제 |

### 아직 할 수 없는 것 (현재 버전의 한계)
- **목적지 IP 기준 매칭**은 지원하지 않는다. 룰은 항상 **출발지 IP prefix** 기준이다.
- 같은 출발지 prefix에는 **룰을 하나만** 둘 수 있다.
- `--priority`, `--rate-limit`, `--expire`, `--pkt-len` 옵션은 저장만 되고 **아직 적용되지 않는다**.
- IPv4만 처리한다. IPv6와 ARP는 그대로 통과한다.
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
  패킷 ────▶ │  xdp_filter.o : 출발지 IP로 룰 조회 → 프로토콜/포트/플래그 확인  │ ──▶ 통과 / 차단 / 리다이렉트
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
  add-rule     필터링 규칙 추가 (--src-ip 필수, --dst-ip 미지원, src prefix당 룰 1개)
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
e2e_check: PASS=26 FAIL=0 SKIP=2
RESULT: ALL PASS
```
- `RESULT: ALL PASS`가 나오면 설치와 커널 기능이 모두 정상이다.
- `SKIP`은 선택 항목이라 괜찮다. 위 예는 bpftool이 없고 WASM 모듈을 빌드하지 않은 경우다. 둘을 갖추면 SKIP이 줄고 PASS가 늘어난다. 중요한 것은 `FAIL=0`이다.
- `FAIL`이 있으면 출력 끝의 daemon 로그를 보고 [14. 문제 해결](#14-문제-해결-faq)을 참고한다.
- 설치(`make install`)를 하지 않았다면 이 스크립트는 저장소의 `target/release/` 빌드본을 쓴다.

---

## 6. 처음 사용해 보기 (10분)

실제 네트워크를 건드리지 않도록 **가상 실습 랩**에서 진행한다. 랩은 PC 안에 작은 가상 네트워크를 만든다.

```
[가상 클라이언트들]  10.200.0.2  10.200.0.3  10.200.0.4  10.200.0.5
          │ (가상 케이블)
[내 PC]  sg-lab0  10.200.0.1   ← 여기에 Swift-Guard를 붙인다. 웹 서버 :8080, UDP 서버 :5353이 떠 있다
```

### 6-1. 랩 만들기 (터미널 1)
```bash
$ sudo tools/test/lab.sh up
lab up: XDP 대상 인터페이스 = sg-lab0, 서버 = 10.200.0.1 (HTTP 8080, UDP 5353), 클라이언트 = 10.200.0.2 10.200.0.3 10.200.0.4 10.200.0.5, redirect 대상 = sg-lab-insp0
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
LABEL                ACTION          SOURCE               DEST       PROTOCOL
--------------------------------------------------------------------------------
my-first-rule        drop            10.200.0.2           *          any
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

여기까지 됐다면 기본 사용법은 다 익힌 것이다. 포트·대역·SYN 차단, 예외 허용, 모니터링, 리다이렉트, WASM 등 **예시 10가지**는 [docs/examples.md](docs/examples.md)에 있다. 같은 랩에서 그대로 따라 할 수 있다.

---

## 7. 명령어 레퍼런스

### 7-1. `swift-guard-daemon` (root로 실행)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-b, --bpf-obj <파일>` | `src/bpf/xdp_filter.o` | XDP 프로그램 경로. **설치본을 쓸 때는 `/usr/local/lib/swift-guard/xdp_filter.o`를 지정한다** |
| `-c, --config <파일>` | `/etc/swift-guard/config.yaml` | 설정 파일. 없으면 기본값으로 실행 |
| `-i, --interface <이름>` | (없음) | 지정하면 시작할 때 그 인터페이스에 바로 attach. 이때는 `xdp-filter attach`를 다시 하지 않는다 |
| `--api-addr <주소:포트>` | `127.0.0.1:7654` | CLI가 접속할 주소 |
| `-v, --verbose` | | 디버그 로그 출력 |

```bash
$ sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o -v      # 디버그 로그
$ sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o -i eth0 # 시작과 동시에 eth0에 연결
```
종료는 `Ctrl+C`나 `kill <PID>`(SIGTERM)로 한다. 붙였던 XDP는 자동으로 해제된다.

### 7-2. `xdp-filter` (CLI)

공통 옵션: `--api-server <주소:포트>`(기본 `127.0.0.1:7654`), `-v`(상세 로그), `-h`(도움말). 하위 명령마다 `xdp-filter <명령> --help`로 도움말을 볼 수 있다.

| 명령 | 설명 | 예 |
|------|------|----|
| `attach <인터페이스> [--mode driver\|generic\|offload] [--force]` | XDP 연결. 기본 모드는 `driver`. 가상 인터페이스나 드라이버 미지원 NIC는 `generic` | `xdp-filter attach eth0 --mode generic` |
| `detach <인터페이스>` | XDP 해제 | `xdp-filter detach eth0` |
| `add-rule ...` | 룰 추가 (아래 표) | |
| `delete-rule --label <이름>` | 룰 삭제 | `xdp-filter delete-rule --label block-web` |
| `list-rules [--stats]` | 룰 목록. `--stats`를 붙이면 룰별 패킷·바이트 수도 표시 | `xdp-filter list-rules --stats` |
| `stats [--interval <초>]` | 전체 통계를 주기적으로 출력. `Ctrl+C`로 종료 | `xdp-filter stats --interval 2` |
| `wasm load --name <이름> --file <경로>` | WASM 모듈 로드 | [12장](#12-wasm-검사-모듈) |
| `wasm list` / `wasm stats --name <이름>` / `wasm unload --name <이름>` | 모듈 조회 / 통계 / 언로드 | |

**`add-rule` 옵션**

| 옵션 | 필수 | 형식 | 설명 |
|------|:---:|------|------|
| `--src-ip` | ✅ | `a.b.c.d` 또는 `a.b.c.d/N` | 출발지 IP 또는 대역 |
| `--action` | ✅ | `drop` `pass` `count` `redirect` | 차단 / 허용 / 통과시키며 집계 / 다른 인터페이스로 보냄 |
| `--label` | ✅ | 31바이트 이하 문자열 | 룰 이름. 삭제할 때 쓴다(중복 불가) |
| `--protocol` | | `tcp` `udp` `icmp` `any` | 기본값 `any` |
| `--dst-port` | | `80` 또는 `8000-8100` | 목적지 포트 (TCP/UDP) |
| `--src-port` | | `80` 또는 `1024-65535` | 출발지 포트 (TCP/UDP) |
| `--tcp-flags` | | `SYN`, `SYN,ACK` 등 | 지정한 플래그가 모두 켜진 TCP 패킷만 매치 |
| `--redirect-if` | redirect일 때 ✅ | 인터페이스 이름 | 리다이렉트 대상. redirect가 아닌 룰에 쓰면 거부된다 |
| `--dst-ip` | | | **미지원**(지정하면 거부) |
| `--priority`, `--rate-limit`, `--expire`, `--pkt-len` | | | 아직 적용되지 않음 |

---

## 8. 룰 작성 가이드

### 8-1. 매칭 규칙 (꼭 알아야 할 4가지)
1. **출발지 IP prefix로 룰을 찾는다.** 패킷의 출발지 IP에 대해 **가장 긴 prefix**(/32 > /24 > /16 …)의 룰 하나가 선택된다.
2. **선택된 룰의 세부 조건**(프로토콜, 포트, TCP 플래그)이 맞으면 액션을 실행한다. 맞지 않으면 **그냥 통과**한다. 더 짧은 prefix의 룰로 다시 찾아가지 않는다.
3. **같은 prefix에는 룰이 하나만** 있을 수 있다. 같은 IP에 포트별로 다른 동작이 필요하면 지금은 할 수 없다.
4. 포트 조건이 있는 룰은 ICMP(ping)와 매치하지 않는다(ICMP에는 포트가 없다).

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
```
각 예시를 실습 랩에서 직접 확인하는 방법은 [docs/examples.md](docs/examples.md)에 있다.

### 8-3. 거부되는 입력과 에러 메시지
| 상황 | 메시지 |
|------|--------|
| `--src-ip` 없음 | `Error: src_ip is required: XDP filter matches by source IP prefix only` |
| `--dst-ip` 지정 | `Error: dst_ip matching is not supported` |
| 같은 prefix 중복 | `Error: a rule for 10.200.0.2/32 already exists (label 'dup-a')` |
| 없는 인터페이스로 redirect | `Error: unknown interface 'nope0': ENODEV: No such device` |
| redirect가 아닌데 `--redirect-if` | `Error: redirect_if 'eth1' is only allowed with the redirect action` |
| redirect인데 `--redirect-if` 없음 | `Error: redirect action requires redirect_if` |

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
- 룰은 daemon 메모리와 커널 맵에만 있다. **daemon을 재시작하면 룰이 사라진다.** 부팅 후 필요한 룰은 스크립트로 다시 넣는다.
- 중지: `sudo systemctl stop swift-guard` (XDP가 자동으로 해제된다)
- 자동 시작 해제: `sudo systemctl disable swift-guard`

---

## 11. 설정 파일

위치: `/etc/swift-guard/config.yaml` (원본은 `config/swift-guard.yaml`). 파일이 없으면 기본값으로 실행된다.

| 키 | 기본값 | 현재 적용 여부 |
|----|--------|:---:|
| `telemetry.interval` | `10` | ✅ 통계 수집 주기(초) |
| `telemetry.log_stats` | `true` | ✅ 수집한 통계를 로그로 출력 |
| `general.log_level` | `info` | ❌ 대신 `-v` 옵션이나 `RUST_LOG=debug` 환경변수를 쓴다 |
| `wasm.*`, `interfaces`, `rules` | | ❌ 아직 적용되지 않는다. 인터페이스 자동 연결은 [10장](#10-systemd-서비스로-운영하기)의 `-i` 옵션을 쓴다 |

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
- **신뢰할 수 있는 모듈만 로드한다.** `init`은 1초, 패킷 검사는 10ms의 실행 시간 제한이 있고 메모리는 32MB로 제한된다. 동시에 로드할 수 있는 모듈은 2개까지다.
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
| 2. 커널 기능 (E2E) | verifier, attach/detach, 차단·집계·리다이렉트, CIDR, 통계, 종료 정리 | Linux 5.10+, root (VM 가능, NIC 불필요) | `sudo tools/test/e2e_check.sh` |
| 2'. 사용 예시 회귀 | [docs/examples.md](docs/examples.md)의 예시 10종이 문서대로 동작하는지 | 위와 같음 | `sudo tools/test/examples.sh -v` |
| 3. 성능 | Mpps, 지연, driver 모드 | 물리 서버 + XDP 지원 NIC | `sudo tools/bench/basic_throughput_test.sh --interface <NIC>` |

자세한 내용은 [docs/linux-verification.md](docs/linux-verification.md)에 있다. 성능 시나리오(룰 수 증가, WASM 오버헤드)는 [docs/poc-plan.md](docs/poc-plan.md)에 설명돼 있지만 스크립트는 아직 포함되지 않았다. 분석 스크립트는 `python3 tools/analysis/analyze_performance.py`이다(pandas, matplotlib 필요).

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
| 룰을 넣었는데 차단이 안 됨 | ① 출발지 IP가 맞는지(NAT, 프록시 뒤라면 다를 수 있다) ② 같은 IP에 더 긴 prefix 룰이 있는지 ③ 프로토콜·포트 조건이 맞는지 확인한다. `xdp-filter list-rules --stats`로 매치 수를 본다. [8-1](#8-1-매칭-규칙-꼭-알아야-할-4가지)을 참고한다 |
| daemon을 재시작했더니 룰이 사라짐 | 정상이다. 룰은 저장되지 않는다([10장](#10-systemd-서비스로-운영하기)) |
| SSH가 끊겼다 | 콘솔로 접속해 `sudo systemctl stop swift-guard`를 실행하거나 [9-4](#9-4-비상시-수동-해제)의 수동 해제 명령을 쓴다 |
| `wasm load`에서 `unreachable` | 오래된 방식으로 빌드한 모듈이다. [12-2](#12-2-직접-모듈-만들기-abi)대로 import를 선언하고 다시 빌드한다 |
| `wasm load`에서 `too many concurrent module loads` | 로드 중인 모듈이 2개다. 잠시 후 다시 시도한다 |
| `tools/test/*.sh: Permission denied` | `chmod +x tools/test/*.sh`, 또는 `sudo bash tools/test/e2e_check.sh` |
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
│   ├── test/                  e2e_check.sh, examples.sh, lab.sh (실습 랩)
│   ├── bench/                 성능 측정
│   └── analysis/              결과 분석
├── tests/integration/         통합 테스트 (cargo test -- --ignored)
└── docs/
    ├── examples.md            사용 예시 10종
    ├── linux-verification.md  검증 단계 가이드
    ├── poc-plan.md            PoC·벤치마크 계획
    └── evaluation.md          평가 방법론
```

---

## 17. 성능

아래는 연구 목표치이며, 이 저장소에 측정 결과가 포함돼 있지 않다. 측정 환경과 절차는 [docs/poc-plan.md](docs/poc-plan.md)와 [docs/evaluation.md](docs/evaluation.md)를 따른다.

| 지표 | 목표치 | 조건 |
|------|--------|------|
| 패킷 처리 지연 | 2–5 μs | 5-tuple 분류 |
| 최대 처리량 | 약 10–15 Mpps | 단일 코어 |
| 룰 추가 지연 | < 50 μs | |
| 메모리 | 약 2–5 MB | 룰 1만 개 |

*참고 환경: Intel Xeon E5-2680v4 @ 2.4GHz, Linux 5.15, XDP driver 모드*

---

## 18. 라이선스와 참고 자료

- 라이선스: **GPL-2.0** (`Cargo.toml`, XDP 프로그램의 `SPDX-License-Identifier`)
- 이슈와 기여: https://github.com/uni2u/swift-guard/issues

참고 자료
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [libbpf-rs](https://github.com/libbpf/libbpf-rs)
- [Cilium BPF & XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)
- [Proxy-Wasm spec](https://github.com/proxy-wasm/spec)
