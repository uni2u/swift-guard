# Swift-Guard 사용 예시

설치한 뒤 동작을 확인하기 위한 예시 모음이다. 물리 NIC 없이 **가상 실습 랩**(veth + network namespace)에서 바로 따라 할 수 있다. 각 예시는 "룰 추가 → 트래픽으로 확인 → 룰 삭제" 순서로 독립적이다.

> 이 문서의 모든 예시와 출력은 `sudo tools/test/examples.sh -v`로 자동 검증된다. 결과가 이 문서와 다르면 버그다.

## 목차
- [0. 설치 확인](#0-설치-확인)
- [1. 실습 랩 준비](#1-실습-랩-준비)
- [2. daemon 시작과 XDP 연결](#2-daemon-시작과-xdp-연결)
- 예시
  - [예시 1. 특정 호스트의 모든 트래픽 차단](#예시-1-특정-호스트의-모든-트래픽-차단)
  - [예시 2. 특정 서비스(포트)만 차단](#예시-2-특정-서비스포트만-차단)
  - [예시 3. 포트 범위 차단](#예시-3-포트-범위-차단)
  - [예시 4. UDP 서비스 차단](#예시-4-udp-서비스-차단)
  - [예시 5. 새 TCP 연결(SYN)만 차단](#예시-5-새-tcp-연결syn만-차단)
  - [예시 6. 대역 차단 + 예외 허용](#예시-6-대역-차단--예외-허용)
  - [예시 7. 차단 없이 트래픽 집계 (모니터링)](#예시-7-차단-없이-트래픽-집계-모니터링)
  - [예시 8. 검사 인터페이스로 리다이렉트](#예시-8-검사-인터페이스로-리다이렉트)
  - [예시 9. 거부되는 입력](#예시-9-거부되는-입력)
  - [예시 10. WASM 검사 모듈 관리](#예시-10-wasm-검사-모듈-관리)
- [3. 정리](#3-정리)
- [4. 실제 인터페이스에 적용할 때](#4-실제-인터페이스에-적용할-때)
- [5. systemd 서비스로 운영](#5-systemd-서비스로-운영)
- [룰 매칭 규칙 요약](#룰-매칭-규칙-요약)
- [문제 해결](#문제-해결)

---

## 0. 설치 확인

```bash
which xdp-filter swift-guard-daemon        # /usr/local/bin/...
ls /usr/local/lib/swift-guard/             # xdp_filter.o (+ wasm/)
xdp-filter --version
xdp-filter --help                           # attach, detach, add-rule, delete-rule, list-rules, stats, wasm
uname -r                                    # 5.10 이상
```

설치하지 않고 저장소에서 빌드만 했다면 `./target/release/xdp-filter`, `./target/release/swift-guard-daemon`, `src/bpf/xdp_filter.o`를 대신 쓴다.

## 1. 실습 랩 준비

```bash
sudo apt install -y iproute2 iputils-ping curl python3
sudo tools/test/lab.sh up
```

```
[netns sg-lab]  sg-lab-c0   10.200.0.2  .3  .4  .5     ← 클라이언트 4대 역할
                     ║ veth
[root ns]       sg-lab0     10.200.0.1                 ← XDP를 붙일 인터페이스
                서버: HTTP :8080, UDP echo :5353
                sg-lab-insp0 ══veth══ sg-lab-insp1      ← 리다이렉트 대상("검사 인터페이스")
```

트래픽 확인 명령은 성공하면 `OK`, 막히면 `BLOCKED`를 출력한다.

```bash
sudo tools/test/lab.sh ping 10.200.0.2        # ICMP
sudo tools/test/lab.sh http 10.200.0.2        # TCP 8080 (HTTP)
sudo tools/test/lab.sh udp  10.200.0.2        # UDP 5353
sudo tools/test/lab.sh syn  10.200.0.2        # TCP 연결 시도만
sudo tools/test/lab.sh insp-rx                # 검사 인터페이스 수신 패킷 수
```

아래 예시에서는 편의상 `alias lab='sudo tools/test/lab.sh'`, `alias xf='sudo xdp-filter'`로 줄여 쓴다.

## 2. daemon 시작과 XDP 연결

```bash
sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o &
xf attach sg-lab0 --mode generic
```
```
Success: XDP program attached to sg-lab0 in mode 1
```

- veth 같은 가상 인터페이스는 `--mode generic`으로 붙인다. driver 모드는 NIC 드라이버가 지원해야 한다.
- 연결됐는지 확인: `ip -d link show sg-lab0 | grep xdp`, 또는 `lab status`.
- 룰이 없으면 모든 트래픽이 통과한다: `lab ping 10.200.0.2` → `OK`

---

## 예시 1. 특정 호스트의 모든 트래픽 차단

```bash
xf add-rule --src-ip 10.200.0.2 --action drop --label block-host
```
```
Rule added: Rule 'block-host' added successfully
```
| 확인 | 결과 |
|------|------|
| `lab ping 10.200.0.2` | `BLOCKED` |
| `lab http 10.200.0.2` | `BLOCKED` |
| `lab ping 10.200.0.3` | `OK` ← 다른 호스트는 영향 없음 |

```bash
xf delete-rule --label block-host          # → lab ping 10.200.0.2 : OK
```

## 예시 2. 특정 서비스(포트)만 차단

10.200.0.3이 웹(TCP 8080)에 접근하는 것만 막고, 나머지는 허용한다.
```bash
xf add-rule --src-ip 10.200.0.3 --protocol tcp --dst-port 8080 --action drop --label block-web
```
| 확인 | 결과 |
|------|------|
| `lab http 10.200.0.3` | `BLOCKED` |
| `lab ping 10.200.0.3` | `OK` ← ICMP는 룰 조건(tcp, 8080)에 맞지 않아 통과 |

```bash
xf delete-rule --label block-web
```

## 예시 3. 포트 범위 차단

```bash
xf add-rule --src-ip 10.200.0.4 --protocol tcp --dst-port 8000-8100 --action drop --label block-range
```
| 확인 | 결과 |
|------|------|
| `lab http 10.200.0.4 8080` | `BLOCKED` |
| `lab udp 10.200.0.4` | `OK` ← UDP는 통과 |

```bash
xf delete-rule --label block-range
```
`--src-port`도 같은 형식(`80`, `1024-65535`)으로 쓸 수 있다.

## 예시 4. UDP 서비스 차단

```bash
xf add-rule --src-ip 10.200.0.3 --protocol udp --dst-port 5353 --action drop --label block-udp
```
| 확인 | 결과 |
|------|------|
| `lab udp 10.200.0.3` | `BLOCKED` |
| `lab http 10.200.0.3` | `OK` |

```bash
xf delete-rule --label block-udp
```

## 예시 5. 새 TCP 연결(SYN)만 차단

```bash
xf add-rule --src-ip 10.200.0.3 --protocol tcp --dst-port 8080 --tcp-flags SYN --action drop --label block-syn
```
| 확인 | 결과 |
|------|------|
| `lab syn 10.200.0.3` | `BLOCKED` ← 연결 수립(SYN) 단계에서 차단 |
| `lab ping 10.200.0.3` | `OK` |

```bash
xf delete-rule --label block-syn
```
`--tcp-flags`는 `SYN,ACK,FIN,RST,PSH,URG`를 쉼표로 조합한다. 지정한 플래그가 **모두 켜진** 패킷과 매치한다. 예를 들어 `SYN`은 SYN과 SYN-ACK 모두와 매치한다.

## 예시 6. 대역 차단 + 예외 허용

10.200.0.0/24 전체를 막고, 관리자 호스트(10.200.0.5)만 허용한다. 가장 긴 prefix가 우선한다.
```bash
xf add-rule --src-ip 10.200.0.0/24 --action drop --label block-subnet
xf add-rule --src-ip 10.200.0.5    --action pass --label allow-admin
xf list-rules
```
```
LABEL                ACTION          SOURCE               DEST       PROTOCOL
--------------------------------------------------------------------------------
block-subnet         drop            10.200.0.0/24        *          any
allow-admin          pass            10.200.0.5           *          any
```
| 확인 | 결과 |
|------|------|
| `lab ping 10.200.0.2` | `BLOCKED` |
| `lab http 10.200.0.4` | `BLOCKED` |
| `lab ping 10.200.0.5` | `OK` ← /32 예외가 /24보다 우선 |
| `lab http 10.200.0.5` | `OK` |

```bash
xf delete-rule --label allow-admin
xf delete-rule --label block-subnet
```
`10.200.0.7/24`처럼 호스트 비트가 섞인 값은 `10.200.0.0/24`로 정규화된다.

## 예시 7. 차단 없이 트래픽 집계 (모니터링)

```bash
xf add-rule --src-ip 10.200.0.4 --action count --label watch-host
lab ping 10.200.0.4; lab http 10.200.0.4        # 둘 다 OK
xf list-rules --stats
```
```
LABEL                ACTION          SOURCE               DEST       PROTOCOL
--------------------------------------------------------------------------------
watch-host           count           10.200.0.4           *          any
  Packets: 9, Bytes: 777
```
전체 통계는 1초 간격으로 계속 갱신되며, Ctrl+C로 끝낸다.
```bash
xf stats --interval 1
```
```
Collecting statistics (press Ctrl+C to exit)...
Timestamp: 2026-10-14 04:26:29
Total packets: 37
Total bytes: 3020 (0.00 MB)
Packets/sec: 0
Bandwidth: 0.00 Mbps
----------------------------------------
```
```bash
xf delete-rule --label watch-host
```
룰별 통계(`Packets`)는 그 룰에 매치한 패킷만 센다. 전체 통계(`Total packets`)는 모든 룰의 매치를 합한 값이다. 패킷 수는 환경에 따라 다를 수 있다.

## 예시 8. 검사 인터페이스로 리다이렉트

10.200.0.5의 ICMP를 검사 인터페이스(`sg-lab-insp0`)로 돌린다. 실제 환경에서는 IDS나 분석 장비 쪽 인터페이스에 해당한다.
```bash
lab insp-rx                                     # 현재 수신 수 기록 (예: 0)
xf add-rule --src-ip 10.200.0.5 --protocol icmp --action redirect --redirect-if sg-lab-insp0 --label to-inspect
```
| 확인 | 결과 |
|------|------|
| `lab ping 10.200.0.5` | `BLOCKED` ← 원래 목적지 대신 검사 인터페이스로 감 |
| `lab insp-rx` | 3 이상 증가 |
| `lab http 10.200.0.5` | `OK` ← ICMP만 리다이렉트 |

```bash
xf delete-rule --label to-inspect
```

## 예시 9. 거부되는 입력

daemon은 잘못된 룰을 받으면 에러로 응답한다. CLI 종료 코드는 0이 아니다.

| 명령 | 출력 |
|------|------|
| `xf add-rule --protocol tcp --dst-port 80 --action drop --label bad1` | `Error: src_ip is required: XDP filter matches by source IP prefix only` |
| `xf add-rule --src-ip 10.200.0.2 --dst-ip 10.200.0.1 --action drop --label bad2` | `Error: dst_ip matching is not supported` |
| (같은 src에 룰이 이미 있을 때) `xf add-rule --src-ip 10.200.0.2 --protocol tcp --action pass --label dup-b` | `Error: a rule for 10.200.0.2/32 already exists (label 'dup-a')` |
| `xf add-rule --src-ip 10.200.0.3 --action redirect --redirect-if nope0 --label bad3` | `Error: unknown interface 'nope0': ENODEV: No such device` |
| `xf add-rule --src-ip 10.200.0.3 --action drop --redirect-if sg-lab-insp0 --label bad4` | `Error: redirect_if 'sg-lab-insp0' is only allowed with the redirect action` |
| `xf add-rule --src-ip 10.200.0.3 --action redirect --label bad5` | `Error: redirect action requires redirect_if` |

## 예시 10. WASM 검사 모듈 관리

```bash
(cd wasm && ./build.sh)          # 필요: rustup target add wasm32-unknown-unknown
xf wasm load --name http-inspector --file /usr/local/lib/swift-guard/wasm/http_inspector.wasm
xf wasm list
xf wasm stats --name http-inspector
xf wasm unload --name http-inspector
```
```
Module loaded: WASM module 'http-inspector' loaded

NAME                     STATE        LOADED_AT
------------------------------------------------------------
http-inspector           loaded       2026-10-14 04:31:33

Module: http-inspector
Processed packets: 0
Blocked packets: 0
Avg processing time: 0.00 us

Module unloaded: WASM module 'http-inspector' unloaded
```
- 현재 버전은 모듈 관리(load/list/stats/unload)만 한다. XDP에서 WASM으로 패킷을 넘기는 데이터 경로는 아직 연결되지 않았으므로, `Processed packets`는 0으로 남는다.
- 신뢰할 수 있는 모듈만 로드한다. `init`과 패킷 검사에는 실행 시간 제한이 있고 메모리는 32MB로 제한되지만, 모듈 컴파일 자체에는 시간 제한이 없다.
- 저장소 빌드본은 `wasm/modules/http_inspector.wasm`에 있다.

---

## 3. 정리

```bash
xf detach sg-lab0                      # Success: XDP program detached from sg-lab0
sudo kill %1                           # daemon 종료 (SIGTERM이면 붙어 있던 XDP를 자동 해제)
lab down
```

## 4. 실제 인터페이스에 적용할 때

```bash
sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o &
xf attach eth0 --mode driver            # 드라이버가 지원하지 않으면 --mode generic
xf add-rule --src-ip 203.0.113.0/24 --action drop --label block-bad-net
```
- **원격(SSH)으로 작업 중이면 자기 접속 IP를 막지 않도록 주의한다.** 먼저 콘솔 접근 수단을 확보하거나, 내 IP에 `--action pass` 룰을 먼저 넣는다(예시 6 참고).
- 원래 상태로 되돌리기:
  - `xf detach eth0`
  - daemon이 비정상 종료(SIGKILL)한 경우에는 `sudo ip link set dev eth0 xdp off`. generic 모드였다면 `xdpgeneric off`.
- 다른 프로그램이 이미 XDP를 붙인 인터페이스에는 `attach`가 거부된다. 교체하려면 `--force`를 붙인다.

## 5. systemd 서비스로 운영

```bash
sudo systemctl enable --now swift-guard
systemctl status swift-guard
journalctl -u swift-guard -f              # 로그
xf attach eth0 --mode driver              # 이후 CLI 사용법은 동일
sudo systemctl stop swift-guard           # SIGTERM → XDP 자동 해제
```
설정 파일은 `/etc/swift-guard/config.yaml`이다(예시: `config/swift-guard.yaml`).

---

## 룰 매칭 규칙 요약

| 규칙 | 설명 |
|------|------|
| 매칭 키 | **출발지 IP prefix만** 쓴다(`--src-ip`, 필수). 목적지 IP 매칭은 지원하지 않는다 |
| prefix 우선순위 | 가장 긴 prefix가 이긴다(/32 > /24 > /8) |
| prefix당 룰 1개 | 같은 prefix에 두 번째 룰을 넣으면 거부된다. 포트별로 다른 동작이 필요하면 prefix를 나눈다 |
| 세부 조건 | 이긴 룰의 프로토콜·포트·TCP 플래그가 맞을 때만 액션을 실행한다. 맞지 않으면 **통과**한다. 더 짧은 prefix로 되돌아가 다시 찾지 않는다 |
| 프로토콜 | `tcp`, `udp`, `icmp`, `any`(기본값) |
| 포트 | `N` 또는 `N-M`. ICMP는 포트가 0이므로, 포트 조건이 있는 룰과는 매치하지 않는다 |
| 액션 | `drop`, `pass`, `count`(통과하며 집계), `redirect`(`--redirect-if` 필요) |
| 미구현 | `--priority`, `--rate-limit`, `--expire`, `--pkt-len`은 저장만 되고 아직 적용되지 않는다 |
| 대상 트래픽 | XDP를 붙인 인터페이스로 **들어오는** IPv4 패킷. IPv6와 ARP는 그대로 통과한다 |

## 문제 해결

| 증상 | 확인 |
|------|------|
| `Failed to connect` | daemon이 실행 중인지, `--api-addr`와 `--api-server` 주소가 같은지(기본 `127.0.0.1:7654`) |
| `BPF object load failed` / `BTF is required` | `xdp_filter.o`를 `make -C src/bpf`로 다시 빌드한다(`-g`가 빠지면 BTF가 없다). 커널 5.10 이상인지 확인한다 |
| attach 실패 (driver) | `--mode generic`으로 재시도한다. 드라이버 지원 여부는 `ethtool -i eth0`로 확인한다 |
| `already attached` | 이미 붙어 있다. `xf detach <if>` 후 다시 붙이거나 `--force`를 쓴다 |
| 룰을 넣었는데 매치가 안 됨 | [룰 매칭 규칙](#룰-매칭-규칙-요약)을 본다(같은 IP에 더 긴 prefix 룰이 있는지, 프로토콜·포트 조건). `xf list-rules --stats`로 매치 수를 확인한다 |
| WASM `unreachable` trap | 오래된 모듈 빌드다. 호스트 함수는 `#[link(wasm_import_module = "env")]`로 선언해야 한다(`wasm/modules/http_inspector.rs` 참고) |

자동 검증:
```bash
sudo tools/test/examples.sh        # 이 문서의 예시 전체 (PASS/FAIL)
sudo tools/test/e2e_check.sh       # 커널 기능 E2E (docs/linux-verification.md)
```
