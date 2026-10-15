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
  - [예시 11. 목적지(서버 IP) 기준 차단](#예시-11-목적지서버-ip-기준-차단)
  - [예시 12. 출발지 룰 우선과 목적지 룰로 넘어가기](#예시-12-출발지-룰-우선과-목적지-룰로-넘어가기)
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
[root ns]       sg-lab0     10.200.0.1, 10.200.0.11    ← XDP를 붙일 인터페이스 (서버 IP 2개)
                서버(두 IP 각각): HTTP :8080, UDP echo :5353
                sg-lab-insp0 ══veth══ sg-lab-insp1      ← 리다이렉트 대상("검사 인터페이스")
```

트래픽 확인 명령은 성공하면 `OK`, 막히면 `BLOCKED`를 출력한다.

```bash
sudo tools/test/lab.sh ping 10.200.0.2        # ICMP
sudo tools/test/lab.sh http 10.200.0.2        # TCP 8080 (HTTP)
sudo tools/test/lab.sh udp  10.200.0.2        # UDP 5353
sudo tools/test/lab.sh syn  10.200.0.2        # TCP 연결 시도만
sudo tools/test/lab.sh insp-rx                # 검사 인터페이스 수신 패킷 수
sudo tools/test/lab.sh --to 10.200.0.11 http 10.200.0.2   # 두 번째 서버 IP로
```

목적지는 기본이 `10.200.0.1`이다. `--to 10.200.0.11`을 트래픽 명령 앞에 붙이면 두 번째 서버 IP로 보낸다(예시 11, 12). `--to`에는 이 두 주소만 쓸 수 있다.

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
LABEL                ACTION          SOURCE               DEST                 PROTOCOL
------------------------------------------------------------------------------------------
block-subnet         drop            10.200.0.0/24        *                    any
allow-admin          pass            10.200.0.5           *                    any
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
LABEL                ACTION          SOURCE               DEST                 PROTOCOL
------------------------------------------------------------------------------------------
watch-host           count           10.200.0.4           *                    any
  Packets: 9, Bytes: 777
```
전체 통계를 1초 간격으로 2번 출력한다. `--count`를 빼면 Ctrl+C까지 계속 출력한다.
```bash
xf stats --count 2
```
출력 예(수치는 예시이며 환경에 따라 다르다):
```
Collecting 2 samples every 1s...
Timestamp: 2026-10-14 06:35:31
Total packets: 38
Total bytes: 3086 (0.00 MB)
Packets/sec: n/a
Bandwidth: n/a
XDP rx packets: 52
XDP rx bytes: 4710 (0.00 MB)
XDP rx packets/sec: n/a
XDP rx bandwidth: n/a
XDP verdicts: drop=26 pass=3 redirect=0 count=9 no_match=12 invalid=0 non_ipv4=2 action_error=0
----------------------------------------
Timestamp: 2026-10-14 06:35:32
Total packets: 38
Total bytes: 3086 (0.00 MB)
Packets/sec: 0
Bandwidth: 0.00 Mbps
XDP rx packets: 52
XDP rx bytes: 4710 (0.00 MB)
XDP rx packets/sec: 0
XDP rx bandwidth: 0.00 Mbps
XDP verdicts: drop=26 pass=3 redirect=0 count=9 no_match=12 invalid=0 non_ipv4=2 action_error=0
----------------------------------------
```
두 종류의 통계가 나온다.

| 줄 | 세는 것 |
|----|---------|
| `Total packets` / `Total bytes` | **룰에 매치한 패킷**만. 모든 룰의 매치를 합한 값이다(drop·pass·count·redirect 모두) |
| `XDP rx packets` / `XDP rx bytes` | **XDP가 본 전체 패킷**. 룰 매치와 무관하다 |
| `XDP verdicts` | 전체 패킷이 어떻게 처리됐는지. `drop`·`pass`·`redirect`·`count` = 룰 액션, `no_match` = 매치한 룰이 없어 통과, `invalid` = 비정상 헤더·tiny fragment라 룰과 무관하게 차단, `non_ipv4` = IPv6·ARP·VLAN 태그 프레임이라 검사 없이 통과, `action_error` = 룰은 매치했지만 실행할 수 없어 통과(redirect 대상 인터페이스가 사라진 경우 등) |

`XDP rx packets`는 `XDP verdicts`의 8개 값을 더한 것과 같다(트래픽이 흐르는 중에는 조금 어긋날 수 있다). 위 예에서 `Total packets` 38 = drop 26 + pass 3 + redirect 0 + count 9 이고, 매치하지 않은 12개는 `no_match`로만 보인다.

`Packets/sec`·`Bandwidth`(룰 매치 기준)와 `XDP rx packets/sec`·`XDP rx bandwidth`(전체 기준)는 CLI가 연속한 두 샘플의 총계 차이로 계산한다. 그래서 첫 샘플은 `n/a`이고, 그 사이에 트래픽이 없으면 0이다. daemon이 이전 버전이라 XDP 카운터를 주지 않으면 XDP 줄 대신 `XDP counters: n/a (daemon does not report them)` 한 줄이 나온다.

스크립트에서 쓰려면 `xf stats --format csv --count 60 > stats.csv`를 쓴다. 헤더는 17열로 고정이다.
```
timestamp_ms,total_packets,total_bytes,pps,mbps,xdp_rx_packets,xdp_rx_bytes,xdp_rx_pps,xdp_rx_mbps,xdp_drop_packets,xdp_pass_packets,xdp_redirect_packets,xdp_count_packets,xdp_no_match_packets,xdp_invalid_packets,xdp_non_ipv4_packets,xdp_action_error_packets
```
첫 행의 비율 열(`pps`, `mbps`, `xdp_rx_pps`, `xdp_rx_mbps`)은 빈 칸이다.
```bash
xf delete-rule --label watch-host
```
룰별 통계(`Packets`)는 그 룰에 매치한 패킷만 센다. **어떤 룰에도 매치하지 않은 패킷은 `Total packets`에는 잡히지 않고 `XDP rx packets`와 `no_match`에만 잡힌다.** 트래픽이 XDP에 도달하는지 보려면 `XDP rx packets`를 본다.

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
| `xf add-rule --protocol tcp --dst-port 80 --action drop --label bad1` | `Error: src_ip or dst_ip is required` |
| `xf add-rule --src-ip 10.200.0.2 --dst-ip 10.200.0.1 --action drop --label bad2` | `Error: specify either src_ip or dst_ip, not both` |
| (같은 src에 룰이 이미 있을 때) `xf add-rule --src-ip 10.200.0.2 --protocol tcp --action pass --label dup-b` | `Error: a rule for 10.200.0.2/32 already exists (label 'dup-a')` |
| (같은 목적지에 룰이 이미 있을 때) `xf add-rule --dst-ip 10.200.0.11 --protocol tcp --action pass --label dup-d` | `Error: a rule for dst 10.200.0.11/32 already exists (label 'dup-c')` |
| `xf add-rule --src-ip 10.200.0.3 --action redirect --redirect-if nope0 --label bad3` | `Error: unknown interface 'nope0': ENODEV: No such device` |
| `xf add-rule --src-ip 10.200.0.3 --action drop --redirect-if sg-lab-insp0 --label bad4` | `Error: redirect_if 'sg-lab-insp0' is only allowed with the redirect action` |
| `xf add-rule --src-ip 10.200.0.3 --action redirect --label bad5` | `Error: Redirect action requires '--redirect-if' parameter` ← CLI가 먼저 검사한다 |
| `xf add-rule --src-ip 10.200.0.3 --action drop --priority 10 --label bad6` | `Error: priority is not implemented yet: only 0 is accepted (got 10)` |
| `xf add-rule --src-ip 10.200.0.3 --action drop --rate-limit 1000 --label bad7` | `Error: rate_limit is not implemented yet: only 0 is accepted (got 1000)` |
| `xf add-rule --src-ip 10.200.0.3 --action drop --expire 60 --label bad8` | `Error: expire is not implemented yet: only 0 is accepted (got 60)` |
| `xf add-rule --src-ip 10.200.0.3 --action drop --pkt-len 64-128 --label bad9` | `Error: --pkt-len is not implemented yet` ← CLI가 요청을 보내기 전에 거부한다 |

`--priority`·`--rate-limit`·`--expire`는 아직 구현되지 않았다. 기본값 0은 그대로 허용되고, 0이 아닌 값은 daemon이 거부한다(이전 버전은 저장만 하고 적용하지 않았다). `--pkt-len`은 값과 상관없이 거부된다.

같은 prefix라도 출발지 룰과 목적지 룰은 따로 둘 수 있다(예: `--src-ip 10.200.0.2` 룰과 `--dst-ip 10.200.0.2` 룰을 함께 둘 수 있다). label은 전체에서 유일해야 한다.

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
- 신뢰할 수 있는 모듈만 로드한다. 패킷 검사 호출에는 실행 시간 제한(기본 10ms), 모듈 메모리에는 상한(기본 32MB)이 있다. 두 값은 설정 파일의 `wasm.execution_timeout_ms`, `wasm.memory_limit_mb`로 바꿀 수 있다. `init`의 시간 제한은 1초로 고정이고, 모듈 컴파일 자체에는 시간 제한이 없다.
- daemon을 시작할 때 모듈을 자동으로 올리려면 설정 파일에서 `wasm.auto_load: true`와 `wasm.auto_load_modules`를 쓴다. 로드에 실패해도 daemon은 에러를 로그에 남기고 계속 동작한다.
- 저장소 빌드본은 `wasm/modules/http_inspector.wasm`에 있다.

## 예시 11. 목적지(서버 IP) 기준 차단

출발지와 상관없이 두 번째 서버 IP(10.200.0.11)의 웹(TCP 8080)으로 오는 트래픽을 막는다. 같은 인터페이스의 다른 서버 IP(10.200.0.1)는 영향을 받지 않는다.
```bash
xf add-rule --dst-ip 10.200.0.11 --protocol tcp --dst-port 8080 --action drop --label protect-web2
xf list-rules
```
```
LABEL                ACTION          SOURCE               DEST                 PROTOCOL
------------------------------------------------------------------------------------------
protect-web2         drop            *                    10.200.0.11:8080     tcp
```
| 확인 | 결과 |
|------|------|
| `lab --to 10.200.0.11 http 10.200.0.2` | `BLOCKED` |
| `lab --to 10.200.0.11 http 10.200.0.3` | `BLOCKED` ← 출발지와 무관 |
| `lab --to 10.200.0.11 ping 10.200.0.2` | `OK` ← 포트 조건이 있어 ICMP와는 매치하지 않음 |
| `lab --to 10.200.0.11 udp 10.200.0.2` | `OK` ← UDP는 통과 |
| `lab http 10.200.0.2` | `OK` ← 10.200.0.1은 대상이 아님 |

```bash
xf delete-rule --label protect-web2        # → lab --to 10.200.0.11 http 10.200.0.2 : OK
```
`--dst-ip`도 `a.b.c.d/N` 대역을 받는다. 룰 하나에는 `--src-ip`와 `--dst-ip` 중 하나만 쓴다(예시 9).

## 예시 12. 출발지 룰 우선과 목적지 룰로 넘어가기

출발지 룰이 항상 먼저 평가된다. 출발지 룰이 없거나 세부 조건이 맞지 않을 때만 목적지 룰을 본다.
```bash
xf add-rule --dst-ip 10.200.0.11 --action drop --label block-srv2
xf add-rule --src-ip 10.200.0.5 --action pass --label admin-pass
xf add-rule --src-ip 10.200.0.4 --protocol udp --action count --label watch-udp4
```
| 확인 | 결과 |
|------|------|
| `lab --to 10.200.0.11 ping 10.200.0.2` | `BLOCKED` ← 출발지 룰 없음 → 목적지 룰(drop) |
| `lab --to 10.200.0.11 ping 10.200.0.5` | `OK` ← 출발지 룰(pass)이 먼저 매치 |
| `lab --to 10.200.0.11 udp 10.200.0.4` | `OK` ← 출발지 룰(count, udp)이 매치 → 목적지 룰까지 가지 않음 |
| `lab --to 10.200.0.11 ping 10.200.0.4` | `BLOCKED` ← 출발지 룰 조건(udp) 불일치 → 목적지 룰 적용 |
| `lab ping 10.200.0.4` | `OK` ← 10.200.0.1은 목적지 룰 대상이 아님 |

```bash
xf list-rules --stats
```
```
LABEL                ACTION          SOURCE               DEST                 PROTOCOL
------------------------------------------------------------------------------------------
block-srv2           drop            *                    10.200.0.11          any
  Packets: 6, Bytes: 588
admin-pass           pass            10.200.0.5           *                    any
  Packets: 3, Bytes: 294
watch-udp4           count           10.200.0.4           *                    udp
  Packets: 1, Bytes: 46
```
세 룰 모두 매치 수(`Packets`)가 0보다 크다. 수치는 환경에 따라 다를 수 있다. `admin-pass`처럼 출발지에 `pass` 룰을 두면 그 호스트는 **모든 목적지**의 목적지 룰을 피해 간다는 점에 주의한다.
```bash
xf delete-rule --label watch-udp4
xf delete-rule --label admin-pass
xf delete-rule --label block-srv2
```

---

## 3. 정리

```bash
xf detach sg-lab0                      # Success: XDP program detached from sg-lab0
sudo kill -INT $(pidof swift-guard-daemon)   # daemon 종료 (붙어 있던 XDP 자동 해제)
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
설정 파일은 `/etc/swift-guard/config.yaml`이다(예시: `config/swift-guard.yaml`). 로그 수준(`general.log_level`, 기본 `info`)과 WASM 모듈 자동 로드(`wasm.auto_load`)를 여기서 정한다. 로그 수준은 `-v` > `RUST_LOG` 환경변수 > `general.log_level` 순으로 적용된다. 이전 버전 설정 파일에만 있던 키(`general.work_dir`, `interfaces`, `rules` 등)는 `config key '...' is no longer supported and is ignored` 경고를 남기고 무시되므로, 업그레이드한 뒤에도 그대로 기동한다.

---

## 룰 매칭 규칙 요약

| 규칙 | 설명 |
|------|------|
| 매칭 키 | 출발지 IP prefix(`--src-ip`) 또는 목적지 IP prefix(`--dst-ip`) 중 **정확히 하나** |
| 평가 순서 | 출발지 룰 → (없거나 조건 불일치면) 목적지 룰 → 둘 다 아니면 통과 |
| prefix 우선순위 | 각 맵(출발지·목적지) 안에서 가장 긴 prefix가 이긴다(/32 > /24 > /8) |
| prefix당 룰 1개 | 출발지·목적지 맵별로 prefix당 1개. 같은 맵에 두 번째 룰을 넣으면 거부된다. label은 전체에서 유일하다. 포트별로 다른 동작이 필요하면 prefix를 나눈다 |
| 세부 조건 | 이긴 룰의 프로토콜·포트·TCP 플래그가 맞을 때만 액션을 실행한다. 맞지 않으면 목적지 룰로 넘어가고, 그것도 아니면 **통과**한다. 같은 맵의 더 짧은 prefix로 되돌아가 다시 찾지 않는다 |
| 프로토콜 | `tcp`, `udp`, `icmp`, `any`(기본값) |
| 포트·TCP 플래그 | 포트는 `N` 또는 `N-M`. 포트나 TCP 플래그 조건이 있는 룰은 **L4 헤더를 확인할 수 있는 패킷에만** 매치한다. ICMP(포트 없음), 조각의 두 번째 이후 조각, L4가 짧은 비조각 패킷(`tot_len − IHL×4`가 TCP 20B / UDP 8B 미만)과는 매치하지 않는다. 포트 범위에 0이 들어 있어도(예: `0-1023`) 마찬가지다 |
| IP 옵션 | IPv4 헤더 길이(IHL)만큼 옵션을 건너뛰고 L4 헤더를 읽는다. 옵션이 붙어 있어도 포트 룰이 똑같이 적용된다 |
| 조각(fragment) | 첫 조각은 L4 헤더가 온전하면 포트·플래그까지 평가한다. 두 번째 이후 조각에는 L4 헤더가 없으므로 IP·프로토콜만 쓰는 룰만 매치한다(포트 룰로 첫 조각이 막히면 재조립이 실패해 나머지도 전달되지 않는다). 조각 재조립이나 추적은 하지 않는다 |
| 무조건 차단 | 다음 패킷은 룰과 상관없이 DROP한다(`XDP verdicts`의 `invalid`). `pass` 룰로도 예외 처리할 수 없다: tiny fragment(첫 조각인데 TCP 20B / UDP 8B 헤더가 다 들어 있지 않음), offset이 1인 TCP 조각(RFC 1858), version≠4·IHL<5·IPv4 헤더 20B 미만·IHL이 가리키는 길이가 패킷보다 긴 패킷, IP 전체 길이(`tot_len`)가 IHL×4보다 작거나 받은 프레임보다 긴(프레임이 잘린) 패킷. 정상 스택은 이런 패킷을 만들지 않고, 비정상 헤더는 커널도 버린다. L4 헤더가 온전한지는 IP 헤더의 전체 길이(`tot_len`)로 판단한다. 그래서 짧은 프레임 뒤에 붙는 이더넷 패딩(최소 60B까지 0으로 채움)은 L4 헤더로 취급하지 않는다 |
| 액션 | `drop`, `pass`, `count`(통과하며 집계), `redirect`(`--redirect-if` 필요) |
| 미구현 | `--priority`, `--rate-limit`, `--expire`는 0이 아닌 값을 넣으면 거부된다(기본값 0은 허용). `--pkt-len`은 지정하면 거부된다([예시 9](#예시-9-거부되는-입력)) |
| 대상 트래픽 | XDP를 붙인 인터페이스로 **들어오는** IPv4 패킷. IPv6, ARP, 802.1Q VLAN 태그가 붙은 프레임은 검사 없이 통과한다(`non_ipv4`로 집계). NIC의 VLAN 오프로드로 태그가 떼어진 채 들어오면 IPv4로 검사된다 |

## 문제 해결

| 증상 | 확인 |
|------|------|
| `Failed to connect` | daemon이 실행 중인지, `--api-addr`와 `--api-server` 주소가 같은지(기본 `127.0.0.1:7654`) |
| `BPF object load failed` / `BTF is required` | `xdp_filter.o`를 `make -C src/bpf`로 다시 빌드한다(`-g`가 빠지면 BTF가 없다). 커널 5.10 이상인지 확인한다 |
| attach 실패 (driver) | `--mode generic`으로 재시도한다. 드라이버 지원 여부는 `ethtool -i eth0`로 확인한다 |
| `already attached` | 이미 붙어 있다. `xf detach <if>` 후 다시 붙이거나 `--force`를 쓴다 |
| `Total packets`가 0에서 늘지 않음 | `Total packets`는 룰에 매치한 패킷만 센다. `XDP rx packets`가 늘면 트래픽은 XDP에 도달하고 있고 룰이 매치하지 않는 것이다(`no_match`가 함께 는다). `XDP rx packets`도 그대로면 트래픽이 이 인터페이스로 들어오지 않는다 |
| `BPF object has no map 'xdp_stats_map'` | 이전 버전 `xdp_filter.o`로 daemon을 띄웠다. `make -C src/bpf`로 다시 빌드하고 다시 설치한다 |
| `... is not implemented yet` | `--priority`·`--rate-limit`·`--expire`에 0이 아닌 값, 또는 `--pkt-len`을 썼다. 해당 옵션을 빼고 다시 실행한다([예시 9](#예시-9-거부되는-입력)) |
| 룰을 넣었는데 매치가 안 됨 | [룰 매칭 규칙](#룰-매칭-규칙-요약)을 본다(같은 IP에 더 긴 prefix 룰이 있는지, 프로토콜·포트 조건, 목적지 룰이라면 같은 패킷에 매치하는 출발지 룰이 먼저 적용되지 않았는지). `xf list-rules --stats`로 매치 수를 확인한다 |
| WASM `unreachable` trap | 오래된 모듈 빌드다. 호스트 함수는 `#[link(wasm_import_module = "env")]`로 선언해야 한다(`wasm/modules/http_inspector.rs` 참고) |

자동 검증:
```bash
sudo tools/test/examples.sh        # 이 문서의 예시 전체 (PASS/FAIL)
sudo tools/test/e2e_check.sh       # 커널 기능 E2E (docs/linux-verification.md)
```
