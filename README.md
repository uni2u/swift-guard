# swift-guard
Secure WebAssembly Inspection Framework for Traffic using Guard

## Architecture
```
[커널 공간]
    └── [XDP 프로그램]
          ├── [패킷 분류 엔진] - 최적화된 5-튜플+ 분류
          ├── [BPF 맵 클러스터] - 정책 및 상태 저장소
          └── [리다이렉션 메커니즘] - 패킷 경로 재구성

[사용자 공간]
    ├── [Rust 제어 데몬]
    │     ├── [libbpf-rs 바인딩] - 커널 인터페이스
    │     ├── [맵 관리 로직] - 정책 CRUD 작업
    │     └── [텔레메트리 수집기] - 성능 및 작동 메트릭
    │
    └── [CLI 인터페이스]
          ├── [명령 파서] - 구조화된 인자 처리
          └── [정책 유효성 검증기] - 구문 및 의미 검증
```

### CLI
```
xdp-filter - High-performance XDP packet filtering and redirection framework

USAGE:
    xdp-filter <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    attach      Attach XDP program to network interface
    detach      Detach XDP program from network interface
    add-rule    Add packet filtering and redirection rule
    list-rules  List active filtering rules
    delete-rule Delete filtering rule
    stats       Show statistics about packet processing
    help        Prints this message or the help of the given subcommand(s)

---------------------------------

xdp-filter-attach - Attach XDP program to network interface

USAGE:
    xdp-filter attach <interface> [FLAGS] [OPTIONS]

ARGS:
    <interface>    Network interface name

FLAGS:
    -h, --help       Prints help information
    --force          Skip check for XDP support

OPTIONS:
    --mode <mode>    Attach mode (default: driver, options: driver, offload, generic)

---------------------------------

xdp-filter-add-rule - Add packet filtering and redirection rule

USAGE:
    xdp-filter add-rule --action <action> [OPTIONS]

OPTIONS:
    --src-ip <src_ip>            Source IP address (format: a.b.c.d or a.b.c.d/prefix)
    --dst-ip <dst_ip>            Destination IP address (format: a.b.c.d or a.b.c.d/prefix)
    --src-port <src_port>        Source port or port range (format: port or port1-port2)
    --dst-port <dst_port>        Destination port or port range (format: port or port1-port2)
    --protocol <protocol>        Protocol (options: tcp, udp, icmp, any)
    --tcp-flags <tcp_flags>      TCP flags to match (format: SYN,ACK,FIN,RST,PSH,URG)
    --pkt-len <pkt_len>          Packet length range to match (format: min-max)
    --action <action>            Action (options: pass, drop, redirect, count)
    --redirect-if <redirect_if>  Redirect interface (required for redirect action)
    --priority <priority>        Rule priority (higher number = higher priority, default: 0)
    --rate-limit <rate_limit>    Rate limit in packets per second (0 = unlimited)
    --expire <expire>            Rule expiration time in seconds (0 = no expiration)
    --label <label>              Rule name/label for identification
    -h, --help                   Prints help information
```

#### example
```
# 인터페이스에 XDP 프로그램 연결
$ xdp-filter attach eth0 --mode driver

# 다양한 필터링 규칙 추가 예시
$ xdp-filter add-rule --src-ip 192.168.1.100 --dst-port 80 --protocol tcp --action drop --label "block-web-access"

$ xdp-filter add-rule --src-ip 10.0.0.0/8 --dst-port 22 --protocol tcp --tcp-flags SYN --action redirect --redirect-if wasm0 --label "inspect-ssh-connections"

$ xdp-filter add-rule --src-port 53 --protocol udp --action count --priority 10 --label "monitor-dns"

# 활성 규칙 나열
$ xdp-filter list-rules --stats

# 통계 확인
$ xdp-filter stats --interval 5

# 규칙 삭제
$ xdp-filter delete-rule --label "block-web-access"
```
