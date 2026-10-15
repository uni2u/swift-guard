#!/usr/bin/env python3
"""Swift-Guard 파서 검증용 패킷 생성기 (python3 표준 라이브러리만 사용).

L4 파싱 경계(IP 옵션, 조각, tiny fragment, 비정상 IHL)를 재현하는 이더넷 프레임을
결정적인 바이트로 만든다. e2e_check.sh가 `bpftool prog run`(PROG_TEST_RUN)과 live 송신에 쓴다.

사용법:
  sg_pkt.py build <case> -o <file> [--src A] [--dst B] [--sport N] [--dport N] [--flags SYN,ACK]
                  [--src-mac M] [--dst-mac M] [--pad N]
  sg_pkt.py send  <case> --ifname <if> --dst-mac <mac> [--count N] [같은 옵션]
        AF_PACKET SOCK_RAW로 만든 이더넷 프레임을 그대로 송신한다(root 필요, Linux 전용).
        출발지 MAC은 /sys/class/net/<if>/address에서 읽는다(--src-mac로 덮어쓸 수 있다).
  sg_pkt.py dump  <case> [같은 옵션]     # 프레임을 16진수로 출력
  sg_pkt.py --selftest                  # 손계산한 바이트·필드와 대조 (종료 코드 0/1)
  sg_pkt.py --list                      # case 목록

case:
  tcp               IHL=5, TCP 20B (payload 없음)
  tcp-opt           IHL=6, 옵션 NOP x4 (01 01 01 01), TCP 20B
  tcp-opt-decoy     IHL=6, 옵션 01 01 1f 90 (IHL을 무시하는 파서는 sport=257, dport=8080으로 오독), TCP 20B
  udp               IHL=5, UDP 8B (payload 없음)
  frag-first-full   TCP, MF=1, off=0, TCP 20B + payload 20B
  tiny-frag         TCP, MF=1, off=0, TCP 앞 8B만 (sport, dport, seq) — RFC 1858 tiny fragment
  frag-nonfirst     TCP, MF=0, off=185, payload 40B. byte 0-1 = --sport, 2-3 = --dport (기본 1f 90)
  frag-off1         TCP, MF=0, off=1, payload 16B (0) — RFC 1858 겹침 공격
  udp-frag-nonfirst UDP, MF=0, off=185, payload 40B. byte 0-1 = --sport, 2-3 = --dport
  tcp-trunc         TCP, MF=0, off=0, L4 10B (TCP 헤더 잘림, 조각 아님)
  ihl4              version 4, IHL=4 (비정상), 뒤에 TCP 20B
  ihl-trunc         IHL=15 (헤더 60B 주장), 실제 IP 이하 길이 40B
  arp               EtherType 0x0806 ARP request (비IPv4)
  tiny-frag-pad     tiny-frag를 이더넷 최소 60B까지 0으로 패딩 (tot_len 28 그대로, 패딩 18B)
  udp-pad           udp를 60B까지 0으로 패딩 (tot_len 28 그대로, 패딩 18B) — 정상 짧은 UDP

--pad N: 프레임(FCS 제외)을 N바이트까지 0으로 채운다(이미 길면 그대로). IP tot_len은 바꾸지 않는다.
  실제 NIC는 60B 미만 프레임에 패딩을 붙여 보내지만, AF_PACKET으로 veth에 보내면 커널이 패딩하지
  않으므로 패딩 경로(L4 완전성을 data_end가 아니라 tot_len으로 판단하는지)는 명시적으로 재현한다.

기본값: --src 10.200.0.2 --dst 10.200.0.1 --sport 12345 --dport 8080 --flags SYN
        --src-mac 02:00:00:00:00:02 --dst-mac 02:00:00:00:00:01
고정값: IP id 0x1234, TTL 64, TOS 0, TCP seq 1, ack 0, window 0xffff.
IP 헤더 체크섬은 항상 계산한다. TCP/UDP 체크섬은 L4 세그먼트 전체가 한 패킷에 있을 때만 계산하고
(tcp, tcp-opt, tcp-opt-decoy, udp), 조각·잘린 패킷에서는 0이다.
"""

import argparse
import ipaddress
import socket
import struct
import sys

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IP_MF = 0x2000
IP_ID = 0x1234
TTL = 64
TCP_SEQ = 1
TCP_WIN = 0xFFFF

TCP_FLAG_BITS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "ACK": 0x10, "URG": 0x20}

CASES = [
    "tcp", "tcp-opt", "tcp-opt-decoy", "udp", "frag-first-full", "tiny-frag", "frag-nonfirst",
    "frag-off1", "udp-frag-nonfirst", "tcp-trunc", "ihl4", "ihl-trunc", "arp",
    "tiny-frag-pad", "udp-pad",
]
ETH_MIN_FRAME = 60   # 이더넷 최소 프레임 64B - FCS 4B
# 패딩 별칭: case → (기본 case, 패딩 목표 길이)
PAD_CASES = {"tiny-frag-pad": ("tiny-frag", ETH_MIN_FRAME), "udp-pad": ("udp", ETH_MIN_FRAME)}

DEFAULTS = dict(src="10.200.0.2", dst="10.200.0.1", sport=12345, dport=8080, flags="SYN",
                src_mac="02:00:00:00:00:02", dst_mac="02:00:00:00:00:01", pad=0)


def csum16(data):
    """인터넷 체크섬(RFC 1071). 홀수 길이는 0으로 채운다."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for (w,) in struct.iter_unpack("!H", data):
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def parse_flags(text):
    v = 0
    for name in filter(None, (p.strip().upper() for p in text.split(","))):
        if name not in TCP_FLAG_BITS:
            raise ValueError("unknown TCP flag '%s' (FIN,SYN,RST,PSH,ACK,URG)" % name)
        v |= TCP_FLAG_BITS[name]
    return v


def mac_bytes(text):
    parts = text.split(":")
    if len(parts) != 6:
        raise ValueError("bad MAC '%s'" % text)
    return bytes(int(p, 16) for p in parts)


def ip_bytes(text):
    return ipaddress.IPv4Address(text).packed


def eth(dst_mac, src_mac, ethertype):
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", ethertype)


def ipv4(src, dst, proto, payload, *, ihl=5, options=b"", frag=0, tot_len=None, csum_len=None):
    """IPv4 헤더 + payload. ihl은 첫 바이트에 그대로 들어가고 options는 그 뒤에 붙는다.
    tot_len 기본값 = 실제 헤더(20+옵션) + payload. 체크섬은 실제 헤더 바이트 전체로 계산한다."""
    hdr_len = 20 + len(options)
    if tot_len is None:
        tot_len = hdr_len + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, tot_len, IP_ID, frag, TTL, proto, 0,
                      ip_bytes(src), ip_bytes(dst)) + options
    c = csum16(hdr if csum_len is None else hdr[:csum_len])
    hdr = hdr[:10] + struct.pack("!H", c) + hdr[12:]
    return hdr + payload


def pseudo(src, dst, proto, length):
    return ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, proto, length)


def tcp_hdr(a, payload=b"", with_csum=True):
    h = struct.pack("!HHIIBBHHH", a.sport, a.dport, TCP_SEQ, 0, 5 << 4, parse_flags(a.flags),
                    TCP_WIN, 0, 0)
    seg = h + payload
    if with_csum:
        c = csum16(pseudo(a.src, a.dst, IPPROTO_TCP, len(seg)) + seg)
        seg = seg[:16] + struct.pack("!H", c) + seg[18:]
    return seg


def udp_hdr(a, payload=b"", with_csum=True):
    seg = struct.pack("!HHHH", a.sport, a.dport, 8 + len(payload), 0) + payload
    if with_csum:
        c = csum16(pseudo(a.src, a.dst, IPPROTO_UDP, len(seg)) + seg) or 0xFFFF
        seg = seg[:6] + struct.pack("!H", c) + seg[8:]
    return seg


def decoy_payload(a, n=40):
    """후속 조각 payload: IHL/조각을 무시하는 파서가 포트로 오독할 바이트를 앞 4B에 둔다."""
    return struct.pack("!HH", a.sport, a.dport) + b"\x00" * (n - 4)


def build_l3(case, a):
    """case → (ethertype, L3 바이트)"""
    s, d = a.src, a.dst
    if case == "tcp":
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, tcp_hdr(a))
    if case == "tcp-opt":
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, tcp_hdr(a), ihl=6, options=b"\x01\x01\x01\x01")
    if case == "tcp-opt-decoy":
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, tcp_hdr(a), ihl=6, options=b"\x01\x01\x1f\x90")
    if case == "udp":
        return ETH_P_IP, ipv4(s, d, IPPROTO_UDP, udp_hdr(a))
    if case == "frag-first-full":
        # 첫 조각의 데이터 길이는 8의 배수여야 한다: TCP 20 + payload 20 = 40
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, tcp_hdr(a, b"\x00" * 20, with_csum=False), frag=IP_MF)
    if case == "tiny-frag":
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, tcp_hdr(a, with_csum=False)[:8], frag=IP_MF)
    if case == "frag-nonfirst":
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, decoy_payload(a), frag=185)
    if case == "frag-off1":
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, b"\x00" * 16, frag=1)
    if case == "udp-frag-nonfirst":
        return ETH_P_IP, ipv4(s, d, IPPROTO_UDP, decoy_payload(a), frag=185)
    if case == "tcp-trunc":
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, tcp_hdr(a, with_csum=False)[:10])
    if case == "ihl4":
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, tcp_hdr(a), ihl=4)
    if case == "ihl-trunc":
        # IHL=15(60B)을 주장하지만 IP 이하 실제 길이는 40B. tot_len=40, 체크섬은 앞 20B로 계산
        return ETH_P_IP, ipv4(s, d, IPPROTO_TCP, tcp_hdr(a, with_csum=False), ihl=15, csum_len=20)
    if case == "arp":
        smac = mac_bytes(a.src_mac)
        arp = struct.pack("!HHBBH", 1, ETH_P_IP, 6, 4, 1) + smac + ip_bytes(s) + b"\x00" * 6 + ip_bytes(d)
        return ETH_P_ARP, arp
    raise ValueError("unknown case '%s' (use --list)" % case)


def build_frame(case, a):
    base, pad = PAD_CASES.get(case, (case, 0))
    pad = max(pad, getattr(a, "pad", 0) or 0)
    et, l3 = build_l3(base, a)
    f = eth(a.dst_mac, a.src_mac, et) + l3
    if len(f) < pad:
        f += b"\x00" * (pad - len(f))
    return f


def ns(**over):
    d = dict(DEFAULTS)
    d.update(over)
    return argparse.Namespace(**d)


# ------------------------------------------------------------------ selftest
# 기대 바이트는 손으로 계산했다(기본 옵션: 10.200.0.2 → 10.200.0.1, 12345 → 8080, SYN).
#   IP 체크섬 예 (tiny-frag): 4500+001c+1234+2000+4006+0000+0ac8+0002+0ac8+0001 = 0xcce9 → ~ = 0x3316
#   TCP 체크섬 (tcp/tcp-opt): 가상헤더 0ac8+0002+0ac8+0001+0006+0014 = 0x15ad
#       + 3039+1f90+0000+0001+0000+0000+5002+ffff+0000+0000 → 0x1b578 → 접기 0xb579 → ~ = 0x4a86
ETH_DEF = "020000000001" "020000000002"
TCP_DEF = "30391f90" "00000001" "00000000" "5002ffff" "4a860000"
GOLDEN = {
    # IHL 5: 4500+0028+1234+0000+4006+0ac8+0002+0ac8+0001 = 0xacf5 → ~ = 0x530a
    "tcp": ETH_DEF + "0800" + "45000028" "12340000" "4006530a" "0ac80002" "0ac80001" + TCP_DEF,
    # IHL 6, tot_len 44: 4600+002c+1234+4006+0ac8+0002+0ac8+0001+0101+0101 = 0xaffb → ~ = 0x5004
    "tcp-opt": ETH_DEF + "0800" + "4600002c" "12340000" "40065004" "0ac80002" "0ac80001" "01010101"
    + TCP_DEF,
    # 옵션 01 01 1f 90: 0xadf9 + 0101 + 1f90 = 0xce8a → ~ = 0x3175
    "tcp-opt-decoy": ETH_DEF + "0800" + "4600002c" "12340000" "40063175" "0ac80002" "0ac80001"
    "01011f90" + TCP_DEF,
    # MF, tot_len 28, TCP 8B(sport, dport, seq). 체크섬 0x3316 (위 주석)
    "tiny-frag": ETH_DEF + "0800" + "4500001c" "12342000" "40063316" "0ac80002" "0ac80001"
    "30391f90" "00000001",
    # off=1, tot_len 36: 4524+1234+0001+4006+0ac8+0002+0ac8+0001 = 0xacf2 → ~ = 0x530d
    "frag-off1": ETH_DEF + "0800" + "45000024" "12340001" "4006530d" "0ac80002" "0ac80001"
    + "00" * 16,
    # off=185(0x00b9), tot_len 60: 453c+1234+00b9+4006+0ac8+0002+0ac8+0001 = 0xadc2 → ~ = 0x523d
    "frag-nonfirst": ETH_DEF + "0800" + "4500003c" "123400b9" "4006523d" "0ac80002" "0ac80001"
    "30391f90" + "00" * 36,
    # IHL 15, tot_len 40, 앞 20B 체크섬: 4f28+1234+4006+0ac8+0002+0ac8+0001 = 0xb6f5 → ~ = 0x490a
    # TCP 20B는 체크섬 0 (with_csum=False)
    "ihl-trunc": ETH_DEF + "0800" + "4f000028" "12340000" "4006490a" "0ac80002" "0ac80001"
    "30391f90" "00000001" "00000000" "5002ffff" "00000000",
    # UDP, tot_len 28: 451c+1234+0000+4011+0ac8+0002+0ac8+0001 = 0xacf4 → ~ = 0x530b
    # UDP 체크섬: 가상헤더 0ac8+0002+0ac8+0001+0011+0008 = 0x15ac + 3039+1f90+0008+0000 = 0x657d → ~ = 0x9a82
    "udp": ETH_DEF + "0800" + "4500001c" "12340000" "4011530b" "0ac80002" "0ac80001" "30391f90" "00089a82",
    # 패딩: 42B → 60B, 뒤에 0 18바이트. 헤더(tot_len 포함)는 패딩 전과 같다
    "tiny-frag-pad": ETH_DEF + "0800" + "4500001c" "12342000" "40063316" "0ac80002" "0ac80001"
    "30391f90" "00000001" + "00" * 18,
    "udp-pad": ETH_DEF + "0800" + "4500001c" "12340000" "4011530b" "0ac80002" "0ac80001" "30391f90" "00089a82"
    + "00" * 18,
    # ARP request: htype 1, ptype 0800, hlen 6, plen 4, op 1, sha, spa, tha 0, tpa
    "arp": ETH_DEF + "0806" + "0001080006040001" "020000000002" "0ac80002" "000000000000" "0ac80001",
}

# 구조 검사 기대값: (프레임 길이, ethertype, 첫 바이트(ver/ihl), proto, frag_off, tot_len, tot_len 기준 L4 바이트 수)
# 프레임 길이 - 14 - tot_len = 패딩(0이어야 함)
STRUCT = {
    "tcp":               (54, ETH_P_IP, 0x45, 6, 0x0000, 40, 20),
    "tcp-opt":           (58, ETH_P_IP, 0x46, 6, 0x0000, 44, 20),
    "tcp-opt-decoy":     (58, ETH_P_IP, 0x46, 6, 0x0000, 44, 20),
    "udp":               (42, ETH_P_IP, 0x45, 17, 0x0000, 28, 8),
    "frag-first-full":   (74, ETH_P_IP, 0x45, 6, 0x2000, 60, 40),
    "tiny-frag":         (42, ETH_P_IP, 0x45, 6, 0x2000, 28, 8),
    "frag-nonfirst":     (74, ETH_P_IP, 0x45, 6, 0x00B9, 60, 40),
    "frag-off1":         (50, ETH_P_IP, 0x45, 6, 0x0001, 36, 16),
    "udp-frag-nonfirst": (74, ETH_P_IP, 0x45, 17, 0x00B9, 60, 40),
    "tcp-trunc":         (44, ETH_P_IP, 0x45, 6, 0x0000, 30, 10),
    "ihl4":              (54, ETH_P_IP, 0x44, 6, 0x0000, 40, None),   # IHL*4=16 < 20: L4 위치 정의 불가
    "ihl-trunc":         (54, ETH_P_IP, 0x4F, 6, 0x0000, 40, None),   # IHL*4=60 > 40: L4 위치가 패킷 밖
    "arp":               (42, ETH_P_ARP, None, None, None, None, None),
    "tiny-frag-pad":     (60, ETH_P_IP, 0x45, 6, 0x2000, 28, 8),      # 패딩 18B
    "udp-pad":           (60, ETH_P_IP, 0x45, 17, 0x0000, 28, 8),     # 패딩 18B
}


def selftest():
    fails = 0

    def check(cond, msg):
        nonlocal fails
        if cond:
            print("[ok]   " + msg)
        else:
            print("[FAIL] " + msg)
            fails += 1

    a = ns()
    check(csum16(bytes.fromhex("45000073000040004011" "0000" "c0a80001c0a800c7")) == 0xB861,
          "csum16 RFC 1071 예제 (c0a8 0001 → c0a8 00c7) = 0xb861")
    for case, hexs in GOLDEN.items():
        got = build_frame(case, a).hex()
        check(got == hexs, "%-17s 손계산 바이트와 일치" % case + ("" if got == hexs else "\n       want %s\n       got  %s" % (hexs, got)))

    for case in CASES:
        f = build_frame(case, a)
        flen, et, vihl, proto, frag, tot, l4n = STRUCT[case]
        check(len(f) == flen, "%-17s 프레임 길이 %d" % (case, flen))
        check(struct.unpack("!H", f[12:14])[0] == et, "%-17s EtherType 0x%04x" % (case, et))
        if vihl is None:
            continue
        ip = f[14:]
        ihl = ip[0] & 0x0F
        check(ip[0] == vihl, "%-17s version/IHL 바이트 0x%02x (ihl*4=%d)" % (case, vihl, ihl * 4))
        check(ip[9] == proto, "%-17s protocol %d" % (case, proto))
        check(struct.unpack("!H", ip[6:8])[0] == frag,
              "%-17s frag_off 0x%04x (MF=%d off=%d)" % (case, frag, bool(frag & IP_MF), frag & 0x1FFF))
        padn = len(ip) - tot
        check(struct.unpack("!H", ip[2:4])[0] == tot and padn >= 0 and ip[tot:] == b"\x00" * padn,
              "%-17s tot_len %d, 그 뒤 0 패딩 %dB" % (case, tot, padn))
        check((padn > 0) == (case in PAD_CASES), "%-17s 패딩은 *-pad case에만" % case)
        hl = min(ihl * 4, tot) if ihl >= 5 else 20
        check(csum16(ip[:min(hl, 20) if case == "ihl-trunc" else hl]) == 0, "%-17s IP 헤더 체크섬 검증" % case)
        if l4n is not None:
            check(tot - ihl * 4 == l4n, "%-17s tot_len 기준 IHL 뒤 L4 바이트 %d" % (case, l4n))
    # 세부 의미 검사
    f = build_frame("tcp-trunc", a)
    check(f[14 + 20:] == bytes.fromhex("30391f90000000010000"), "tcp-trunc         L4 10B = sport dport seq ack[0:2]")
    f = build_frame("udp-frag-nonfirst", ns(dport=5353))
    check(f[14 + 20:14 + 24] == bytes.fromhex("303914e9"), "udp-frag-nonfirst --dport 5353 → payload byte 2-3 = 14 e9")
    f = build_frame("tcp-opt", ns(src="10.77.0.3", flags="ACK"))
    check(f[14 + 24 + 13] == 0x10 and f[26:30] == bytes([10, 77, 0, 3]),
          "tcp-opt --flags ACK --src 10.77.0.3 → TCP byte 13 = 0x10, saddr 0a4d0003")
    f = build_frame("tcp-opt", a)
    check(csum16(pseudo(a.src, a.dst, 6, 20) + f[14 + 24:]) == 0, "tcp-opt           TCP 체크섬 검증 (가상 헤더 포함)")
    f = build_frame("udp", a)
    check(csum16(pseudo(a.src, a.dst, 17, 8) + f[14 + 20:]) == 0, "udp               UDP 체크섬 검증 (가상 헤더 포함)")
    f = build_frame("tiny-frag", ns(pad=60))
    check(f == build_frame("tiny-frag-pad", a), "--pad 60 tiny-frag == tiny-frag-pad")
    check(build_frame("tcp", ns(pad=60)) == build_frame("tcp", a) + b"\x00" * 6, "--pad 60 tcp (54B) → 6B 패딩")
    check(build_frame("frag-nonfirst", ns(pad=60)) == build_frame("frag-nonfirst", a), "--pad 60: 74B 프레임은 그대로")
    print("selftest: %s (%d fail)" % ("PASS" if fails == 0 else "FAIL", fails))
    return 0 if fails == 0 else 1


# ------------------------------------------------------------------ send
def iface_mac(ifname):
    with open("/sys/class/net/%s/address" % ifname) as fh:
        return fh.read().strip()


def send(case, a):
    if not hasattr(socket, "AF_PACKET"):
        sys.exit("send: AF_PACKET 미지원 OS (Linux 전용)")
    if a.src_mac_given is None:
        a.src_mac = iface_mac(a.ifname)
    frame = build_frame(case, a)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        s.bind((a.ifname, 0))
        for _ in range(a.count):
            s.send(frame)
    finally:
        s.close()
    print("sent %d x %s (%d bytes) on %s" % (a.count, case, len(frame), a.ifname))


def main(argv):
    if "--selftest" in argv:
        return selftest()
    if "--list" in argv:
        print("\n".join(CASES))
        return 0
    p = argparse.ArgumentParser(prog="sg_pkt.py", description="Swift-Guard 파서 검증용 패킷 생성기")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("case", choices=CASES)
        sp.add_argument("--src", default=DEFAULTS["src"])
        sp.add_argument("--dst", default=DEFAULTS["dst"])
        sp.add_argument("--sport", type=int, default=DEFAULTS["sport"])
        sp.add_argument("--dport", type=int, default=DEFAULTS["dport"])
        sp.add_argument("--flags", default=DEFAULTS["flags"], help="TCP 플래그 (예: SYN,ACK)")
        sp.add_argument("--src-mac", dest="src_mac_given", default=None)
        sp.add_argument("--pad", type=int, default=0,
                        help="프레임(FCS 제외)을 N바이트까지 0으로 채움 (이더넷 최소는 60)")

    b = sub.add_parser("build", help="프레임을 파일로 저장")
    common(b)
    b.add_argument("--dst-mac", default=DEFAULTS["dst_mac"])
    b.add_argument("-o", "--output", required=True)
    d = sub.add_parser("dump", help="프레임을 16진수로 출력")
    common(d)
    d.add_argument("--dst-mac", default=DEFAULTS["dst_mac"])
    s = sub.add_parser("send", help="AF_PACKET으로 송신")
    common(s)
    s.add_argument("--ifname", required=True)
    s.add_argument("--dst-mac", required=True)
    s.add_argument("--count", type=int, default=1)
    a = p.parse_args(argv)

    if not 0 <= a.pad <= 9000:
        p.error("--pad out of range: %d" % a.pad)
    for port in (a.sport, a.dport):
        if not 0 <= port <= 65535:
            p.error("port out of range: %d" % port)
    try:
        parse_flags(a.flags)
        ip_bytes(a.src)
        ip_bytes(a.dst)
        mac_bytes(a.dst_mac)
        if a.src_mac_given is not None:
            mac_bytes(a.src_mac_given)
    except ValueError as e:
        p.error(str(e))
    a.src_mac = a.src_mac_given or DEFAULTS["src_mac"]

    if a.cmd == "send":
        send(a.case, a)
        return 0
    frame = build_frame(a.case, a)
    if a.cmd == "dump":
        print(frame.hex())
        return 0
    with open(a.output, "wb") as fh:
        fh.write(frame)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
