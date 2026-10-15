#!/usr/bin/env python3
"""PROG_TEST_RUN verification of xdp_filter.o against plan C2 (run as root in privileged container)."""
import json, os, socket, struct, subprocess, sys, tempfile

OBJ = sys.argv[1]
PIN = "/sys/fs/bpf/sgt"
MAPS = "/sys/fs/bpf/sgtm"
XDP_DROP, XDP_PASS, XDP_REDIRECT = 1, 2, 4
SLOTS = ["RX", "DROP", "PASS", "REDIRECT", "COUNT", "NO_MATCH", "INVALID", "NON_IPV4", "ACTION_ERR"]

def sh(*a, check=True):
    r = subprocess.run(a, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"cmd failed: {a}\n{r.stdout}\n{r.stderr}")
    return r

def hexs(b): return [f"{x:02x}" for x in b]

def ipb(s): return socket.inet_aton(s)

# ---------- setup ----------
os.makedirs("/sys/fs/bpf", exist_ok=True)
subprocess.run(["mount", "-t", "bpf", "bpf", "/sys/fs/bpf"], capture_output=True)
for p in (PIN, MAPS): subprocess.run(["rm", "-rf", p])
r = sh("bpftool", "prog", "loadall", OBJ, PIN, "type", "xdp", "pinmaps", MAPS, check=False)
if r.returncode != 0:
    print("VERIFIER/LOAD FAIL\n", r.stdout[-4000:], r.stderr[-6000:]); sys.exit(1)
print("verifier: prog loadall OK")
PROG = PIN + "/xdp_filter_func"
info = json.loads(sh("bpftool", "-j", "prog", "show", "pinned", PROG).stdout)
print(f"prog id={info['id']} xlated={info.get('bytes_xlated')}B jited={info.get('bytes_jited')}B")
maps = sorted(os.listdir(MAPS)); print("maps:", maps)
xinfo = json.loads(sh("bpftool", "-j", "map", "show", "pinned", MAPS + "/xdp_stats_map").stdout)
print("xdp_stats_map:", {k: xinfo[k] for k in ("type", "bytes_key", "bytes_value", "max_entries")})

ANY, TCP, UDP, ICMP = 255, 6, 17, 1
A_PASS, A_DROP, A_REDIR, A_COUNT = 1, 2, 3, 4

def rule_val(action, proto=ANY, sp=(0, 65535), dp=(0, 65535), flags=0, ifidx=0, label=b""):
    v = struct.pack("<IBBHHHHB", 0, action, proto, sp[0], sp[1], dp[0], dp[1], flags)
    v += b"\0"  # pad to 16
    v += struct.pack("<III", ifidx, 0, 0) + label.ljust(32, b"\0") + b"\0" * 4 + b"\0" * 24
    assert len(v) == 88, len(v)
    return v

def add_rule(mapname, ip, val):
    key = struct.pack("<I", 32) + ipb(ip)
    sh("bpftool", "map", "update", "pinned", f"{MAPS}/{mapname}", "key", "hex", *hexs(key), "value", "hex", *hexs(val))

def rule_pkts(mapname, ip):
    key = struct.pack("<I", 32) + ipb(ip)
    j = json.loads(sh("bpftool", "-j", "map", "lookup", "pinned", f"{MAPS}/{mapname}", "key", "hex", *hexs(key)).stdout)
    val = bytes(int(x, 16) for x in j["value"])
    return struct.unpack_from("<Q", val, 64)[0]

def global_stats():
    j = json.loads(sh("bpftool", "-j", "map", "dump", "pinned", f"{MAPS}/stats_map").stdout)
    tot = 0
    for e in j:
        for c in e["values"]:
            tot += struct.unpack_from("<Q", bytes(int(x, 16) for x in c["value"]), 0)[0]
    return tot

def xdp_counters():
    j = json.loads(sh("bpftool", "-j", "map", "dump", "pinned", f"{MAPS}/xdp_stats_map").stdout)
    out = {}
    for e in j:
        k = struct.unpack("<I", bytes(int(x, 16) for x in e["key"]))[0]
        p = b = 0
        for c in e["values"]:
            pp, bb = struct.unpack("<QQ", bytes(int(x, 16) for x in c["value"]))
            p += pp; b += bb
        out[SLOTS[k]] = (p, b)
    return out

# Rules
add_rule("filter_rules", "10.77.0.1", rule_val(A_DROP, TCP, dp=(8080, 8080)))      # R1
add_rule("filter_rules", "10.77.0.2", rule_val(A_DROP))                            # R2 IP-only
add_rule("filter_rules", "10.77.0.3", rule_val(A_DROP, TCP, flags=0x02))           # R3 SYN
add_rule("filter_rules", "10.77.0.4", rule_val(A_COUNT, UDP, dp=(5353, 5353)))     # R4
add_rule("filter_rules", "10.77.0.5", rule_val(A_DROP, ANY, dp=(0, 1023)))          # R5 port range incl 0 (D3)
add_rule("filter_rules", "10.77.0.6", rule_val(A_PASS))                            # R6 pass
add_rule("filter_rules", "10.77.0.7", rule_val(A_REDIR, ifidx=99))                 # R7 redirect, no target
add_rule("filter_rules", "10.77.0.8", rule_val(A_REDIR, ifidx=1))                  # R8 redirect lo
add_rule("filter_rules", "10.77.0.9", rule_val(7))                                 # R9 unknown action
add_rule("dst_rules", "10.88.0.1", rule_val(A_DROP))                               # D1 dst drop
redir_val = struct.pack("<I", 1) + b"lo".ljust(16, b"\0")
sh("bpftool", "map", "update", "pinned", f"{MAPS}/redirect_map", "key", "hex", *hexs(struct.pack("<I", 1)), "value", "hex", *hexs(redir_val))

# ---------- packet builder ----------
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack(f"!{len(b)//2}H", b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

ETH_IP = b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00"

def ipv4(src, dst, proto, payload, ihl=5, opts=b"", mf=0, off=0, ver=4, tot=None):
    opts = opts.ljust((ihl - 5) * 4, b"\x01") if ihl >= 5 else b""
    if tot is None:
        tot = ihl * 4 + len(payload) if ihl >= 5 else 20 + len(payload)
    frag = (0x2000 if mf else 0) | off
    h = struct.pack("!BBHHHBBH4s4s", (ver << 4) | ihl, 0, tot, 0x1234, frag, 64, proto, 0, ipb(src), ipb(dst)) + opts
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    return ETH_IP + h + payload

def tcp(sp=40000, dp=80, flags=0x02, plen=0):
    return struct.pack("!HHIIBBHHH", sp, dp, 1, 0, 5 << 4, flags, 65535, 0, 0) + b"A" * plen

def udp(sp=40000, dp=53, plen=0):
    return struct.pack("!HHHH", sp, dp, 8 + plen, 0) + b"U" * plen

ICMP_ECHO = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"P" * 32
OTHER = "10.99.0.9"
DST = "10.66.0.1"

cases = []  # (name, frame, expected_ret, expected_slot, extra_check)
C = lambda *a, **k: cases.append((a, k))

# --- C2 parser cases ---
C("P1 tcp ihl5 .1 dport8080", ipv4("10.77.0.1", DST, TCP, tcp(dp=8080)), XDP_DROP, "DROP")
C("P2 tcp ihl6 NOP .1 dport8080", ipv4("10.77.0.1", DST, TCP, tcp(dp=8080), ihl=6, opts=b"\x01" * 4), XDP_DROP, "DROP")
C("P2b tcp ihl15 opts .1 dport8080", ipv4("10.77.0.1", DST, TCP, tcp(dp=8080), ihl=15, opts=b"\x01" * 40), XDP_DROP, "DROP")
C("P3 tcp ihl6 decoy(1f90) .1 dport80", ipv4("10.77.0.1", DST, TCP, tcp(dp=80), ihl=6, opts=b"\x01\x01\x1f\x90"), XDP_PASS, "NO_MATCH")
C("P4 frag-first-full MF .1 dport8080", ipv4("10.77.0.1", DST, TCP, tcp(dp=8080, plen=16), mf=1), XDP_DROP, "DROP")
C("P5 tiny-frag tcp8B MF .2 (IP drop rule)", ipv4("10.77.0.2", DST, TCP, tcp(dp=8080)[:8], mf=1), XDP_DROP, "INVALID")
C("P6 tiny-frag tcp8B MF no-rule", ipv4(OTHER, DST, TCP, tcp(dp=8080)[:8], mf=1), XDP_DROP, "INVALID")
C("P6b tiny-frag tcp19B MF ihl6 no-rule", ipv4(OTHER, DST, TCP, tcp()[:19], ihl=6, mf=1), XDP_DROP, "INVALID")
C("P6c tiny-frag udp4B MF no-rule", ipv4(OTHER, DST, UDP, udp()[:4], mf=1), XDP_DROP, "INVALID")
nonfirst_payload = b"\0\0\x1f\x90" + b"\0" * 36
C("P7 frag-nonfirst off185 .1 (payload 1f90)", ipv4("10.77.0.1", DST, TCP, nonfirst_payload, off=185), XDP_PASS, "NO_MATCH")
C("P7b frag-nonfirst-last off185 MF=0 .1 short 4B", ipv4("10.77.0.1", DST, TCP, nonfirst_payload[:4], off=185), XDP_PASS, "NO_MATCH")
C("P8 frag-nonfirst off185 .2 (IP-only rule)", ipv4("10.77.0.2", DST, TCP, nonfirst_payload, off=185), XDP_DROP, "DROP")
C("P8b frag-nonfirst short 4B .2 MF", ipv4("10.77.0.2", DST, TCP, b"abcd", off=185, mf=1), XDP_DROP, "DROP")
C("P9 frag-off1 tcp no-rule", ipv4(OTHER, DST, TCP, b"\0" * 40, off=1, mf=1), XDP_DROP, "INVALID")
C("P9b frag-off1 udp no-rule (only TCP rejected)", ipv4(OTHER, DST, UDP, b"\0" * 40, off=1), XDP_PASS, "NO_MATCH")
C("P10 tcp-trunc MF=0 10B .2", ipv4("10.77.0.2", DST, TCP, tcp()[:10]), XDP_DROP, "DROP")
C("P11 tcp-trunc MF=0 10B .1 (port rule)", ipv4("10.77.0.1", DST, TCP, tcp(dp=8080)[:10]), XDP_PASS, "NO_MATCH")
C("P11b udp-trunc MF=0 4B .4 (port rule)", ipv4("10.77.0.4", DST, UDP, udp(dp=5353)[:4]), XDP_PASS, "NO_MATCH")
C("P12 ihl4 no-rule", ipv4(OTHER, DST, TCP, tcp(), ihl=4), XDP_DROP, "INVALID")
C("P12b ihl0 .2", ipv4("10.77.0.2", DST, TCP, tcp(), ihl=0), XDP_DROP, "INVALID")
C("P12c version6 in IPv4 ethertype", ipv4(OTHER, DST, TCP, tcp(), ver=6), XDP_DROP, "INVALID")
C("P13 ihl15 truncated (<60B IP hdr)", ipv4(OTHER, DST, TCP, b"", ihl=15)[:14 + 40], XDP_DROP, "INVALID")
C("P13b ipv4 <20B (eth+10B)", (ETH_IP + ipv4(OTHER, DST, TCP, tcp())[14:24]), XDP_DROP, "INVALID")
C("P14 tcp-opt .3 SYN", ipv4("10.77.0.3", DST, TCP, tcp(flags=0x02), ihl=6), XDP_DROP, "DROP")
C("P14b tcp .3 SYN|ACK", ipv4("10.77.0.3", DST, TCP, tcp(flags=0x12)), XDP_DROP, "DROP")
C("P15 tcp-opt .3 ACK", ipv4("10.77.0.3", DST, TCP, tcp(flags=0x10), ihl=6), XDP_PASS, "NO_MATCH")
C("P15b frag-nonfirst .3 (flag rule)", ipv4("10.77.0.3", DST, TCP, nonfirst_payload, off=185), XDP_PASS, "NO_MATCH")
C("P16 udp-frag-nonfirst .4 (payload 14e9)", ipv4("10.77.0.4", DST, UDP, b"\0\0\x14\xe9" + b"\0" * 36, off=185), XDP_PASS, "NO_MATCH", r4_unchanged=True)
C("P16b udp .4 dport5353 (count)", ipv4("10.77.0.4", DST, UDP, udp(dp=5353)), XDP_PASS, "COUNT")
C("P16c udp frag-first-full .4 dport5353 MF", ipv4("10.77.0.4", DST, UDP, udp(dp=5353, plen=8), mf=1), XDP_PASS, "COUNT")
# D3 ICMP
C("D3a icmp .5 (rule dport 0-1023)", ipv4("10.77.0.5", DST, ICMP, ICMP_ECHO), XDP_PASS, "NO_MATCH")
C("D3b tcp .5 dport80 (rule dport 0-1023)", ipv4("10.77.0.5", DST, TCP, tcp(dp=80)), XDP_DROP, "DROP")
C("D3c icmp .2 (IP-only rule)", ipv4("10.77.0.2", DST, ICMP, ICMP_ECHO), XDP_DROP, "DROP")
C("D3d icmp .1 (tcp port rule)", ipv4("10.77.0.1", DST, ICMP, ICMP_ECHO), XDP_PASS, "NO_MATCH")
# non-IPv4
C("N1 arp", b"\xff" * 6 + b"\x02\0\0\0\0\x01" + b"\x08\x06" + b"\0" * 28, XDP_PASS, "NON_IPV4")
C("N2 ipv6", b"\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x86\xdd" + b"\x60" + b"\0" * 39, XDP_PASS, "NON_IPV4")
C("N3 802.1Q tagged IPv4 (.2)", b"\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x81\x00\x00\x01" + ipv4("10.77.0.2", DST, TCP, tcp())[12:], XDP_PASS, "NON_IPV4")
C("N4 eth hdr only 14B ethertype IPv4", ETH_IP, XDP_DROP, "INVALID")
# regression: order src -> dst -> pass
C("R-a src .6 pass rule, dst drop rule -> src wins", ipv4("10.77.0.6", "10.88.0.1", TCP, tcp()), XDP_PASS, "PASS")
C("R-b no src rule, dst drop", ipv4(OTHER, "10.88.0.1", TCP, tcp()), XDP_DROP, "DROP")
C("R-c src .1 mismatch(port80) -> dst drop", ipv4("10.77.0.1", "10.88.0.1", TCP, tcp(dp=80)), XDP_DROP, "DROP")
C("R-d src .7 redirect no target -> PASS, not dst", ipv4("10.77.0.7", "10.88.0.1", TCP, tcp()), XDP_PASS, "ACTION_ERR")
C("R-e src .8 redirect lo", ipv4("10.77.0.8", DST, TCP, tcp()), XDP_REDIRECT, "REDIRECT")
C("R-f src .9 unknown action -> PASS", ipv4("10.77.0.9", "10.88.0.1", TCP, tcp()), XDP_PASS, "ACTION_ERR")
C("R-g no rule at all", ipv4(OTHER, DST, TCP, tcp()), XDP_PASS, "NO_MATCH")
C("R-h dst rule hit by tiny frag still INVALID", ipv4(OTHER, "10.88.0.1", TCP, tcp()[:8], mf=1), XDP_DROP, "INVALID")

# --- F1: Ethernet minimum-frame padding (NIC pads <60B frames; data_end includes padding).
#     L4 completeness must come from tot_len, never from padding bytes.
def pad(frame, n=60, fill=b"\0"):
    return frame + fill * max(0, n - len(frame))

C("F1a tiny-frag 42B padded to 60 no-rule", pad(ipv4(OTHER, DST, TCP, tcp(dp=8080)[:8], mf=1)), XDP_DROP, "INVALID")
C("F1b tiny-frag padded .2 (IP drop rule)", pad(ipv4("10.77.0.2", DST, TCP, tcp()[:8], mf=1)), XDP_DROP, "INVALID")
C("F1c tiny-frag padded .1 dport8080 (port rule)", pad(ipv4("10.77.0.1", DST, TCP, tcp(dp=8080)[:8], mf=1)), XDP_DROP, "INVALID")
C("F1d tiny-frag padded .3, padding=0x02 (SYN bait)", pad(ipv4("10.77.0.3", DST, TCP, tcp()[:8], mf=1), fill=b"\x02"), XDP_DROP, "INVALID")
C("F1e udp tiny-frag 4B padded no-rule", pad(ipv4(OTHER, DST, UDP, udp()[:4], mf=1)), XDP_DROP, "INVALID")
C("F1f short udp .4 dport5353 padded (normal match)", pad(ipv4("10.77.0.4", DST, UDP, udp(dp=5353))), XDP_PASS, "COUNT")
C("F1g short tcp .1 dport8080 20B padded (normal match)", pad(ipv4("10.77.0.1", DST, TCP, tcp(dp=8080))), XDP_DROP, "DROP")
C("F1h tcp-trunc 10B padded .1 (port rule, l4 unknown)", pad(ipv4("10.77.0.1", DST, TCP, tcp(dp=8080)[:10])), XDP_PASS, "NO_MATCH")
C("F1i tcp-trunc 10B padded=0x02 .3 (flag rule, l4 unknown)", pad(ipv4("10.77.0.3", DST, TCP, tcp(flags=0x02)[:10]), fill=b"\x02"), XDP_PASS, "NO_MATCH")
C("F1j tcp-trunc 10B padded .2 (IP-only rule)", pad(ipv4("10.77.0.2", DST, TCP, tcp()[:10])), XDP_DROP, "DROP")
C("F1k icmp short padded .2 (IP-only rule)", pad(ipv4("10.77.0.2", DST, ICMP, ICMP_ECHO[:8])), XDP_DROP, "DROP")
# --- F1: tot_len validation
C("T1 tot_len > frame (claims +20B) no-rule", ipv4(OTHER, DST, TCP, tcp(), tot=60), XDP_DROP, "INVALID")
C("T2 tot_len > frame .6 (pass rule cannot exempt)", ipv4("10.77.0.6", DST, TCP, tcp(), tot=1500), XDP_DROP, "INVALID")
C("T3 tot_len 19 < ihl*4 (ihl5)", ipv4(OTHER, DST, TCP, tcp(), tot=19), XDP_DROP, "INVALID")
C("T4 tot_len 22 < ihl*4 (ihl6)", ipv4(OTHER, DST, TCP, tcp(), ihl=6, tot=22), XDP_DROP, "INVALID")
C("T5 tot_len 0", ipv4(OTHER, DST, TCP, tcp(), tot=0), XDP_DROP, "INVALID")
C("T6 tot_len == ihl*4, MF=0, .2 (no L4, IP rule)", ipv4("10.77.0.2", DST, TCP, b"", tot=20), XDP_DROP, "DROP")
C("T7 tot_len == ihl*4, MF=0, .1 (port rule)", pad(ipv4("10.77.0.1", DST, TCP, b"", tot=20)), XDP_PASS, "NO_MATCH")
C("T8 tot_len == ihl*4, MF=1 (tiny frag)", pad(ipv4(OTHER, DST, TCP, b"", mf=1)), XDP_DROP, "INVALID")
C("T9 tot_len == frame exactly, ihl15 + tcp", ipv4("10.77.0.1", DST, TCP, tcp(dp=8080), ihl=15), XDP_DROP, "DROP")

# rule-matched slots that bump stats_map
RULE_SLOTS = {"DROP", "PASS", "REDIRECT", "COUNT"}

fails = 0
tmpd = tempfile.mkdtemp()
total_expected = {s: 0 for s in SLOTS}
start = xdp_counters()
for i, (a, k) in enumerate(cases):
    name, frame, exp_ret, exp_slot = a
    f = os.path.join(tmpd, f"c{i}.bin"); open(f, "wb").write(frame)
    before = xdp_counters(); g0 = global_stats(); r4_0 = rule_pkts("filter_rules", "10.77.0.4")
    r = sh("bpftool", "prog", "run", "pinned", PROG, "data_in", f, "repeat", "1", check=False)
    ret = None
    for line in r.stdout.splitlines():
        if line.startswith("Return value:"): ret = int(line.split(":")[1].split(",")[0])
    after = xdp_counters(); g1 = global_stats(); r4_1 = rule_pkts("filter_rules", "10.77.0.4")
    delta = {s: (after.get(s, (0, 0))[0] - before.get(s, (0, 0))[0], after.get(s, (0, 0))[1] - before.get(s, (0, 0))[1]) for s in SLOTS}
    want = {s: (0, 0) for s in SLOTS}; want["RX"] = (1, len(frame)); want[exp_slot] = (1, len(frame))
    ok = ret == exp_ret and delta == want
    gd = g1 - g0
    if gd != (1 if exp_slot in RULE_SLOTS else 0): ok = False
    if k.get("r4_unchanged") and r4_1 != r4_0: ok = False
    total_expected["RX"] += 1; total_expected[exp_slot] += 1
    tag = "PASS" if ok else "FAIL"
    if not ok: fails += 1
    nz = {s: v for s, v in delta.items() if v != (0, 0)}
    print(f"[{tag}] {name:52s} len={len(frame):3d} ret={ret} (want {exp_ret}) slot={exp_slot} delta={nz} stats_map+={gd}"
          + (f" R4 {r4_0}->{r4_1}" if k.get("r4_unchanged") else "") + ("" if ret is not None else f"\n   stderr={r.stderr.strip()}"))

end = xdp_counters()
rx = end["RX"][0] - start["RX"][0]
res = sum(end[s][0] - start[s][0] for s in SLOTS[1:])
print(f"invariant: RX={rx} sum(results)={res} -> {'OK' if rx == res == len(cases) else 'MISMATCH'}")
if not (rx == res == len(cases)): fails += 1
print("totals:", {s: end[s][0] - start[s][0] for s in SLOTS})
print(f"RESULT: {len(cases) - fails}/{len(cases)} cases OK" if fails == 0 else f"RESULT: {fails} FAIL")
sys.exit(1 if fails else 0)
