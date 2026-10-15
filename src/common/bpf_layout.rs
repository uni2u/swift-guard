// Swift-Guard BPF 맵 바이트 레이아웃
// include/swift_guard.h 의 C 구조체를 명시적 offset으로 직렬화/역직렬화한다.
// C 레이아웃이 원천이다: filter_rule=88, prefix_key=8, if_redirect=20, filter_stats=24, sg_counter=16.
// 순수 Rust(의존성 추가 없음)라 macOS에서도 `cargo test -p swift-guard-common`으로 검증된다.

use anyhow::{anyhow, Result};

use crate::api::XdpCounters;

/// sizeof(struct filter_rule) (align 8)
pub const FILTER_RULE_SIZE: usize = 88;
/// sizeof(struct prefix_key)
pub const PREFIX_KEY_SIZE: usize = 8;
/// sizeof(struct if_redirect)
pub const IF_REDIRECT_SIZE: usize = 20;
/// sizeof(struct filter_stats)
pub const FILTER_STATS_SIZE: usize = 24;

/// sizeof(struct sg_counter) — xdp_stats_map 값 (packets@0, bytes@8, align 8, 패딩 없음)
pub const SG_COUNTER_SIZE: usize = 16;

/// xdp_stats_map 슬롯 인덱스 (swift_guard.h SG_STAT_*)
pub mod xdp_stat {
    pub const RX: u32 = 0;
    pub const DROP: u32 = 1;
    pub const PASS: u32 = 2;
    pub const REDIRECT: u32 = 3;
    pub const COUNT: u32 = 4;
    pub const NO_MATCH: u32 = 5;
    pub const INVALID: u32 = 6;
    pub const NON_IPV4: u32 = 7;
    pub const ACTION_ERR: u32 = 8;
    /// max_entries
    pub const MAX: u32 = 9;
}

/// label 필드 크기 (char[32], NUL 포함)
pub const LABEL_SIZE: usize = 32;
/// ifname 필드 크기 (char[16], NUL 포함)
pub const IFNAME_SIZE: usize = 16;

/// struct filter_rule 필드 offset
pub mod off {
    pub const PRIORITY: usize = 0;
    pub const ACTION: usize = 4;
    pub const PROTOCOL: usize = 5;
    pub const SRC_PORT_MIN: usize = 6;
    pub const SRC_PORT_MAX: usize = 8;
    pub const DST_PORT_MIN: usize = 10;
    pub const DST_PORT_MAX: usize = 12;
    pub const TCP_FLAGS: usize = 14;
    // 15: 1바이트 패딩
    pub const REDIRECT_IFINDEX: usize = 16;
    pub const RATE_LIMIT: usize = 20;
    pub const EXPIRE: usize = 24;
    pub const LABEL: usize = 28;
    // 60..64: 4바이트 패딩
    pub const STATS: usize = 64;
}

/// struct filter_rule 에서 stats 를 제외한 값 (stats 는 쓰기 시 항상 0)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterRuleValue {
    pub priority: u32,
    pub action: u8,
    pub protocol: u8,
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub tcp_flags: u8,
    pub redirect_ifindex: u32,
    pub rate_limit: u32,
    pub expire: u32,
    pub label: [u8; LABEL_SIZE],
}

/// label 을 char[32] 로 인코딩한다. 31바이트 초과는 Err (조용한 절단 금지).
pub fn encode_label(s: &str) -> Result<[u8; LABEL_SIZE]> {
    let bytes = s.as_bytes();
    if bytes.len() > LABEL_SIZE - 1 {
        return Err(anyhow!(
            "label '{}' is {} bytes; maximum is {} bytes",
            s,
            bytes.len(),
            LABEL_SIZE - 1
        ));
    }
    if bytes.contains(&0) {
        return Err(anyhow!("label must not contain NUL bytes"));
    }
    let mut out = [0u8; LABEL_SIZE];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

/// struct filter_rule (88B) 인코딩. 패딩과 stats 는 0.
pub fn encode_filter_rule(v: &FilterRuleValue) -> [u8; FILTER_RULE_SIZE] {
    let mut b = [0u8; FILTER_RULE_SIZE];
    b[off::PRIORITY..off::PRIORITY + 4].copy_from_slice(&v.priority.to_ne_bytes());
    b[off::ACTION] = v.action;
    b[off::PROTOCOL] = v.protocol;
    b[off::SRC_PORT_MIN..off::SRC_PORT_MIN + 2].copy_from_slice(&v.src_port_min.to_ne_bytes());
    b[off::SRC_PORT_MAX..off::SRC_PORT_MAX + 2].copy_from_slice(&v.src_port_max.to_ne_bytes());
    b[off::DST_PORT_MIN..off::DST_PORT_MIN + 2].copy_from_slice(&v.dst_port_min.to_ne_bytes());
    b[off::DST_PORT_MAX..off::DST_PORT_MAX + 2].copy_from_slice(&v.dst_port_max.to_ne_bytes());
    b[off::TCP_FLAGS] = v.tcp_flags;
    b[off::REDIRECT_IFINDEX..off::REDIRECT_IFINDEX + 4]
        .copy_from_slice(&v.redirect_ifindex.to_ne_bytes());
    b[off::RATE_LIMIT..off::RATE_LIMIT + 4].copy_from_slice(&v.rate_limit.to_ne_bytes());
    b[off::EXPIRE..off::EXPIRE + 4].copy_from_slice(&v.expire.to_ne_bytes());
    b[off::LABEL..off::LABEL + LABEL_SIZE].copy_from_slice(&v.label);
    b
}

/// prefix_len 비트 마스크(호스트 정수). 0 → 0, 32 이상 → u32::MAX.
pub fn prefix_mask(prefix_len: u32) -> u32 {
    match prefix_len {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    }
}

/// prefix 밖의 비트를 지운 정규 주소(호스트 정수)
pub fn canonical_prefix(addr_host: u32, prefix_len: u32) -> u32 {
    addr_host & prefix_mask(prefix_len)
}

/// struct prefix_key (8B). prefix_len 은 호스트 오더, addr 는 네트워크 오더.
/// addr_host 는 `utils::parse_ip_prefix` 가 돌려주는 호스트 정수값(MSB=첫 옥텟)이다.
/// filter_rules(src, addr=출발지) 와 dst_rules(dst, addr=목적지) 키 모두에 이 함수를 쓴다.
pub fn encode_prefix_key(addr_host: u32, prefix_len: u32) -> [u8; PREFIX_KEY_SIZE] {
    let mut b = [0u8; PREFIX_KEY_SIZE];
    b[0..4].copy_from_slice(&prefix_len.to_ne_bytes());
    b[4..8].copy_from_slice(&canonical_prefix(addr_host, prefix_len).to_be_bytes());
    b
}

/// struct if_redirect (20B). ifname 은 최대 15바이트 + NUL (IFNAMSIZ 16).
/// 커널 인터페이스 이름은 15바이트를 넘지 않으므로 초과분은 잘라낸다.
pub fn encode_if_redirect(ifindex: u32, ifname: &str) -> [u8; IF_REDIRECT_SIZE] {
    let mut b = [0u8; IF_REDIRECT_SIZE];
    b[0..4].copy_from_slice(&ifindex.to_ne_bytes());
    let name = ifname.as_bytes();
    let n = name.len().min(IFNAME_SIZE - 1);
    b[4..4 + n].copy_from_slice(&name[..n]);
    b
}

fn read_u64(buf: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&buf[at..at + 8]);
    u64::from_ne_bytes(a)
}

/// struct filter_stats (24B) 디코딩 → (packets, bytes, last_matched)
pub fn decode_filter_stats(buf: &[u8]) -> Option<(u64, u64, u64)> {
    if buf.len() < FILTER_STATS_SIZE {
        return None;
    }
    Some((read_u64(buf, 0), read_u64(buf, 8), read_u64(buf, 16)))
}

/// filter_rule 값(정확히 88B)에서 절대 offset 64 의 stats 를 읽는다.
pub fn decode_rule_stats(value: &[u8]) -> Option<(u64, u64, u64)> {
    if value.len() != FILTER_RULE_SIZE {
        return None;
    }
    decode_filter_stats(&value[off::STATS..])
}

/// PERCPU 맵 조회 결과(CPU당 filter_stats)를 합산 → (packets, bytes)
pub fn sum_percpu_stats(per_cpu: &[Vec<u8>]) -> (u64, u64) {
    per_cpu
        .iter()
        .filter_map(|v| decode_filter_stats(v))
        .fold((0u64, 0u64), |(p, b), (cp, cb, _)| {
            (p.wrapping_add(cp), b.wrapping_add(cb))
        })
}

/// struct sg_counter (16B) 디코딩 → (packets, bytes). 16B 미만이면 None.
pub fn decode_counter(buf: &[u8]) -> Option<(u64, u64)> {
    if buf.len() < SG_COUNTER_SIZE {
        return None;
    }
    Some((read_u64(buf, 0), read_u64(buf, 8)))
}

/// PERCPU 조회 결과(CPU당 sg_counter)를 합산 → (packets, bytes). 짧은 값은 건너뛴다.
pub fn sum_percpu_counters(per_cpu: &[Vec<u8>]) -> (u64, u64) {
    per_cpu
        .iter()
        .filter_map(|v| decode_counter(v))
        .fold((0u64, 0u64), |(p, b), (cp, cb)| {
            (p.wrapping_add(cp), b.wrapping_add(cb))
        })
}

/// 슬롯별 (packets, bytes) 합산값(인덱스 = xdp_stat::*) → API 카운터.
/// slots.len() < MAX 이면 없는 슬롯은 0 이다.
pub fn xdp_counters_from_slots(slots: &[(u64, u64)]) -> XdpCounters {
    let pk = |i: u32| slots.get(i as usize).map(|s| s.0).unwrap_or(0);
    XdpCounters {
        rx_packets: pk(xdp_stat::RX),
        rx_bytes: slots.get(xdp_stat::RX as usize).map(|s| s.1).unwrap_or(0),
        drop_packets: pk(xdp_stat::DROP),
        pass_packets: pk(xdp_stat::PASS),
        redirect_packets: pk(xdp_stat::REDIRECT),
        count_packets: pk(xdp_stat::COUNT),
        no_match_packets: pk(xdp_stat::NO_MATCH),
        invalid_packets: pk(xdp_stat::INVALID),
        non_ipv4_packets: pk(xdp_stat::NON_IPV4),
        action_error_packets: pk(xdp_stat::ACTION_ERR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FilterRuleValue {
        FilterRuleValue {
            priority: 0x0102_0304,
            action: 0x05,
            protocol: 0x06,
            src_port_min: 0x0708,
            src_port_max: 0x090A,
            dst_port_min: 0x0B0C,
            dst_port_max: 0x0D0E,
            tcp_flags: 0x0F,
            redirect_ifindex: 0x1112_1314,
            rate_limit: 0x1516_1718,
            expire: 0x191A_1B1C,
            label: encode_label("abc").unwrap(),
        }
    }

    #[test]
    fn filter_rule_size_and_padding() {
        let b = encode_filter_rule(&sample());
        assert_eq!(b.len(), FILTER_RULE_SIZE);
        assert_eq!(b[15], 0, "tcp_flags 뒤 패딩");
        assert_eq!(&b[60..64], &[0, 0, 0, 0], "label 뒤 패딩");
        assert_eq!(&b[off::STATS..], &[0u8; 24], "stats 는 0");
    }

    #[test]
    fn filter_rule_single_byte_fields() {
        let b = encode_filter_rule(&sample());
        assert_eq!(b[off::ACTION], 0x05);
        assert_eq!(b[off::PROTOCOL], 0x06);
        assert_eq!(b[off::TCP_FLAGS], 0x0F);
        assert_eq!(&b[off::LABEL..off::LABEL + 4], b"abc\0");
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn filter_rule_multi_byte_offsets_le() {
        let b = encode_filter_rule(&sample());
        assert_eq!(&b[0..4], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&b[6..8], &[0x08, 0x07]);
        assert_eq!(&b[8..10], &[0x0A, 0x09]);
        assert_eq!(&b[10..12], &[0x0C, 0x0B]);
        assert_eq!(&b[12..14], &[0x0E, 0x0D]);
        assert_eq!(&b[16..20], &[0x14, 0x13, 0x12, 0x11]);
        assert_eq!(&b[20..24], &[0x18, 0x17, 0x16, 0x15]);
        assert_eq!(&b[24..28], &[0x1C, 0x1B, 0x1A, 0x19]);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn prefix_key_bytes() {
        assert_eq!(
            encode_prefix_key(0xC0A8_0164, 32),
            [0x20, 0, 0, 0, 0xC0, 0xA8, 0x01, 0x64]
        );
        assert_eq!(
            encode_prefix_key(0x0A00_0001, 8),
            [0x08, 0, 0, 0, 0x0A, 0, 0, 0]
        );
    }

    /// dst_rules 키: parse_ip_prefix → encode_prefix_key 실제 경로로 목적지 주소를 인코딩
    #[cfg(target_endian = "little")]
    #[test]
    fn dst_prefix_key_network_order() {
        use crate::utils::parse_ip_prefix;
        use std::net::Ipv4Addr;

        let (a, p) = parse_ip_prefix("10.200.0.11").unwrap();
        let k = encode_prefix_key(a, p);
        assert_eq!(k, [0x20, 0, 0, 0, 0x0A, 0xC8, 0x00, 0x0B]);
        assert_eq!(&k[4..8], &Ipv4Addr::new(10, 200, 0, 11).octets());

        let (a, p) = parse_ip_prefix("10.200.0.77/24").unwrap();
        let k = encode_prefix_key(a, p);
        assert_eq!(k, [0x18, 0, 0, 0, 0x0A, 0xC8, 0x00, 0x00]);
        assert_eq!(&k[4..8], &Ipv4Addr::new(10, 200, 0, 0).octets());
    }

    #[test]
    fn prefix_canonicalization() {
        assert_eq!(canonical_prefix(0x0A00_0001, 8), 0x0A00_0000);
        assert_eq!(prefix_mask(0), 0);
        assert_eq!(prefix_mask(32), u32::MAX);
        assert_eq!(prefix_mask(24), 0xFFFF_FF00);
        assert_eq!(canonical_prefix(0xFFFF_FFFF, 0), 0);
    }

    #[test]
    fn label_limits() {
        assert!(encode_label(&"a".repeat(32)).is_err());
        let l = encode_label(&"a".repeat(31)).unwrap();
        assert_eq!(l[31], 0);
        assert_eq!(l[30], b'a');
        assert_eq!(encode_label("").unwrap(), [0u8; 32]);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn if_redirect_bytes() {
        let b = encode_if_redirect(7, "eth1");
        assert_eq!(b.len(), IF_REDIRECT_SIZE);
        assert_eq!(&b[0..4], &[7, 0, 0, 0]);
        assert_eq!(&b[4..9], b"eth1\0");
        assert_eq!(&b[9..], &[0u8; 11]);
        let long = encode_if_redirect(1, "abcdefghijklmnopqrst");
        assert_eq!(long[4 + 15], 0, "ifname 은 NUL 종료");
    }

    #[test]
    fn rule_stats_absolute_offset() {
        let mut v = [0u8; FILTER_RULE_SIZE];
        v[64..72].copy_from_slice(&3u64.to_ne_bytes());
        v[72..80].copy_from_slice(&300u64.to_ne_bytes());
        v[80..88].copy_from_slice(&99u64.to_ne_bytes());
        assert_eq!(decode_rule_stats(&v), Some((3, 300, 99)));
        assert_eq!(decode_rule_stats(&v[..87]), None);
        assert_eq!(decode_rule_stats(&[0u8; 89]), None);
    }

    #[test]
    fn percpu_sum() {
        let mk = |p: u64, b: u64| {
            let mut v = vec![0u8; FILTER_STATS_SIZE];
            v[0..8].copy_from_slice(&p.to_ne_bytes());
            v[8..16].copy_from_slice(&b.to_ne_bytes());
            v[16..24].copy_from_slice(&1u64.to_ne_bytes());
            v
        };
        assert_eq!(sum_percpu_stats(&[mk(10, 1000), mk(5, 500)]), (15, 1500));
        assert_eq!(sum_percpu_stats(&[]), (0, 0));
        assert_eq!(sum_percpu_stats(&[mk(u64::MAX, 0), mk(2, 0)]), (1, 0));
    }

    fn counter(p: u64, b: u64) -> Vec<u8> {
        let mut v = vec![0u8; SG_COUNTER_SIZE];
        v[0..8].copy_from_slice(&p.to_ne_bytes());
        v[8..16].copy_from_slice(&b.to_ne_bytes());
        v
    }

    #[test]
    fn sg_counter_decode() {
        assert_eq!(SG_COUNTER_SIZE, 16);
        assert_eq!(decode_counter(&counter(7, 686)), Some((7, 686)));
        assert_eq!(decode_counter(&counter(7, 686)[..15]), None);
        assert_eq!(decode_counter(&[]), None);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn sg_counter_offsets_le() {
        let mut v = [0u8; 16];
        v[0] = 0x01; // packets@0
        v[8] = 0x02; // bytes@8
        assert_eq!(decode_counter(&v), Some((1, 2)));
    }

    #[test]
    fn percpu_counter_sum_wrapping() {
        assert_eq!(sum_percpu_counters(&[counter(10, 1000), counter(5, 500)]), (15, 1500));
        assert_eq!(sum_percpu_counters(&[]), (0, 0));
        assert_eq!(sum_percpu_counters(&[counter(u64::MAX, 1), counter(2, 0)]), (1, 1));
        // 짧은 값은 무시
        assert_eq!(sum_percpu_counters(&[counter(3, 30), vec![1u8; 8]]), (3, 30));
    }

    #[test]
    fn xdp_stat_indices_match_header() {
        use xdp_stat::*;
        assert_eq!(
            [RX, DROP, PASS, REDIRECT, COUNT, NO_MATCH, INVALID, NON_IPV4, ACTION_ERR, MAX],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
    }

    #[test]
    fn slots_to_xdp_counters() {
        let slots: Vec<(u64, u64)> = (0..xdp_stat::MAX as u64).map(|i| (100 + i, 1000 + i)).collect();
        let c = xdp_counters_from_slots(&slots);
        assert_eq!(c.rx_packets, 100);
        assert_eq!(c.rx_bytes, 1000);
        assert_eq!(c.drop_packets, 101);
        assert_eq!(c.pass_packets, 102);
        assert_eq!(c.redirect_packets, 103);
        assert_eq!(c.count_packets, 104);
        assert_eq!(c.no_match_packets, 105);
        assert_eq!(c.invalid_packets, 106);
        assert_eq!(c.non_ipv4_packets, 107);
        assert_eq!(c.action_error_packets, 108);
        // 슬롯 부족 → 없는 슬롯 0
        let c = xdp_counters_from_slots(&[(9, 90), (4, 40)]);
        assert_eq!((c.rx_packets, c.rx_bytes, c.drop_packets, c.pass_packets), (9, 90, 4, 0));
        assert_eq!(xdp_counters_from_slots(&[]), XdpCounters::default());
    }
}
