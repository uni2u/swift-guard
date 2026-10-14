// Swift-Guard BPF 맵 바이트 레이아웃
// include/swift_guard.h 의 C 구조체를 명시적 offset으로 직렬화/역직렬화한다.
// C 레이아웃이 원천이다: filter_rule=88, prefix_key=8, if_redirect=20, filter_stats=24.
// 순수 Rust(의존성 추가 없음)라 macOS에서도 `cargo test -p swift-guard-common`으로 검증된다.

use anyhow::{anyhow, Result};

/// sizeof(struct filter_rule) (align 8)
pub const FILTER_RULE_SIZE: usize = 88;
/// sizeof(struct prefix_key)
pub const PREFIX_KEY_SIZE: usize = 8;
/// sizeof(struct if_redirect)
pub const IF_REDIRECT_SIZE: usize = 20;
/// sizeof(struct filter_stats)
pub const FILTER_STATS_SIZE: usize = 24;

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
}
