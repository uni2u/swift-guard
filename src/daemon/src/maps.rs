//! 맵 관리자 모듈
//! BPF 맵(filter_rules / dst_rules / redirect_map / stats_map / xdp_stats_map)을 관리한다.
//! - filter_rules: 출발지 IP prefix LPM 룰 (먼저 평가)
//! - dst_rules: 목적지 IP prefix LPM 룰 (출발지 룰이 없거나 조건 불일치일 때 평가)
//! - 두 룰 맵은 같은 키(prefix_key)·값(filter_rule 88B) 형식이며 redirect_map 을 공유한다.
//! - stats_map: 룰에 매치한 패킷만 센다 (PERCPU_ARRAY 1칸, filter_stats 24B).
//! - xdp_stats_map: XDP 가 본 전체 패킷(SG_STAT_RX)과 결과별 슬롯(PERCPU_ARRAY 9칸, sg_counter 16B).
//!
//! 바이트 직렬화는 전부 `swift_guard::bpf_layout` 을 사용한다(C 레이아웃이 원천).
//! MapManager 는 XdpFilterSkel 을 소유하며 !Send 이므로 main 태스크에서만 사용한다.

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{Map, MapFlags};
use log::{debug, warn};

use crate::bpf::XdpFilterSkel;

use swift_guard::api::{RuleInfo, RuleStats, XdpCounters};
use swift_guard::bpf_layout::{self, FilterRuleValue};
use swift_guard::types::MatchSide;
use swift_guard::utils;

const FILTER_RULES_MAP: &str = "filter_rules";
const DST_RULES_MAP: &str = "dst_rules";
const REDIRECT_MAP: &str = "redirect_map";
const STATS_MAP: &str = "stats_map";
const XDP_STATS_MAP: &str = "xdp_stats_map";
const XDP_PROG: &str = "xdp_filter_func";

/// redirect 액션 값 (ACTION_REDIRECT)
pub const ACTION_REDIRECT: u8 = 3;

/// 필터 규칙 정보 (데몬 캐시)
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// 출발지 (호스트 정수 IP, 프리픽스 길이) — filter_rules 룰.
    /// 불변식: src_ip / dst_ip 중 정확히 하나만 Some.
    pub src_ip: Option<(u32, u32)>,
    /// 목적지 (호스트 정수 IP, 프리픽스 길이) — dst_rules 룰.
    pub dst_ip: Option<(u32, u32)>,
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub action: u8,
    pub redirect_ifindex: u32,
    /// if_nametoindex 로 해석한 실제 인터페이스 이름
    pub redirect_ifname: Option<String>,
    pub priority: u32,
    pub rate_limit: u32,
    pub expire: u32,
    pub label: String,
    #[allow(dead_code)] // 향후 expire 처리용
    pub creation_time: u64,
}

fn format_prefix(ip: u32, prefix: u32) -> String {
    if prefix == 32 {
        utils::ipv4_to_string(ip)
    } else {
        format!("{}/{}", utils::ipv4_to_string(ip), prefix)
    }
}

fn map_for(side: MatchSide) -> &'static str {
    match side {
        MatchSide::Src => FILTER_RULES_MAP,
        MatchSide::Dst => DST_RULES_MAP,
    }
}

impl FilterRule {
    /// 룰이 들어갈 맵과 매칭 쪽, (주소, prefix 길이). 불변식 위반 시 API 와 같은 문구로 Err.
    fn target(&self) -> Result<(&'static str, MatchSide, u32, u32)> {
        match (self.src_ip, self.dst_ip) {
            (Some(_), Some(_)) => Err(anyhow!("specify either src_ip or dst_ip, not both")),
            (None, None) => Err(anyhow!("src_ip or dst_ip is required")),
            (Some((a, p)), None) => Ok((map_for(MatchSide::Src), MatchSide::Src, a, p)),
            (None, Some((a, p))) => Ok((map_for(MatchSide::Dst), MatchSide::Dst, a, p)),
        }
    }

    /// 해당 side 의 prefix 값
    fn prefix_of(&self, side: MatchSide) -> Option<(u32, u32)> {
        match side {
            MatchSide::Src => self.src_ip,
            MatchSide::Dst => self.dst_ip,
        }
    }

    /// API 룰 정보로 변환
    pub fn to_rule_info(&self, stats: RuleStats) -> RuleInfo {
        RuleInfo {
            label: self.label.clone(),
            action: utils::action_num_to_name(self.action),
            src_ip: self.src_ip.map(|(ip, prefix)| format_prefix(ip, prefix)),
            dst_ip: self.dst_ip.map(|(ip, prefix)| format_prefix(ip, prefix)),
            src_port: utils::port_range_to_string(self.src_port_min, self.src_port_max),
            dst_port: utils::port_range_to_string(self.dst_port_min, self.dst_port_max),
            protocol: utils::protocol_num_to_name(self.protocol),
            tcp_flags: if self.tcp_flags == 0 {
                None
            } else {
                Some(utils::tcp_flags_to_string(self.tcp_flags))
            },
            priority: self.priority,
            redirect_if: if self.action == ACTION_REDIRECT {
                self.redirect_ifname.clone()
            } else {
                None
            },
            rate_limit: self.rate_limit,
            expire: self.expire,
            stats,
        }
    }
}

fn zero_stats() -> RuleStats {
    RuleStats {
        packets: 0,
        bytes: 0,
        last_matched: 0,
    }
}

fn is_enoent(e: &libbpf_rs::Error) -> bool {
    matches!(e, libbpf_rs::Error::System(errno) if *errno == libc::ENOENT)
}

/// 맵 관리자
pub struct MapManager {
    skel: XdpFilterSkel,
    rules: Vec<FilterRule>,
}

impl std::fmt::Debug for MapManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapManager")
            .field("rules", &self.rules)
            .finish()
    }
}

impl MapManager {
    /// 5개 맵과 XDP 프로그램이 오브젝트에 있는지 검증한다.
    /// 오래된 xdp_filter.o 라면 `BPF object has no map 'xdp_stats_map'` 등으로 기동이 실패한다.
    pub fn new(skel: XdpFilterSkel) -> Result<Self> {
        for name in [FILTER_RULES_MAP, DST_RULES_MAP, REDIRECT_MAP, STATS_MAP, XDP_STATS_MAP] {
            if skel.obj.map(name).is_none() {
                return Err(anyhow!("BPF object has no map '{}'", name));
            }
        }
        if let Some(m) = skel.obj.map(XDP_STATS_MAP) {
            let n = m.value_size() as usize;
            if n != bpf_layout::SG_COUNTER_SIZE {
                return Err(anyhow!(
                    "BPF map '{}' value size {} != {} (rebuild xdp_filter.o)",
                    XDP_STATS_MAP,
                    n,
                    bpf_layout::SG_COUNTER_SIZE
                ));
            }
        }
        if skel.obj.prog(XDP_PROG).is_none() {
            return Err(anyhow!("BPF object has no program '{}'", XDP_PROG));
        }
        Ok(Self {
            skel,
            rules: Vec::new(),
        })
    }

    fn map(&self, name: &str) -> Result<&Map> {
        self.skel
            .obj
            .map(name)
            .ok_or_else(|| anyhow!("BPF map '{}' not found", name))
    }

    fn map_mut(&mut self, name: &str) -> Result<&mut Map> {
        self.skel
            .obj
            .map_mut(name)
            .ok_or_else(|| anyhow!("BPF map '{}' not found", name))
    }

    /// XDP 프로그램 fd (attach 용)
    pub fn xdp_prog_fd(&self) -> Result<i32> {
        self.skel
            .obj
            .prog(XDP_PROG)
            .map(|p| p.fd())
            .ok_or_else(|| anyhow!("BPF program '{}' not found", XDP_PROG))
    }

    /// 규칙 추가.
    /// 순서: 캐시 중복 검사 → (필요 시) redirect_map → filter_rules|dst_rules(NOEXIST) → 성공 시 캐시 push.
    pub fn add_rule(&mut self, mut rule: FilterRule) -> Result<()> {
        debug!("Adding rule: {}", rule.label);

        // 방어 검사: src_ip / dst_ip 중 정확히 하나
        let (map_name, side, addr, prefix_len) = rule.target()?;
        if prefix_len > 32 {
            return Err(anyhow!("invalid prefix length {}", prefix_len));
        }
        let addr = bpf_layout::canonical_prefix(addr, prefix_len);
        match side {
            MatchSide::Src => rule.src_ip = Some((addr, prefix_len)),
            MatchSide::Dst => rule.dst_ip = Some((addr, prefix_len)),
        }

        let label = bpf_layout::encode_label(&rule.label)?;

        // (1) 캐시 중복 검사 — prefix 는 같은 side(맵) 안에서만, label 은 전체
        if let Some(existing) = self
            .rules
            .iter()
            .find(|r| r.prefix_of(side) == Some((addr, prefix_len)))
        {
            let side_word = match side {
                MatchSide::Src => "",
                MatchSide::Dst => "dst ",
            };
            return Err(anyhow!(
                "a rule for {}{}/{} already exists (label '{}')",
                side_word,
                utils::ipv4_to_string(addr),
                prefix_len,
                existing.label
            ));
        }
        if self.rules.iter().any(|r| r.label == rule.label) {
            return Err(anyhow!("a rule with label '{}' already exists", rule.label));
        }
        if rule.action == ACTION_REDIRECT && rule.redirect_ifindex == 0 {
            return Err(anyhow!("redirect action requires a valid redirect interface"));
        }

        let key = bpf_layout::encode_prefix_key(addr, prefix_len);
        let value = bpf_layout::encode_filter_rule(&FilterRuleValue {
            priority: rule.priority,
            action: rule.action,
            protocol: rule.protocol,
            src_port_min: rule.src_port_min,
            src_port_max: rule.src_port_max,
            dst_port_min: rule.dst_port_min,
            dst_port_max: rule.dst_port_max,
            tcp_flags: rule.tcp_flags,
            redirect_ifindex: rule.redirect_ifindex,
            rate_limit: rule.rate_limit,
            expire: rule.expire,
            label,
        });

        // (2) redirect_map — 다른 룰이 이미 같은 ifindex 를 넣었으면 건드리지 않는다
        let mut inserted_redirect: Option<[u8; 4]> = None;
        if rule.action == ACTION_REDIRECT {
            let ifindex = rule.redirect_ifindex;
            let already = self
                .rules
                .iter()
                .any(|r| r.action == ACTION_REDIRECT && r.redirect_ifindex == ifindex);
            if !already {
                let rkey = ifindex.to_ne_bytes();
                let ifname = rule.redirect_ifname.clone().unwrap_or_default();
                let rval = bpf_layout::encode_if_redirect(ifindex, &ifname);
                self.map_mut(REDIRECT_MAP)?
                    .update(&rkey, &rval, MapFlags::ANY)
                    .context("Failed to update redirect_map")?;
                inserted_redirect = Some(rkey);
            }
        }

        // (3) filter_rules 또는 dst_rules
        let res = self
            .map_mut(map_name)?
            .update(&key, &value, MapFlags::NO_EXIST);
        if let Err(e) = res {
            if let Some(rkey) = inserted_redirect {
                if let Err(re) = self.map_mut(REDIRECT_MAP).and_then(|m| {
                    m.delete(&rkey).context("redirect_map rollback delete failed")
                }) {
                    warn!("redirect_map rollback failed: {:#}", re);
                }
            }
            return Err(anyhow::Error::new(e).context(format!(
                "Failed to update {} map for {}/{}",
                map_name,
                utils::ipv4_to_string(addr),
                prefix_len
            )));
        }

        // (4) 캐시
        self.rules.push(rule);
        Ok(())
    }

    /// 규칙 삭제. 라벨이 없으면 Ok(false).
    /// 맵 delete 실패(ENOENT 제외) 시 Err 이고 캐시는 유지한다.
    pub fn delete_rule(&mut self, label: &str) -> Result<bool> {
        debug!("Deleting rule: {}", label);

        let Some(index) = self.rules.iter().position(|r| r.label == label) else {
            return Ok(false);
        };
        let rule = self.rules[index].clone();

        let (map_name, _, addr, prefix_len) = rule.target()?;
        let key = bpf_layout::encode_prefix_key(addr, prefix_len);
        match self.map_mut(map_name)?.delete(&key) {
            Ok(()) => {}
            Err(e) if is_enoent(&e) => {
                warn!(
                    "rule '{}' was not present in {} map; removing from cache",
                    label, map_name
                );
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("Failed to delete rule '{}' from {} map", label, map_name)));
            }
        }

        self.rules.remove(index);

        // 해당 ifindex 를 참조하는 다른 룰이 없으면 redirect_map 항목도 삭제
        if rule.action == ACTION_REDIRECT && rule.redirect_ifindex != 0 {
            let ifindex = rule.redirect_ifindex;
            let still_used = self
                .rules
                .iter()
                .any(|r| r.action == ACTION_REDIRECT && r.redirect_ifindex == ifindex);
            if !still_used {
                let rkey = ifindex.to_ne_bytes();
                match self.map_mut(REDIRECT_MAP)?.delete(&rkey) {
                    Ok(()) => {}
                    Err(e) if is_enoent(&e) => {}
                    Err(e) => warn!("Failed to delete redirect_map entry for ifindex {}: {}", ifindex, e),
                }
            }
        }

        Ok(true)
    }

    /// 규칙 목록 조회. include_stats 면 룰이 속한 맵(filter_rules|dst_rules) 값의
    /// 절대 offset 64 에서 통계를 읽는다.
    pub fn list_rules(&self, include_stats: bool) -> Result<Vec<RuleInfo>> {
        let mut result = Vec::with_capacity(self.rules.len());
        let maps = if include_stats {
            Some((self.map(FILTER_RULES_MAP)?, self.map(DST_RULES_MAP)?))
        } else {
            None
        };

        for rule in &self.rules {
            let stats = match (maps, rule.target()) {
                (Some((src_map, dst_map)), Ok((map_name, side, addr, prefix_len))) => {
                    let map = match side {
                        MatchSide::Src => src_map,
                        MatchSide::Dst => dst_map,
                    };
                    let key = bpf_layout::encode_prefix_key(addr, prefix_len);
                    let value = map
                        .lookup(&key, MapFlags::ANY)
                        .with_context(|| format!("Failed to look up rule '{}'", rule.label))?;
                    match value {
                        Some(v) => {
                            let (packets, bytes, last_matched) = bpf_layout::decode_rule_stats(&v)
                                .ok_or_else(|| {
                                    anyhow!(
                                        "{} value size {} != {}",
                                        map_name,
                                        v.len(),
                                        bpf_layout::FILTER_RULE_SIZE
                                    )
                                })?;
                            RuleStats {
                                packets,
                                bytes,
                                last_matched,
                            }
                        }
                        None => {
                            warn!(
                                "rule '{}' is cached but missing from {} map",
                                rule.label, map_name
                            );
                            zero_stats()
                        }
                    }
                }
                _ => zero_stats(),
            };

            result.push(rule.to_rule_info(stats));
        }

        Ok(result)
    }

    /// 전체 통계 (stats_map PERCPU_ARRAY key 0 의 CPU별 합산) → (packets, bytes)
    pub fn get_stats(&self) -> Result<(u64, u64)> {
        let key = 0u32.to_ne_bytes();
        let per_cpu = self
            .map(STATS_MAP)?
            .lookup_percpu(&key, MapFlags::ANY)
            .context("Failed to read stats_map")?;
        Ok(per_cpu
            .map(|v| bpf_layout::sum_percpu_stats(&v))
            .unwrap_or((0, 0)))
    }

    /// XDP 전체·결과별 카운터 (xdp_stats_map 키 0..MAX 를 각각 CPU별 합산).
    /// 슬롯 조회 결과가 None 이면 0 으로 둔다. 슬롯별로 따로 읽으므로 트래픽 중에는 합이 약간 어긋날 수 있다.
    pub fn get_xdp_counters(&self) -> Result<XdpCounters> {
        let map = self.map(XDP_STATS_MAP)?;
        let mut slots = Vec::with_capacity(bpf_layout::xdp_stat::MAX as usize);
        for idx in 0..bpf_layout::xdp_stat::MAX {
            let per_cpu = map
                .lookup_percpu(&idx.to_ne_bytes(), MapFlags::ANY)
                .with_context(|| format!("Failed to read xdp_stats_map slot {}", idx))?;
            slots.push(
                per_cpu
                    .map(|v| bpf_layout::sum_percpu_counters(&v))
                    .unwrap_or((0, 0)),
            );
        }
        Ok(bpf_layout::xdp_counters_from_slots(&slots))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(src: Option<(u32, u32)>, dst: Option<(u32, u32)>) -> FilterRule {
        FilterRule {
            src_ip: src,
            dst_ip: dst,
            src_port_min: 0,
            src_port_max: 65535,
            dst_port_min: 8080,
            dst_port_max: 8080,
            protocol: 6,
            tcp_flags: 0,
            action: 2,
            redirect_ifindex: 0,
            redirect_ifname: None,
            priority: 0,
            rate_limit: 0,
            expire: 0,
            label: "t".to_string(),
            creation_time: 0,
        }
    }

    #[test]
    fn target_selects_map_by_side() {
        let (m, s, a, p) = rule(Some((0x0A00_0002, 32)), None).target().unwrap();
        assert_eq!((m, s, a, p), (FILTER_RULES_MAP, MatchSide::Src, 0x0A00_0002, 32));
        let (m, s, a, p) = rule(None, Some((0x0AC8_000B, 32))).target().unwrap();
        assert_eq!((m, s, a, p), (DST_RULES_MAP, MatchSide::Dst, 0x0AC8_000B, 32));
        assert_eq!(DST_RULES_MAP, "dst_rules");
    }

    #[test]
    fn target_rejects_invariant_violation() {
        assert_eq!(
            rule(Some((1, 32)), Some((2, 32))).target().unwrap_err().to_string(),
            "specify either src_ip or dst_ip, not both"
        );
        assert_eq!(
            rule(None, None).target().unwrap_err().to_string(),
            "src_ip or dst_ip is required"
        );
    }

    #[test]
    fn rule_info_fills_matching_side_only() {
        let info = rule(None, Some((0x0AC8_000B, 32))).to_rule_info(zero_stats());
        assert_eq!(info.src_ip, None);
        assert_eq!(info.dst_ip.as_deref(), Some("10.200.0.11"));
        let info = rule(Some((0x0AC8_0000, 24)), None).to_rule_info(zero_stats());
        assert_eq!(info.src_ip.as_deref(), Some("10.200.0.0/24"));
        assert_eq!(info.dst_ip, None);
    }
}
