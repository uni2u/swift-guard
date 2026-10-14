//! 맵 관리자 모듈
//! BPF 맵(filter_rules / redirect_map / stats_map)을 관리한다.
//!
//! 바이트 직렬화는 전부 `swift_guard::bpf_layout` 을 사용한다(C 레이아웃이 원천).
//! MapManager 는 XdpFilterSkel 을 소유하며 !Send 이므로 main 태스크에서만 사용한다.

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{Map, MapFlags};
use log::{debug, warn};

use crate::bpf::XdpFilterSkel;

use swift_guard::api::{RuleInfo, RuleStats};
use swift_guard::bpf_layout::{self, FilterRuleValue};
use swift_guard::utils;

const FILTER_RULES_MAP: &str = "filter_rules";
const REDIRECT_MAP: &str = "redirect_map";
const STATS_MAP: &str = "stats_map";
const XDP_PROG: &str = "xdp_filter_func";

/// redirect 액션 값 (ACTION_REDIRECT)
pub const ACTION_REDIRECT: u8 = 3;

/// 필터 규칙 정보 (데몬 캐시)
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// (호스트 정수 IP, 프리픽스 길이). XDP 필터는 src IP prefix 로만 매칭하므로 필수.
    pub src_ip: Option<(u32, u32)>,
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

impl FilterRule {
    /// API 룰 정보로 변환
    pub fn to_rule_info(&self, stats: RuleStats) -> RuleInfo {
        RuleInfo {
            label: self.label.clone(),
            action: utils::action_num_to_name(self.action),
            src_ip: self.src_ip.map(|(ip, prefix)| format_prefix(ip, prefix)),
            dst_ip: None, // dst_ip 매칭은 지원하지 않는다
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
    /// 3개 맵과 XDP 프로그램이 오브젝트에 있는지 검증한다.
    pub fn new(skel: XdpFilterSkel) -> Result<Self> {
        for name in [FILTER_RULES_MAP, REDIRECT_MAP, STATS_MAP] {
            if skel.obj.map(name).is_none() {
                return Err(anyhow!("BPF object has no map '{}'", name));
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
    /// 순서: 캐시 중복 검사 → (필요 시) redirect_map → filter_rules(NOEXIST) → 성공 시 캐시 push.
    pub fn add_rule(&mut self, mut rule: FilterRule) -> Result<()> {
        debug!("Adding rule: {}", rule.label);

        // 방어 검사: src_ip 없는 룰은 맵에 들어갈 수 없다
        let (addr, prefix_len) = rule.src_ip.ok_or_else(|| {
            anyhow!("src_ip is required: XDP filter matches by source IP prefix only")
        })?;
        if prefix_len > 32 {
            return Err(anyhow!("invalid prefix length {}", prefix_len));
        }
        let addr = bpf_layout::canonical_prefix(addr, prefix_len);
        rule.src_ip = Some((addr, prefix_len));

        let label = bpf_layout::encode_label(&rule.label)?;

        // (1) 캐시 중복 검사
        if let Some(existing) = self
            .rules
            .iter()
            .find(|r| r.src_ip == Some((addr, prefix_len)))
        {
            return Err(anyhow!(
                "a rule for {}/{} already exists (label '{}')",
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

        // (3) filter_rules
        let res = self
            .map_mut(FILTER_RULES_MAP)?
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
                "Failed to update filter_rules map for {}/{}",
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

        if let Some((addr, prefix_len)) = rule.src_ip {
            let key = bpf_layout::encode_prefix_key(addr, prefix_len);
            match self.map_mut(FILTER_RULES_MAP)?.delete(&key) {
                Ok(()) => {}
                Err(e) if is_enoent(&e) => {
                    warn!("rule '{}' was not present in filter_rules map; removing from cache", label);
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("Failed to delete rule '{}' from filter_rules map", label)));
                }
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

    /// 규칙 목록 조회. include_stats 면 filter_rules 값의 절대 offset 64 에서 통계를 읽는다.
    pub fn list_rules(&self, include_stats: bool) -> Result<Vec<RuleInfo>> {
        let mut result = Vec::with_capacity(self.rules.len());
        let map = if include_stats {
            Some(self.map(FILTER_RULES_MAP)?)
        } else {
            None
        };

        for rule in &self.rules {
            let stats = match (map, rule.src_ip) {
                (Some(map), Some((addr, prefix_len))) => {
                    let key = bpf_layout::encode_prefix_key(addr, prefix_len);
                    let value = map
                        .lookup(&key, MapFlags::ANY)
                        .with_context(|| format!("Failed to look up rule '{}'", rule.label))?;
                    match value {
                        Some(v) => {
                            let (packets, bytes, last_matched) = bpf_layout::decode_rule_stats(&v)
                                .ok_or_else(|| {
                                    anyhow!(
                                        "filter_rules value size {} != {}",
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
                            warn!("rule '{}' is cached but missing from filter_rules map", rule.label);
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
}
