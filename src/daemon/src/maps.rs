//! 맵 관리자 모듈
//! BPF 맵을 관리하는 기능 제공

use anyhow::{anyhow, Context, Result};
use libbpf_rs::Map;
use log::{debug, error, info, warn};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::bpf::XdpFilterSkel;
//use crate::api::{RuleInfo, RuleStats};
//use crate::utils;

use swift_guard::api::{RuleInfo, RuleStats};
use swift_guard::utils;
use libbpf_rs::MapFlags;

/// 필터 규칙 정보
#[derive(Debug, Clone)]
pub struct FilterRule {
    pub src_ip: Option<(u32, u32)>,  // (IP, 프리픽스 길이)
    pub dst_ip: Option<(u32, u32)>,  // (IP, 프리픽스 길이)
    pub src_port_min: u16,
    pub src_port_max: u16,
    pub dst_port_min: u16,
    pub dst_port_max: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub action: u8,
    pub redirect_ifindex: u32,
    pub priority: u32,
    pub rate_limit: u32,
    pub expire: u32,
    pub label: String,
    pub creation_time: u64,
}

impl FilterRule {
    /// API 룰 정보로 변환
    pub fn to_rule_info(&self, stats: RuleStats) -> RuleInfo {
        RuleInfo {
            label: self.label.clone(),
            action: utils::action_num_to_name(self.action),
            src_ip: self.src_ip.map(|(ip, prefix)| {
                if prefix == 32 {
                    utils::ipv4_to_string(ip)
                } else {
                    format!("{}/{}", utils::ipv4_to_string(ip), prefix)
                }
            }),
            dst_ip: self.dst_ip.map(|(ip, prefix)| {
                if prefix == 32 {
                    utils::ipv4_to_string(ip)
                } else {
                    format!("{}/{}", utils::ipv4_to_string(ip), prefix)
                }
            }),
            src_port: utils::port_range_to_string(self.src_port_min, self.src_port_max),
            dst_port: utils::port_range_to_string(self.dst_port_min, self.dst_port_max),
            protocol: utils::protocol_num_to_name(self.protocol),
            tcp_flags: if self.tcp_flags == 0 {
                None
            } else {
                Some(utils::tcp_flags_to_string(self.tcp_flags))
            },
            priority: self.priority,
            redirect_if: if self.action == 3 && self.redirect_ifindex != 0 {
                Some(format!("if{}", self.redirect_ifindex))
            } else {
                None
            },
            rate_limit: self.rate_limit,
            expire: self.expire,
            stats,
        }
    }
}

/// 리디렉션 인터페이스 정보
#[derive(Debug, Clone)]
pub struct RedirectIf {
    pub ifindex: u32,
    pub ifname: String,
}

/*
/// 맵 관리자
#[derive(Debug)]
pub struct MapManager {
    /// 필터 규칙 맵 (LPM 트라이)
    filter_rules_map: Map,
    /// 리디렉션 맵
    redirect_map: Map,
    /// 통계 맵
    stats_map: Map,
    /// 로컬 규칙 캐시
    rules: Vec<FilterRule>,
}
*/

pub struct MapManager<'a> {
    // XdpFilterSkel에 대한 참조만 유지
//    skel: &'a XdpFilterSkel,
    filter_rules_map: Option<&'a Map>,
    redirect_map: Option<&'a Map>,
    stats_map: Option<&'a Map>,
    rules: Vec<FilterRule>,
}

impl<'a> std::fmt::Debug for MapManager<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapManager")
            .field("rules", &self.rules)
            // Map은 Debug할 수 없으므로 포함하지 않음
            .finish()
    }
}

impl<'a> MapManager<'a> {
    pub fn new(skel: &'a XdpFilterSkel) -> Self {
        Self {
//            skel,
            filter_rules_map: skel.maps().filter_rules(),
            redirect_map: skel.maps().redirect_map(),
            stats_map: skel.maps().stats_map(),
            rules: Vec::new(),
        }
    }
    
    // 필요할 때마다 skel에서 맵을 가져오는 헬퍼 메서드
    fn filter_rules_map(&self) -> Option<&Map> {
        self.skel.maps().filter_rules()
//        let maps = &self.skel.maps();
//        maps.filter_rules()
    }
    
    fn redirect_map(&self) -> Option<&Map> {
        self.skel.maps().redirect_map()
//        let maps = &self.skel.maps();
//        maps.redirect_map()
    }
    
    fn stats_map(&self) -> Option<&Map> {
        self.skel.maps().stats_map()
//        let maps = &self.skel.maps();
//        maps.stats_map()
    }

    /// 규칙 추가
    pub fn add_rule(&mut self, rule: FilterRule) -> Result<()> {
        debug!("Adding rule: {}", rule.label);
        
        // 소스 IP 규칙 추가 (있는 경우)
        if let Some((src_ip, prefix_len)) = rule.src_ip {
            let key = self.create_prefix_key(src_ip, prefix_len);
            let value = self.create_filter_rule(&rule)?;
            
            if let Some(map) = self.filter_rules_map() {
                map.update(&key, &value, libbpf_rs::MapFlags::ANY)
                    .context("Failed to update filter_rules map")?;
            } else {
                return Err(anyhow!("Failed to update filter_rules map"));
            }
        }
        
        // 리디렉션 인터페이스 설정 (필요한 경우)
        if rule.action == 3 && rule.redirect_ifindex != 0 {
            let key = rule.redirect_ifindex.to_le_bytes();
            let if_redirect = self.create_if_redirect(rule.redirect_ifindex, &format!("if{}", rule.redirect_ifindex))?;
            
            if let Some(map) = self.redirect_map() {
                map.update(&key, &if_redirect, libbpf_rs::MapFlags::ANY)
                    .context("Failed to update redirect_map")?;
            } else {
                return Err(anyhow!("Failed to update redirect_map"));
            }
        }
        
        // 로컬 캐시 업데이트
        self.rules.push(rule);
        
        Ok(())
    }
    
    /// 규칙 삭제
    pub fn delete_rule(&mut self, label: &str) -> Result<bool> {
        debug!("Deleting rule: {}", label);
        
        let rule_index = self.rules.iter().position(|r| r.label == label);
        
        if let Some(index) = rule_index {
            let rule = &self.rules[index];
            
            // 소스 IP 규칙 삭제 (있는 경우)
            if let Some((src_ip, prefix_len)) = rule.src_ip {
                let key = self.create_prefix_key(src_ip, prefix_len);
                
                if let Some(map) = self.filter_rules_map() {
                    map.delete(&key)
                        .context("Failed to delete from filter_rules map")?;
                } else {
                    return Err(anyhow!("Failed to get filter_rules map"));
                }
            }
            
            // 로컬 캐시 업데이트
            self.rules.remove(index);
            
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// 규칙 목록 조회
    pub fn list_rules(&self, include_stats: bool) -> Result<Vec<RuleInfo>> {
        let mut result = Vec::new();
        
        for rule in &self.rules {
            let stats = if include_stats {
                // 규칙 통계 조회
                if let Some((src_ip, prefix_len)) = rule.src_ip {
                    let key = self.create_prefix_key(src_ip, prefix_len);
                    
//                    if let Ok(value) = self.filter_rules_map.lookup(&key, 0) {
                    if let Some(map) = self.filter_rules_map() {
                        if let Ok(Some(value)) = map.lookup(&key, MapFlags::empty()) {
                            if value.len() >= std::mem::size_of::<RuleStats>() {
                                let stats_offset = value.len() - std::mem::size_of::<RuleStats>();
                                let stats_bytes = &value[stats_offset..];
                            
                                // 통계 데이터 파싱
                                let packets = u64::from_le_bytes([
                                    stats_bytes[0], stats_bytes[1], stats_bytes[2], stats_bytes[3],
                                    stats_bytes[4], stats_bytes[5], stats_bytes[6], stats_bytes[7],
                                ]);
                            
                                let bytes = u64::from_le_bytes([
                                    stats_bytes[8], stats_bytes[9], stats_bytes[10], stats_bytes[11],
                                    stats_bytes[12], stats_bytes[13], stats_bytes[14], stats_bytes[15],
                                ]);
                            
                                let last_matched = u64::from_le_bytes([
                                    stats_bytes[16], stats_bytes[17], stats_bytes[18], stats_bytes[19],
                                    stats_bytes[20], stats_bytes[21], stats_bytes[22], stats_bytes[23],
                                ]);
                            
                                RuleStats {
                                    packets,
                                    bytes,
                                    last_matched,
                                
                                }
                            } else {
                                 RuleStats {
                                    packets: 0,
                                    bytes: 0,
                                    last_matched: 0,
                                }
                            }
                        } else {
                            RuleStats {
                                packets: 0,
                                bytes: 0,
                                last_matched: 0,
                            }
                        }
                    } else {
                        RuleStats {
                            packets: 0,
                            bytes: 0,
                            last_matched: 0,
                        }
                    }
                } else {
                    RuleStats {
                        packets: 0,
                        bytes: 0,
                        last_matched: 0,
                    }
                }
            } else {
                RuleStats {
                    packets: 0,
                    bytes: 0,
                    last_matched: 0,
                }
            };
            
            
            result.push(rule.to_rule_info(stats));
        }
        
        Ok(result)
    }
    
    /// 전체 통계 조회
    pub fn get_stats(&self) -> Result<(u64, u64)> {
        let key = 0u32.to_le_bytes();
        
//        if let Ok(value) = self.stats_map.lookup(&key, 0) {
        if let Some(map) = self.stats_map() {
            if let Ok(Some(value)) = map.lookup(&key, MapFlags::empty()) {
                if value.len() >= 16 {
                    // 통계 데이터 파싱
                    let packets = u64::from_le_bytes([
                        value[0], value[1], value[2], value[3],
                        value[4], value[5], value[6], value[7],
                    ]);
                
                    let bytes = u64::from_le_bytes([
                        value[8], value[9], value[10], value[11],
                        value[12], value[13], value[14], value[15],
                    ]);
                
                    Ok((packets, bytes))
                } else {
                    Ok((0, 0))
                }
            } else {
                Ok((0, 0))
            }
        } else {
            Ok((0, 0))
        }
    }
    
    /// 프리픽스 키 생성
    fn create_prefix_key(&self, addr: u32, prefix_len: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(8);
        
        // 프리픽스 길이 (u32)
        key.extend_from_slice(&prefix_len.to_le_bytes());
        
        // IPv4 주소 (u32)
        key.extend_from_slice(&addr.to_le_bytes());
        
        key
    }
    
    /// 필터 규칙 생성
    fn create_filter_rule(&self, rule: &FilterRule) -> Result<Vec<u8>> {
        let mut value = Vec::new();
        
        // priority (u32)
        value.extend_from_slice(&rule.priority.to_le_bytes());
        
        // action (u8)
        value.push(rule.action);
        
        // protocol (u8)
        value.push(rule.protocol);
        
        // src_port_min (u16)
        value.extend_from_slice(&rule.src_port_min.to_le_bytes());
        
        // src_port_max (u16)
        value.extend_from_slice(&rule.src_port_max.to_le_bytes());
        
        // dst_port_min (u16)
        value.extend_from_slice(&rule.dst_port_min.to_le_bytes());
        
        // dst_port_max (u16)
        value.extend_from_slice(&rule.dst_port_max.to_le_bytes());
        
        // tcp_flags (u8)
        value.push(rule.tcp_flags);
        
        // redirect_ifindex (u32)
        value.extend_from_slice(&rule.redirect_ifindex.to_le_bytes());
        
        // rate_limit (u32)
        value.extend_from_slice(&rule.rate_limit.to_le_bytes());
        
        // expire (u32)
        value.extend_from_slice(&rule.expire.to_le_bytes());
        
        // label (char[32])
        let mut label_bytes = [0u8; 32];
        for (i, b) in rule.label.as_bytes().iter().enumerate() {
            if i < 31 {
                label_bytes[i] = *b;
            }
        }
        value.extend_from_slice(&label_bytes);
        
        // stats (구조체)
        value.extend_from_slice(&[0u8; 24]); // packets, bytes, last_matched (u64 * 3)
        
        Ok(value)
    }
    
    /// 리디렉션 인터페이스 생성
    fn create_if_redirect(&self, ifindex: u32, ifname: &str) -> Result<Vec<u8>> {
        let mut value = Vec::new();
        
        // ifindex (u32)
        value.extend_from_slice(&ifindex.to_le_bytes());
        
        // ifname (char[16])
        let mut ifname_bytes = [0u8; 16];
        for (i, b) in ifname.as_bytes().iter().enumerate() {
            if i < 15 {
                ifname_bytes[i] = *b;
            }
        }
        value.extend_from_slice(&ifname_bytes);
        
        Ok(value)
    }
}
