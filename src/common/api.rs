// Swift-Guard Common API
// CLI와 데몬 간의 통신을 위한 API 정의

use serde::{Deserialize, Serialize};

/// API 요청
#[derive(Debug, Serialize, Deserialize)]
pub enum ApiRequest {
    /// XDP 프로그램 연결
    Attach {
        interface: String,
        mode: u32,
        force: bool,
    },
    
    /// XDP 프로그램 분리
    Detach {
        interface: String,
    },
    
    /// 필터 규칙 추가
    AddRule {
        src_ip: Option<String>,
        dst_ip: Option<String>,
        src_port_min: u16,
        src_port_max: u16,
        dst_port_min: u16,
        dst_port_max: u16,
        protocol: u8,
        tcp_flags: u8,
        action: u8,
        redirect_if: Option<String>,
        priority: u32,
        rate_limit: u32,
        expire: u32,
        label: String,
    },
    
    /// 필터 규칙 삭제
    DeleteRule {
        label: String,
    },
    
    /// 필터 규칙 목록 조회
    ListRules {
        include_stats: bool,
    },
    
    /// 통계 조회
    GetStats {},
    
    /// WASM 모듈 로드
    LoadWasmModule {
        name: String,
        file_path: String,
    },
    
    /// WASM 모듈 언로드
    UnloadWasmModule {
        name: String,
    },
    
    /// WASM 모듈 목록 조회
    ListWasmModules {},
    
    /// WASM 모듈 통계 조회
    WasmModuleStats {
        name: String,
    },
}

/// API 응답
#[derive(Debug, Serialize, Deserialize)]
pub enum ApiResponse {
    /// 성공
    Success {
        message: String,
    },
    
    /// 오류
    Error {
        message: String,
    },
    
    /// 규칙 목록
    Rules {
        rules: Vec<RuleInfo>,
    },
    
    /// 통계
    Stats {
        stats: SystemStats,
    },
    
    /// WASM 모듈 목록
    WasmModules {
        modules: Vec<WasmModuleInfo>,
    },
    
    /// WASM 모듈 통계
    WasmModuleStats {
        name: String,
        processed_packets: u64,
        blocked_packets: u64,
        avg_processing_time_us: f64,
    },
}

/// 필터 규칙 통계
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_matched: u64,
}

/// 필터 규칙 정보
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleInfo {
    pub label: String,
    pub action: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<String>,
    pub dst_port: Option<String>,
    pub protocol: String,
    pub tcp_flags: Option<String>,
    pub priority: u32,
    pub redirect_if: Option<String>,
    pub rate_limit: u32,
    pub expire: u32,
    pub stats: RuleStats,
}

/// 시스템 통계
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStats {
    /// 룰에 매치한 패킷 수 (stats_map). 매치하지 않은 패킷은 포함되지 않는다.
    pub total_packets: u64,
    /// 룰에 매치한 바이트 수 (stats_map)
    pub total_bytes: u64,
    /// daemon 텔레메트리 주기 값 (CLI 는 쓰지 않음, 와이어 호환용)
    pub packets_per_sec: u64,
    /// daemon 텔레메트리 주기 값 (CLI 는 쓰지 않음, 와이어 호환용)
    pub mbps: f64,
    /// xdp_stats_map 합산 (XDP 가 본 전체 패킷과 결과별 카운터).
    /// 구 daemon 응답에는 필드가 없다 → None. 신 daemon 은 항상 Some.
    #[serde(default)]
    pub xdp: Option<XdpCounters>,
}

/// XDP 전체 패킷·결과별 카운터 (xdp_stats_map 슬롯 SG_STAT_* 의 CPU 합산).
/// 불변식(트래픽 정지 시): rx_packets = drop + pass + redirect + count + no_match + invalid
/// + non_ipv4 + action_error.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
pub struct XdpCounters {
    /// SG_STAT_RX.packets — XDP 진입 전체 (파싱 전, 모든 프레임)
    pub rx_packets: u64,
    /// SG_STAT_RX.bytes — L2 프레임 길이 합 (FCS 제외)
    pub rx_bytes: u64,
    /// SG_STAT_DROP — 룰 action=drop
    pub drop_packets: u64,
    /// SG_STAT_PASS — 룰 action=pass
    pub pass_packets: u64,
    /// SG_STAT_REDIRECT — 룰 action=redirect, bpf_redirect 반환 (전송 성공 보장 아님)
    pub redirect_packets: u64,
    /// SG_STAT_COUNT — 룰 action=count
    pub count_packets: u64,
    /// SG_STAT_NO_MATCH — 정상 IPv4, 매치 룰 없음 → PASS
    pub no_match_packets: u64,
    /// SG_STAT_INVALID — 파서 정책으로 무조건 DROP (비정상 헤더, tiny fragment, TCP off=1)
    pub invalid_packets: u64,
    /// SG_STAT_NON_IPV4 — 비IPv4(IPv6/ARP/VLAN 태그 등) 또는 14B 미만 → 검사 없이 PASS
    pub non_ipv4_packets: u64,
    /// SG_STAT_ACTION_ERR — 룰은 매치했지만 실행 불가 → PASS
    pub action_error_packets: u64,
}

/// WASM 모듈 정보
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmModuleInfo {
    pub name: String,
    pub state: String,
    pub loaded_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 구 daemon 응답 형식을 흉내 낸 사본 (xdp 필드 없음)
    #[derive(Debug, Deserialize)]
    struct OldSystemStats {
        total_packets: u64,
        total_bytes: u64,
        packets_per_sec: u64,
        mbps: f64,
    }

    #[test]
    fn old_json_without_xdp_is_none() {
        let json = r#"{"Stats":{"stats":{"total_packets":3,"total_bytes":294,"packets_per_sec":0,"mbps":0.0}}}"#;
        match serde_json::from_str::<ApiResponse>(json).unwrap() {
            ApiResponse::Stats { stats } => {
                assert_eq!(stats.total_packets, 3);
                assert_eq!(stats.total_bytes, 294);
                assert!(stats.xdp.is_none());
            }
            other => panic!("unexpected {:?}", other),
        }
    }

    fn new_stats() -> SystemStats {
        SystemStats {
            total_packets: 3,
            total_bytes: 294,
            packets_per_sec: 1,
            mbps: 0.5,
            xdp: Some(XdpCounters {
                rx_packets: 10,
                rx_bytes: 980,
                drop_packets: 3,
                pass_packets: 0,
                redirect_packets: 0,
                count_packets: 0,
                no_match_packets: 5,
                invalid_packets: 1,
                non_ipv4_packets: 1,
                action_error_packets: 0,
            }),
        }
    }

    #[test]
    fn new_json_readable_by_old_struct() {
        let json = serde_json::to_string(&new_stats()).unwrap();
        assert!(json.contains(r#""xdp":{"rx_packets":10,"rx_bytes":980,"drop_packets":3"#), "{}", json);
        let old: OldSystemStats = serde_json::from_str(&json).unwrap();
        assert_eq!((old.total_packets, old.total_bytes, old.packets_per_sec), (3, 294, 1));
        assert!((old.mbps - 0.5).abs() < 1e-12);
    }

    #[test]
    fn system_stats_roundtrip() {
        let resp = ApiResponse::Stats { stats: new_stats() };
        let json = serde_json::to_string(&resp).unwrap();
        match serde_json::from_str::<ApiResponse>(&json).unwrap() {
            ApiResponse::Stats { stats } => {
                assert_eq!(stats.xdp, new_stats().xdp);
                assert_eq!(stats.total_packets, 3);
            }
            other => panic!("unexpected {:?}", other),
        }
        // xdp: None 은 null 로 직렬화되고 다시 None 으로 읽힌다
        let mut s = new_stats();
        s.xdp = None;
        let back: SystemStats = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(back.xdp.is_none());
    }
}
