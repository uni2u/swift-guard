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
    pub total_packets: u64,
    pub total_bytes: u64,
    pub packets_per_sec: u64,
    pub mbps: f64,
}

/// WASM 모듈 정보
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmModuleInfo {
    pub name: String,
    pub state: String,
    pub loaded_at: u64,
}
