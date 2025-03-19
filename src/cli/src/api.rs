//! API 클라이언트 모듈
//! 데몬과 통신하기 위한 API 클라이언트 구현

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

impl std::fmt::Display for RuleInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<20} {:<15} ", self.label, self.action)?;
        
        let src = match (&self.src_ip, &self.src_port) {
            (Some(ip), Some(port)) => format!("{}:{}", ip, port),
            (Some(ip), None) => ip.clone(),
            (None, Some(port)) => format!("*:{}", port),
            (None, None) => "*".to_string(),
        };
        
        let dst = match (&self.dst_ip, &self.dst_port) {
            (Some(ip), Some(port)) => format!("{}:{}", ip, port),
            (Some(ip), None) => ip.clone(),
            (None, Some(port)) => format!("*:{}", port),
            (None, None) => "*".to_string(),
        };
        
        write!(f, "{:<20} {:<10} {:<10}", src, dst, self.protocol)
    }
}

/// 시스템 통계
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub packets_per_sec: u64,
    pub mbps: f64,
}

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
}

/// API 클라이언트
#[derive(Debug)]
pub struct ApiClient {
    server_addr: String,
}

impl ApiClient {
    /// 새로운 API 클라이언트 생성
    pub fn new(server_addr: &str) -> Result<Self> {
        Ok(Self {
            server_addr: server_addr.to_string(),
        })
    }
    
    /// 요청 전송 및 응답 수신
    pub async fn send_request(&self, request: &ApiRequest) -> Result<ApiResponse> {
        // 서버에 연결
        let mut stream = TcpStream::connect(&self.server_addr)
            .await
            .map_err(|e| anyhow!("Failed to connect to API server: {}", e))?;
        
        // 요청 직렬화
        let request_bytes = serde_json::to_vec(request)
            .map_err(|e| anyhow!("Failed to serialize request: {}", e))?;
        
        // 요청 길이 전송 (4바이트 빅 엔디안)
        let len = request_bytes.len() as u32;
        let len_bytes = len.to_be_bytes();
        stream.write_all(&len_bytes)
            .await
            .map_err(|e| anyhow!("Failed to send request length: {}", e))?;
        
        // 요청 내용 전송
        stream.write_all(&request_bytes)
            .await
            .map_err(|e| anyhow!("Failed to send request: {}", e))?;
        
        // 응답 길이 수신 (4바이트 빅 엔디안)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes)
            .await
            .map_err(|e| anyhow!("Failed to receive response length: {}", e))?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        // 응답 내용 수신
        let mut response_bytes = vec![0u8; len];
        stream.read_exact(&mut response_bytes)
            .await
            .map_err(|e| anyhow!("Failed to receive response: {}", e))?;
        
        // 응답 역직렬화
        let response: ApiResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| anyhow!("Failed to deserialize response: {}", e))?;
        
        Ok(response)
    }
}
