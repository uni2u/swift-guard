//! 공통 타입 정의

use std::net::IpAddr;
use thiserror::Error;

/// Swift-Guard 에러 타입
#[derive(Error, Debug)]
pub enum SwiftGuardError {
    #[error("BPF 오류: {0}")]
    BpfError(String),
    
    #[error("WASM 런타임 오류: {0}")]
    WasmError(String),
    
    #[error("설정 오류: {0}")]
    ConfigError(String),
    
    #[error("I/O 오류: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("알 수 없는 오류: {0}")]
    Unknown(String),
}

/// 패킷 처리 결과
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketVerdict {
    /// 패킷 허용 (정상 네트워크 스택으로 전달)
    Pass,
    /// 패킷 차단
    Drop,
    /// 검사 모듈로 리다이렉션
    Redirect,
    /// 추가 분석을 위한 복사 (원본은 허용)
    Copy,
}

/// 필터링 규칙 정의
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// 출발지 IP 주소 (선택적)
    pub src_ip: Option<IpAddr>,
    /// 목적지 IP 주소 (선택적)
    pub dst_ip: Option<IpAddr>,
    /// 출발지 포트 범위 (선택적)
    pub src_port: Option<(u16, u16)>,
    /// 목적지 포트 범위 (선택적)
    pub dst_port: Option<(u16, u16)>,
    /// 프로토콜 (TCP, UDP, ICMP 등)
    pub protocol: Option<u8>,
    /// 추가 필터링 플래그 (TCP 플래그 등)
    pub flags: Option<u8>,
    /// 패킷 처리 결정
    pub verdict: PacketVerdict,
    /// 리다이렉션 대상 (verdict가 Redirect인 경우)
    pub redirect_target: Option<String>,
    /// 규칙 우선순위 (높을수록 먼저 평가)
    pub priority: u32,
    /// 규칙 식별자
    pub id: Option<String>,
}

/// 패킷 메타데이터
#[derive(Debug, Clone)]
pub struct PacketMetadata {
    /// 출발지 IP 주소
    pub src_ip: IpAddr,
    /// 목적지 IP 주소
    pub dst_ip: IpAddr,
    /// 출발지 포트
    pub src_port: u16,
    /// 목적지 포트
    pub dst_port: u16,
    /// 프로토콜
    pub protocol: u8,
    /// 패킷 크기
    pub length: usize,
    /// TCP 플래그 (TCP인 경우)
    pub tcp_flags: Option<u8>,
    /// 타임스탬프
    pub timestamp: std::time::SystemTime,
}

/// 검사 결과
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionVerdict {
    /// 정상 트래픽
    Clean,
    /// 의심스러운 트래픽 (추가 모니터링 필요)
    Suspicious,
    /// 악성 트래픽
    Malicious,
    /// 분석 불가 (데이터 부족 등)
    Inconclusive,
}

/// 성능 측정 결과
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// 처리된 패킷 수
    pub packets_processed: u64,
    /// 필터링된 패킷 수 (verdict별)
    pub packets_filtered: std::collections::HashMap<PacketVerdict, u64>,
    /// 평균 처리 지연 (나노초)
    pub avg_processing_delay_ns: u64,
    /// 99번째 백분위수 처리 지연 (나노초)
    pub p99_processing_delay_ns: u64,
    /// 측정 시작 시간
    pub start_time: std::time::SystemTime,
    /// 측정 종료 시간
    pub end_time: std::time::SystemTime,
}
