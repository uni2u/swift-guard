// Swift-Guard Common Types
// 공통 타입 정의

/// XDP 프로그램 연결 모드
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpMode {
    /// 드라이버 모드 (네이티브 드라이버 지원)
    Driver = 0,
    /// 제네릭 모드 (SKB 기반, 모든 네트워크 카드 지원)
    Generic = 1,
    /// 오프로드 모드 (하드웨어 오프로드, 지원하는 NIC만)
    Offload = 2,
}

impl XdpMode {
    /// 문자열에서 XDP 모드 파싱
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "driver" => Some(Self::Driver),
            "generic" => Some(Self::Generic),
            "offload" => Some(Self::Offload),
            _ => None,
        }
    }
    
    /// XDP 모드를 문자열로 변환
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Driver => "driver",
            Self::Generic => "generic",
            Self::Offload => "offload",
        }
    }
}

/// 액션 타입
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    /// 패킷 통과
    Pass = 1,
    /// 패킷 드롭
    Drop = 2,
    /// 다른 인터페이스로 리디렉션
    Redirect = 3,
    /// 통계만 수집 (패킷 통과)
    Count = 4,
}

impl ActionType {
    /// 숫자에서 액션 타입 변환
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Pass),
            2 => Some(Self::Drop),
            3 => Some(Self::Redirect),
            4 => Some(Self::Count),
            _ => None,
        }
    }
    
    /// 문자열에서 액션 타입 파싱
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pass" => Some(Self::Pass),
            "drop" => Some(Self::Drop),
            "redirect" => Some(Self::Redirect),
            "count" => Some(Self::Count),
            _ => None,
        }
    }
    
    /// 액션 타입을 문자열로 변환
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Drop => "drop",
            Self::Redirect => "redirect",
            Self::Count => "count",
        }
    }
}

/// 프로토콜 타입
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    /// ICMP
    Icmp = 1,
    /// TCP
    Tcp = 6,
    /// UDP
    Udp = 17,
    /// 모든 프로토콜
    Any = 255,
}

impl ProtocolType {
    /// 숫자에서 프로토콜 타입 변환
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Icmp),
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            255 => Some(Self::Any),
            _ => None,
        }
    }
    
    /// 문자열에서 프로토콜 타입 파싱
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "icmp" => Some(Self::Icmp),
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "any" => Some(Self::Any),
            _ => None,
        }
    }
    
    /// 프로토콜 타입을 문자열로 변환
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Any => "any",
        }
    }
}

/// TCP 플래그
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    
    /// 새로운 TCP 플래그 생성
    pub fn new() -> Self {
        Self(0)
    }
    
    /// 플래그 설정
    pub fn set(&mut self, flag: u8) {
        self.0 |= flag;
    }
    
    /// 플래그 확인
    pub fn has(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }
    
    /// 문자열에서 TCP 플래그 파싱
    pub fn from_str(s: &str) -> Self {
        let mut flags = Self::new();
        
        for flag in s.split(',') {
            match flag.trim().to_uppercase().as_str() {
                "FIN" => flags.set(Self::FIN),
                "SYN" => flags.set(Self::SYN),
                "RST" => flags.set(Self::RST),
                "PSH" => flags.set(Self::PSH),
                "ACK" => flags.set(Self::ACK),
                "URG" => flags.set(Self::URG),
                _ => {}
            }
        }
        
        flags
    }
    
    /// TCP 플래그를 문자열로 변환
    pub fn to_str(&self) -> String {
        let mut result = Vec::new();
        
        if self.has(Self::FIN) { result.push("FIN"); }
        if self.has(Self::SYN) { result.push("SYN"); }
        if self.has(Self::RST) { result.push("RST"); }
        if self.has(Self::PSH) { result.push("PSH"); }
        if self.has(Self::ACK) { result.push("ACK"); }
        if self.has(Self::URG) { result.push("URG"); }
        
        if result.is_empty() {
            "NONE".to_string()
        } else {
            result.join(",")
        }
    }
}

/// WASM 모듈 상태
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmModuleState {
    /// 초기화됨
    Initialized,
    /// 로드됨
    Loaded,
    /// 실행 중
    Running,
    /// 일시 중지됨
    Paused,
    /// 오류 발생
    Error,
}

impl WasmModuleState {
    /// 문자열로 변환
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Initialized => "initialized",
            Self::Loaded => "loaded",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Error => "error",
        }
    }
}
