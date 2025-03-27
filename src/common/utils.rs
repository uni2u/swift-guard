// Swift-Guard Common Utilities
// 공통 유틸리티 함수

use std::net::{IpAddr, Ipv4Addr};
use anyhow::{anyhow, Result};

/// 포트 범위 문자열 파싱 (예: "80" 또는 "1024-2048")
pub fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid port range format: {}", s));
        }
        
        let min = parts[0].trim().parse::<u16>()
            .map_err(|_| anyhow!("Invalid port number: {}", parts[0]))?;
        
        let max = parts[1].trim().parse::<u16>()
            .map_err(|_| anyhow!("Invalid port number: {}", parts[1]))?;
        
        if min > max {
            return Err(anyhow!("Invalid port range: min > max"));
        }
        
        Ok((min, max))
    } else {
        let port = s.trim().parse::<u16>()
            .map_err(|_| anyhow!("Invalid port number: {}", s))?;
        
        Ok((port, port))
    }
}

/// IP 주소 문자열에서 IP 주소와 프리픽스 길이 추출
pub fn parse_ip_prefix(s: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = s.split('/').collect();
    
    let ip_str = parts[0].trim();
    let octets: Vec<&str> = ip_str.split('.').collect();
    if octets.len() != 4 {
        return Err(anyhow!("Invalid IP address format: {}", ip_str));
    }
    
    let mut ip: u32 = 0;
    for (i, octet) in octets.iter().enumerate() {
        let value = octet.parse::<u8>()
            .map_err(|_| anyhow!("Invalid IP address octet: {}", octet))?;
        
        ip |= (value as u32) << (8 * (3 - i));
    }
    
    let prefix_len = if parts.len() > 1 {
        parts[1].trim().parse::<u32>()
            .map_err(|_| anyhow!("Invalid prefix length: {}", parts[1]))?
    } else {
        32 // 프리픽스가 지정되지 않은 경우 32(정확한 IP 매치)
    };
    
    if prefix_len > 32 {
        return Err(anyhow!("Invalid prefix length: {}", prefix_len));
    }
    
    Ok((ip, prefix_len))
}

/// IPv4 주소를 문자열로 변환
pub fn ipv4_to_string(addr: u32) -> String {
    format!("{}.{}.{}.{}", 
        (addr >> 24) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 8) & 0xFF,
        addr & 0xFF
    )
}

/// IPv4 주소를 네트워크 순서(빅 엔디안) u32로 변환
pub fn ipv4_to_u32(addr: &Ipv4Addr) -> u32 {
    let octets = addr.octets();
    ((octets[0] as u32) << 24) |
    ((octets[1] as u32) << 16) |
    ((octets[2] as u32) << 8) |
    (octets[3] as u32)
}

/// u32 네트워크 순서(빅 엔디안)에서 IPv4 주소로 변환
pub fn u32_to_ipv4(addr: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        ((addr >> 24) & 0xFF) as u8,
        ((addr >> 16) & 0xFF) as u8,
        ((addr >> 8) & 0xFF) as u8,
        (addr & 0xFF) as u8
    )
}

/// 현재 시간을 Unix 타임스탬프로 반환 (초 단위)
pub fn current_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 포맷된 크기 문자열 반환 (바이트, KB, MB, GB)
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    
    if bytes >= GB {
        format!("{:.2} GB", (bytes as f64) / (GB as f64))
    } else if bytes >= MB {
        format!("{:.2} MB", (bytes as f64) / (MB as f64))
    } else if bytes >= KB {
        format!("{:.2} KB", (bytes as f64) / (KB as f64))
    } else {
        format!("{} bytes", bytes)
    }
}

// src/common/utils.rs에 추가할 함수들

/// 액션 번호를 액션 이름으로 변환
pub fn action_num_to_name(num: u8) -> String {
    match num {
        1 => "pass".to_string(),
        2 => "drop".to_string(),
        3 => "redirect".to_string(),
        4 => "count".to_string(),
        _ => "unknown".to_string(),
    }
}

/// 프로토콜 번호를 프로토콜 이름으로 변환
pub fn protocol_num_to_name(num: u8) -> String {
    match num {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        255 => "any".to_string(),
        _ => format!("{}", num),
    }
}

/// TCP 플래그 비트맵을 문자열로 변환
pub fn tcp_flags_to_string(flags: u8) -> String {
    let mut result = Vec::new();

    if flags & 0x01 != 0 { result.push("FIN"); }
    if flags & 0x02 != 0 { result.push("SYN"); }
    if flags & 0x04 != 0 { result.push("RST"); }
    if flags & 0x08 != 0 { result.push("PSH"); }
    if flags & 0x10 != 0 { result.push("ACK"); }
    if flags & 0x20 != 0 { result.push("URG"); }

    if result.is_empty() {
        "None".to_string()
    } else {
        result.join(",")
    }
}

/// 포트 범위를 문자열로 변환
pub fn port_range_to_string(min: u16, max: u16) -> Option<String> {
    if min == 0 && max == 65535 {
        None
    } else if min == max {
        Some(format!("{}", min))
    } else {
        Some(format!("{}-{}", min, max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_port_range() {
        assert_eq!(parse_port_range("80").unwrap(), (80, 80));
        assert_eq!(parse_port_range("1024-2048").unwrap(), (1024, 2048));
        assert!(parse_port_range("abc").is_err());
        assert!(parse_port_range("1024-abc").is_err());
        assert!(parse_port_range("2048-1024").is_err());
    }
    
    #[test]
    fn test_parse_ip_prefix() {
        assert_eq!(parse_ip_prefix("192.168.1.1").unwrap(), (0xC0A80101, 32));
        assert_eq!(parse_ip_prefix("10.0.0.0/8").unwrap(), (0x0A000000, 8));
        assert!(parse_ip_prefix("256.168.1.1").is_err());
        assert!(parse_ip_prefix("192.168.1.1/33").is_err());
    }
    
    #[test]
    fn test_ipv4_conversions() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let u32_addr = ipv4_to_u32(&addr);
        assert_eq!(u32_addr, 0xC0A80101);
        assert_eq!(u32_to_ipv4(u32_addr), addr);
    }
}
