//! 유틸리티 모듈
//! 다양한 유틸리티 함수 제공

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

/// 프로토콜 이름을 프로토콜 번호로 변환
pub fn protocol_name_to_num(name: &str) -> Result<u8> {
    match name.to_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "any" => Ok(255),
        _ => Err(anyhow!("Unknown protocol: {}", name)),
    }
}

/// 액션 이름을 액션 번호로 변환
pub fn action_name_to_num(name: &str) -> Result<u8> {
    match name.to_lowercase().as_str() {
        "pass" => Ok(1),
        "drop" => Ok(2),
        "redirect" => Ok(3),
        "count" => Ok(4),
        _ => Err(anyhow!("Unknown action: {}", name)),
    }
}

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

/// IPv4 주소를 문자열로 변환
pub fn ipv4_to_string(addr: u32) -> String {
    format!("{}.{}.{}.{}", 
        (addr >> 24) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 8) & 0xFF,
        addr & 0xFF
    )
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
}
