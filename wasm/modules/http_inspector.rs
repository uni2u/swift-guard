//! HTTP 인스펙터 WASM 모듈
//! 의심스러운 HTTP 요청을 탐지하는 WASM 모듈
//! 이 코드는 Rust에서 컴파일하여 WASM으로 변환

use std::mem;

// 호스트 함수 선언
extern "C" {
    fn log(ptr: *const u8, len: i32) -> i32;
}

// 메모리 관리를 위한 전역 할당자
#[no_mangle]
pub extern "C" fn allocate(size: i32) -> i32 {
    let mut buffer = Vec::with_capacity(size as usize);
    let ptr = buffer.as_mut_ptr();
    mem::forget(buffer);
    ptr as i32
}

#[no_mangle]
pub extern "C" fn deallocate(ptr: i32, capacity: i32) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, 0, capacity as usize);
    }
}

// 로그 함수
fn log_message(message: &str) {
    unsafe {
        log(message.as_ptr(), message.len() as i32);
    }
}

// 초기화 함수
#[no_mangle]
pub extern "C" fn init() {
    log_message("HTTP Inspector initialized");
}

// TCP 패킷 구문 분석
fn parse_tcp_packet(data: &[u8], offset: usize) -> Option<(u16, u16, u8)> {
    if data.len() < offset + 20 {
        return None;
    }
    
    let source_port = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
    let dest_port = ((data[offset + 2] as u16) << 8) | (data[offset + 3] as u16);
    let flags = data[offset + 13];
    
    Some((source_port, dest_port, flags))
}

// HTTP 메서드 확인
fn check_http_method(payload: &[u8]) -> bool {
    let methods = [
        b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", 
        b"OPTIONS ", b"CONNECT ", b"TRACE ", b"PATCH "
    ];
    
    for method in &methods {
        if payload.starts_with(method) {
            return true;
        }
    }
    
    false
}

// 의심스러운 HTTP 요청 검사
fn check_suspicious_http(payload: &[u8]) -> bool {
    // SQL 인젝션 패턴
    let sql_patterns = [
        b"UNION SELECT", b"OR 1=1", b"' OR '", b"DROP TABLE",
        b"--", b"/*", b"*/", b"EXEC(", b"EXECUTE(", b"xp_cmdshell"
    ];
    
    // XSS 패턴
    let xss_patterns = [
        b"<script>", b"javascript:", b"onerror=", b"onload=", b"eval(", 
        b"document.cookie", b"alert(", b"String.fromCharCode("
    ];
    
    // 경로 순회 패턴
    let traversal_patterns = [
        b"../", b"..\\", b"/etc/passwd", b"\\windows\\system32", b"C:\\Windows"
    ];
    
    // 명령어 인젝션 패턴
    let cmd_patterns = [
        b";", b"|", b"&", b"$(", b"`", b"$()", b"${", b">"
    ];
    
    // 페이로드가 너무 큰 경우
    if payload.len() > 4096 {
        log_message(&format!("Large HTTP payload detected: {} bytes", payload.len()));
        return true;
    }
    
    // 패턴 검사
    for pattern in &sql_patterns {
        if payload.windows(pattern.len()).any(|window| window == *pattern) {
            log_message(&format!("SQL injection pattern detected: {:?}", pattern));
            return true;
        }
    }
    
    for pattern in &xss_patterns {
        if payload.windows(pattern.len()).any(|window| window == *pattern) {
            log_message(&format!("XSS pattern detected: {:?}", pattern));
            return true;
        }
    }
    
    for pattern in &traversal_patterns {
        if payload.windows(pattern.len()).any(|window| window == *pattern) {
            log_message(&format!("Path traversal pattern detected: {:?}", pattern));
            return true;
        }
    }
    
    for pattern in &cmd_patterns {
        if payload.windows(pattern.len()).any(|window| window == *pattern) {
            log_message(&format!("Command injection pattern detected: {:?}", pattern));
            return true;
        }
    }
    
    false
}

// 패킷 검사 메인 함수 (WASM 인터페이스)
#[no_mangle]
pub extern "C" fn inspect_packet(ptr: i32, len: i32) -> i32 {
    let data = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, len as usize)
    };
    
    // 최소 이더넷 + IP 헤더 크기 확인
    if data.len() < 34 {
        return 0; // 패킷 통과
    }
    
    // 이더넷 헤더 건너뛰기 (14바이트)
    let eth_type = ((data[12] as u16) << 8) | (data[13] as u16);
    
    // IPv4 확인
    if eth_type != 0x0800 {
        return 0; // 패킷 통과
    }
    
    // IP 헤더 길이 계산
    let ip_header_len = (data[14] & 0x0F) as usize * 4;
    
    // 프로토콜 확인 (TCP = 6)
    if data[23] != 6 {
        return 0; // 패킷 통과
    }
    
    // TCP 헤더 파싱
    let ip_offset = 14;
    let tcp_offset = ip_offset + ip_header_len;
    
    if let Some((source_port, dest_port, flags)) = parse_tcp_packet(data, tcp_offset) {
        // HTTP 트래픽 확인 (포트 80 또는 8080)
        if dest_port == 80 || dest_port == 8080 || dest_port == 443 || dest_port == 8443 {
            // TCP 헤더 길이 계산
            let tcp_header_len = ((data[tcp_offset + 12] >> 4) & 0x0F) as usize * 4;
            let payload_offset = tcp_offset + tcp_header_len;
            
            // 페이로드가 있는 경우
            if data.len() > payload_offset {
                let payload = &data[payload_offset..];
                
                // HTTP 요청인지 확인
                if check_http_method(payload) {
                    log_message(&format!("HTTP traffic detected: {}:{} -> {}",
                        source_port, dest_port, 
                        String::from_utf8_lossy(&payload[0..payload.len().min(20)])
                    ));
                    
                    // 의심스러운 HTTP 요청 확인
                    if check_suspicious_http(payload) {
                        log_message("Suspicious HTTP request blocked");
                        return 1; // 패킷 차단
                    }
                }
            }
        }
    }
    
    0 // 패킷 통과
}
