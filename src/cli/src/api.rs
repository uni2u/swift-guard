//! API 클라이언트 모듈
//! 데몬과 통신하기 위한 API 클라이언트 구현
//! 요청/응답 타입은 swift_guard_common::api 가 원천이다(복제 없음).

use anyhow::{anyhow, Result};
use swift_guard_common::api::{ApiRequest, ApiResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
