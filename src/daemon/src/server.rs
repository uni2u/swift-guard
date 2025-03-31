//! API 서버 모듈
//! CLI 도구와 통신하기 위한 API 서버 구현

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use serde_json::{self, json};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

//use crate::api::{ApiRequest, ApiResponse};
use crate::maps::{FilterRule, MapManager};
use crate::telemetry::TelemetryCollector;
//use crate::utils;

use swift_guard::api::{RuleInfo, RuleStats, ApiRequest, ApiResponse, SystemStats};
use swift_guard::utils;

/// API 서버
#[derive(Debug)]
pub struct ApiServer<'a> {
    /// 바인드 주소
    addr: String,
    /// 맵 관리자
    map_manager: Arc<Mutex<MapManager<'a>>>,
    /// 텔레메트리 수집기
    telemetry: Arc<TelemetryCollector<'a>>,
}

impl<'a> ApiServer<'a> {
    /// 새로운 API 서버 생성
    pub fn new(
        addr: &str,
        map_manager: Arc<Mutex<MapManager<'a>>>,
        telemetry: Arc<TelemetryCollector>,
    ) -> Result<Self> {
        Ok(Self {
            addr: addr.to_string(),
            map_manager,
            telemetry,
        })
    }
    
    /// 서버 실행
    pub async fn run(&self) -> Result<()> {
        // TCP 리스너 생성
        let listener = TcpListener::bind(&self.addr)
            .await
            .context(format!("Failed to bind to {}", self.addr))?;
        
        info!("API server listening on {}", self.addr);
        
        // 연결 수락 루프
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("Accepted connection from {}", addr);
                    
                    // 요청 처리 작업 생성
                    let map_manager = self.map_manager.clone();
                    let telemetry = self.telemetry.clone();
/*                    
                    tokio::spawn(async move {
//                        if let Err(e) = handle_connection(stream, map_manager, telemetry).await {
                        if let Err(e) = handle_connection(stream, map_manager.clone(), telemetry.clone()).await {
                            error!("Connection error: {}", e);
                        }
                    });
                }
*/
                    // 직접 요청 처리
                    if let Err(e) = handle_connection(stream, map_manager.clone(), telemetry.clone()).await {
                        error!("Connection error: {}", e);
                    }
                }

                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// 클라이언트 연결 처리
async fn handle_connection<'a>(
    mut stream: TcpStream,
    map_manager: Arc<Mutex<MapManager<'a>>>,
    telemetry: Arc<TelemetryCollector<'a>>,
) -> Result<()> {
    // 요청 길이 수신 (4바이트 빅 엔디안)
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)
        .await
        .context("Failed to read request length")?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    
    // 요청 내용 수신
    let mut request_bytes = vec![0u8; len];
    stream.read_exact(&mut request_bytes)
        .await
        .context("Failed to read request")?;
    
    // 요청 역직렬화
    let request: ApiRequest = serde_json::from_slice(&request_bytes)
        .context("Failed to deserialize request")?;
    
    // 요청 처리
    debug!("Processing request: {:?}", request);
    let response = process_request(request, map_manager, telemetry).await?;
    
    // 응답 직렬화
    let response_bytes = serde_json::to_vec(&response)
        .context("Failed to serialize response")?;
    
    // 응답 길이 전송 (4바이트 빅 엔디안)
    let len = response_bytes.len() as u32;
    let len_bytes = len.to_be_bytes();
    stream.write_all(&len_bytes)
        .await
        .context("Failed to write response length")?;
    
    // 응답 내용 전송
    stream.write_all(&response_bytes)
        .await
        .context("Failed to write response")?;
    
    Ok(())
}

/// 요청 처리
async fn process_request<'a>(
    request: ApiRequest,
    map_manager: Arc<Mutex<MapManager<'a>>>,
    telemetry: Arc<TelemetryCollector<'a>>,
) -> Result<ApiResponse> {
    match request {
        ApiRequest::Attach { interface, mode, force } => {
            // XDP 프로그램 연결 로직
            // 실제 구현에서는 특정 인터페이스에 XDP 프로그램을 로드하는 로직 추가
            
            Ok(ApiResponse::Success {
                message: format!("XDP program attached to {} in mode {}", interface, mode),
            })
        },
        
        ApiRequest::Detach { interface } => {
            // XDP 프로그램 분리 로직
            // 실제 구현에서는 특정 인터페이스에서 XDP 프로그램을 언로드하는 로직 추가
            
            Ok(ApiResponse::Success {
                message: format!("XDP program detached from {}", interface),
            })
        },
        
        ApiRequest::AddRule {
            src_ip,
            dst_ip,
            src_port_min,
            src_port_max,
            dst_port_min,
            dst_port_max,
            protocol,
            tcp_flags,
            action,
            redirect_if,
            priority,
            rate_limit,
            expire,
            label,
        } => {
            // IP 주소 파싱
            let src_ip_parsed = if let Some(ip_str) = src_ip {
                Some(utils::parse_ip_prefix(&ip_str)?)
            } else {
                None
            };
            
            let dst_ip_parsed = if let Some(ip_str) = dst_ip {
                Some(utils::parse_ip_prefix(&ip_str)?)
            } else {
                None
            };
            
            // 리디렉션 인터페이스 인덱스 획득
            let redirect_ifindex = if let Some(ifname) = redirect_if {
                // 여기서는 간단히 하기 위해 "if<number>" 형식을 파싱
                if ifname.starts_with("if") {
                    ifname[2..].parse::<u32>()
                        .map_err(|_| anyhow!("Invalid interface format: {}", ifname))?
                } else {
                    0
                }
            } else {
                0
            };
            
            // 현재 시간
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| anyhow!("Failed to get system time"))?
                .as_secs();
            
            // 필터 규칙 생성
            let rule = FilterRule {
                src_ip: src_ip_parsed,
                dst_ip: dst_ip_parsed,
                src_port_min,
                src_port_max,
                dst_port_min,
                dst_port_max,
                protocol,
                tcp_flags,
                action,
                redirect_ifindex,
                priority,
                rate_limit,
                expire,
                label: label.clone(),
                creation_time: now,
            };
            
            // 맵 관리자에 규칙 추가
            let mut map_manager = map_manager.lock()
                .map_err(|_| anyhow!("Failed to lock map_manager"))?;
            
            map_manager.add_rule(rule)?;
            
            Ok(ApiResponse::Success {
                message: format!("Rule '{}' added successfully", label),
            })
        },
        
        ApiRequest::DeleteRule { label } => {
            // 맵 관리자에서 규칙 삭제
            let mut map_manager = map_manager.lock()
                .map_err(|_| anyhow!("Failed to lock map_manager"))?;
            
            let deleted = map_manager.delete_rule(&label)?;
            
            if deleted {
                Ok(ApiResponse::Success {
                    message: format!("Rule '{}' deleted successfully", label),
                })
            } else {
                Ok(ApiResponse::Error {
                    message: format!("Rule '{}' not found", label),
                })
            }
        },
        
        ApiRequest::ListRules { include_stats } => {
            // 맵 관리자에서 규칙 목록 조회
            let map_manager = map_manager.lock()
                .map_err(|_| anyhow!("Failed to lock map_manager"))?;
            
            let rules = map_manager.list_rules(include_stats)?;
            
            Ok(ApiResponse::Rules { rules })
        },
        
        ApiRequest::GetStats {} => {
            // 텔레메트리 수집기에서 통계 조회
            let stats = telemetry.get_stats()?;
            
            Ok(ApiResponse::Stats { stats })
        },

        ApiRequest::LoadWasmModule { name, file_path } => {
            // WASM 모듈 로드 로직

            Ok(ApiResponse::Error {
                message: "WASM module loading not implemented yet".to_string(),
            })
        },

        ApiRequest::UnloadWasmModule { name } => {
            // WASM 모듈 언로드 로직

            Ok(ApiResponse::Error {
                message: "WASM module unloading not implemented yet".to_string(),
            })
        },

        ApiRequest::ListWasmModules { } => {
            // WASM 모듈 목록 조회
            
            Ok(ApiResponse::Error {
                message: "WASM module listing not implemented yet".to_string(),
            })
        },

        ApiRequest::WasmModuleStats { name } => {
            // WASM 모듈 통계

            Ok(ApiResponse::Error {
                message: "WASM module statistics not implemented yet".to_string(),
            })
        },
    }
}
