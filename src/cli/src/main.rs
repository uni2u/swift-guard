//! Swift-Guard CLI 도구
//! XDP 필터링 규칙을 관리하고 상태를 확인하는 CLI 인터페이스

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use log::{debug, error, info};
use serde::Serialize;
use std::net::IpAddr;
use std::path::PathBuf;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod api;
mod utils;

use api::{ApiClient, ApiRequest, ApiResponse};
use utils::parse_port_range;

#[derive(Parser, Debug)]
#[clap(name = "xdp-filter", about = "XDP Filtering Tool", version)]
struct Cli {
    /// API 서버 주소
    #[clap(long, default_value = "127.0.0.1:7654")]
    api_server: String,

    /// 상세 로깅
    #[clap(short, long)]
    verbose: bool,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// XDP 프로그램을 인터페이스에 연결
    Attach {
        /// 네트워크 인터페이스 이름
        interface: String,

        /// 연결 모드 (driver, generic, offload)
        #[clap(long, default_value = "driver")]
        mode: String,

        /// 지원 여부 확인 스킵
        #[clap(long)]
        force: bool,
    },

    /// XDP 프로그램을 인터페이스에서 분리
    Detach {
        /// 네트워크 인터페이스 이름
        interface: String,
    },

    /// 필터링 규칙 추가
    AddRule {
        /// 소스 IP 주소 (a.b.c.d 또는 a.b.c.d/prefix)
        #[clap(long)]
        src_ip: Option<String>,

        /// 대상 IP 주소 (a.b.c.d 또는 a.b.c.d/prefix)
        #[clap(long)]
        dst_ip: Option<String>,

        /// 소스 포트 또는 포트 범위 (포트 또는 포트1-포트2)
        #[clap(long)]
        src_port: Option<String>,

        /// 대상 포트 또는 포트 범위 (포트 또는 포트1-포트2)
        #[clap(long)]
        dst_port: Option<String>,

        /// 프로토콜 (tcp, udp, icmp, any)
        #[clap(long)]
        protocol: Option<String>,

        /// TCP 플래그 (SYN,ACK,FIN,RST,PSH,URG)
        #[clap(long)]
        tcp_flags: Option<String>,

        /// 패킷 길이 범위 (min-max)
        #[clap(long)]
        pkt_len: Option<String>,

        /// 액션 (pass, drop, redirect, count)
        #[clap(long)]
        action: String,

        /// 리디렉션 인터페이스 (리디렉션 액션에 필요)
        #[clap(long)]
        redirect_if: Option<String>,

        /// 규칙 우선순위 (높을수록 우선)
        #[clap(long, default_value = "0")]
        priority: u32,

        /// 초당 패킷 수 레이트 리밋 (0 = 무제한)
        #[clap(long, default_value = "0")]
        rate_limit: u32,

        /// 규칙 만료 시간 (초, 0 = 만료 없음)
        #[clap(long, default_value = "0")]
        expire: u32,

        /// 규칙 이름/레이블
        #[clap(long)]
        label: String,
    },

    /// 필터링 규칙 삭제
    DeleteRule {
        /// 규칙 레이블
        #[clap(long)]
        label: String,
    },

    /// 활성 규칙 나열
    ListRules {
        /// 통계 포함
        #[clap(long)]
        stats: bool,
    },

    /// 성능 통계 표시
    Stats {
        /// 통계 업데이트 간격 (초)
        #[clap(long, default_value = "1")]
        interval: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // 로깅 초기화
    env_logger::init();

    // 명령줄 인수 파싱
    let cli = Cli::parse();

    if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }

    // API 클라이언트 생성
    let client = ApiClient::new(&cli.api_server)
        .context("Failed to create API client")?;

    // 명령 실행
    match &cli.command {
        Commands::Attach { interface, mode, force } => {
            debug!("Attaching XDP program to interface: {}", interface);
            
            let mode_value = match mode.as_str() {
                "driver" => 0,
                "generic" => 1,
                "offload" => 2,
                _ => return Err(anyhow!("Invalid mode: {}", mode)),
            };
            
            let request = ApiRequest::Attach {
                interface: interface.clone(),
                mode: mode_value,
                force: *force,
            };
            
            let response = client.send_request(&request).await
                .context("Failed to send attach request")?;
            
            match response {
                ApiResponse::Success { message } => {
                    println!("Success: {}", message);
                },
                ApiResponse::Error { message } => {
                    return Err(anyhow!("Error: {}", message));
                },
                ApiResponse::Rules { .. } | ApiResponse::Stats { .. } => {
                    return Err(anyhow!("Unexpected response type"))
                }
            }
        },
        
        Commands::Detach { interface } => {
            debug!("Detaching XDP program from interface: {}", interface);
            
            let request = ApiRequest::Detach {
                interface: interface.clone(),
            };
            
            let response = client.send_request(&request).await
                .context("Failed to send detach request")?;
            
            match response {
                ApiResponse::Success { message } => {
                    println!("Success: {}", message);
                },
                ApiResponse::Error { message } => {
                    return Err(anyhow!("Error: {}", message));
                },
                ApiResponse::Rules { .. } | ApiResponse::Stats { .. } => {
                    return Err(anyhow!("Unexpected response type"))
                }
            }
        },
        
        Commands::AddRule { src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, 
                          pkt_len, action, redirect_if, priority, rate_limit, expire, label } => {
            debug!("Adding filter rule: {}", label);
            
            // 액션 파싱
            let action_value = match action.as_str() {
                "pass" => 1,
                "drop" => 2,
                "redirect" => 3,
                "count" => 4,
                _ => return Err(anyhow!("Invalid action: {}", action)),
            };
            
            // 프로토콜 파싱
            let protocol_value = match protocol {
                Some(p) => match p.as_str() {
                    "tcp" => 6,
                    "udp" => 17,
                    "icmp" => 1,
                    "any" => 255,
                    _ => return Err(anyhow!("Invalid protocol: {}", p)),
                },
                None => 255, // ANY
            };
            
            // 포트 범위 파싱
            let (src_port_min, src_port_max) = match src_port {
                Some(p) => parse_port_range(p)?,
                None => (0, 65535),
            };
            
            let (dst_port_min, dst_port_max) = match dst_port {
                Some(p) => parse_port_range(p)?,
                None => (0, 65535),
            };
            
            // TCP 플래그 파싱
            let tcp_flags_value = match tcp_flags {
                Some(f) => {
                    let mut flags = 0;
                    for flag in f.split(',') {
                        match flag.trim() {
                            "FIN" => flags |= 0x01,
                            "SYN" => flags |= 0x02,
                            "RST" => flags |= 0x04,
                            "PSH" => flags |= 0x08,
                            "ACK" => flags |= 0x10,
                            "URG" => flags |= 0x20,
                            _ => return Err(anyhow!("Invalid TCP flag: {}", flag)),
                        }
                    }
                    flags
                },
                None => 0,
            };
            
            // 리디렉션 인터페이스 확인
            if action_value == 3 && redirect_if.is_none() {
                return Err(anyhow!("Redirect action requires 'redirect_if' parameter"));
            }
            
            let request = ApiRequest::AddRule {
                src_ip: src_ip.clone(),
                dst_ip: dst_ip.clone(),
                src_port_min,
                src_port_max,
                dst_port_min,
                dst_port_max,
                protocol: protocol_value,
                tcp_flags: tcp_flags_value,
                action: action_value,
                redirect_if: redirect_if.clone(),
                priority: *priority,
                rate_limit: *rate_limit,
                expire: *expire,
                label: label.clone(),
            };
            
            let response = client.send_request(&request).await
                .context("Failed to send add rule request")?;
            
            match response {
                ApiResponse::Success { message } => {
                    println!("Rule added: {}", message);
                },
                ApiResponse::Error { message } => {
                    return Err(anyhow!("Error: {}", message));
                },
                ApiResponse::Rules { .. } | ApiResponse::Stats { .. } => {
                    return Err(anyhow!("Unexpected response type"))
                }
            }
        },
        
        Commands::DeleteRule { label } => {
            debug!("Deleting filter rule: {}", label);
            
            let request = ApiRequest::DeleteRule {
                label: label.clone(),
            };
            
            let response = client.send_request(&request).await
                .context("Failed to send delete rule request")?;
            
            match response {
                ApiResponse::Success { message } => {
                    println!("Rule deleted: {}", message);
                },
                ApiResponse::Error { message } => {
                    return Err(anyhow!("Error: {}", message));
                },
                ApiResponse::Rules { .. } | ApiResponse::Stats { .. } => {
                    return Err(anyhow!("Unexpected response type"))
                }
            }
        },
        
        Commands::ListRules { stats } => {
            debug!("Listing filter rules");
            
            let request = ApiRequest::ListRules {
                include_stats: *stats,
            };
            
            let response = client.send_request(&request).await
                .context("Failed to send list rules request")?;
            
            match response {
                ApiResponse::Rules { rules } => {
                    if rules.is_empty() {
                        println!("No rules found");
                    } else {
                        println!("{:<20} {:<15} {:<20} {:<10} {:<10}", 
                                "LABEL", "ACTION", "SOURCE", "DEST", "PROTOCOL");
                        println!("{}", "-".repeat(80));
                        
                        for rule in rules {
                            println!("{}", rule);
                            if *stats {
                                println!("  Packets: {}, Bytes: {}", 
                                        rule.stats.packets, rule.stats.bytes);
                            }
                        }
                    }
                },
                _ => {
                    return Err(anyhow!("Unexpected response from server"));
                }
            }
        },
        
        Commands::Stats { interval } => {
            debug!("Showing performance statistics");
            
            println!("Collecting statistics (press Ctrl+C to exit)...");
            
            loop {
                let request = ApiRequest::GetStats {};
                
                let response = client.send_request(&request).await
                    .context("Failed to send get stats request")?;
                
                match response {
                    ApiResponse::Stats { stats } => {
                        println!("Timestamp: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
                        println!("Total packets: {}", stats.total_packets);
                        println!("Total bytes: {} ({:.2} MB)", 
                                stats.total_bytes, 
                                stats.total_bytes as f64 / (1024.0 * 1024.0));
                        println!("Packets/sec: {}", stats.packets_per_sec);
                        println!("Bandwidth: {:.2} Mbps", stats.mbps);
                        println!("{}", "-".repeat(40));
                    },
                    _ => {
                        return Err(anyhow!("Unexpected response from server"));
                    }
                }
                
                tokio::time::sleep(std::time::Duration::from_secs(*interval)).await;
            }
        },
    }
    
    Ok(())
}
