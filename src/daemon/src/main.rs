// src/daemon/src/main.rs
use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::signal;

mod bpf;
mod config;
mod maps;
mod server;
mod telemetry;

use crate::maps::MapManager;
use crate::telemetry::TelemetryCollector;

#[derive(Parser, Debug)]
#[clap(name = "swift-guard-daemon", about = "Swift-Guard Daemon")]
struct Args {
    /// BPF 오브젝트 파일 경로
    #[clap(short, long, default_value = "src/bpf/xdp_filter.o")]
    bpf_obj: PathBuf,

    /// 구성 파일 경로
    #[clap(short, long, default_value = "/etc/swift-guard/config.yaml")]
    config: PathBuf,

    /// 인터페이스 이름 (지정하면 자동으로 XDP 프로그램 로드)
    #[clap(short, long)]
    interface: Option<String>,

    /// API 서버 바인드 주소
    #[clap(long, default_value = "127.0.0.1:7654")]
    api_addr: String,

    /// 상세 로깅
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 로깅 초기화
    env_logger::init();

    // 명령줄 인수 파싱
    let args = Args::parse();

    // 로깅 레벨 설정
    if args.verbose {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }

    info!("Swift-Guard 데몬 시작 중...");

    // 구성 로드
    let config = config::load_config(&args.config)
        .context("구성 로드 실패")?;

    // 특정 인터페이스에 XDP 프로그램 로드
    if let Some(interface) = &args.interface {
        info!("인터페이스 {}에 XDP 프로그램 로드 중...", interface);
        if let Err(e) = bpf::load_xdp_program(&args.bpf_obj, interface) {
            error!("XDP 프로그램 로드 실패: {}", e);
        }
    }

    // BPF 프로그램 로드
    let skel = bpf::XdpFilterSkel::builder()
        .obj_path(&args.bpf_obj)
        .open()
        .context("BPF 프로그램 로드 실패")?;

    // 맵 관리자 초기화
    let map_manager = Arc::new(Mutex::new(MapManager::new(&skel)));

    // 텔레메트리 수집기 초기화
    let telemetry = Arc::new(TelemetryCollector::new(&skel, &config)
        .context("텔레메트리 수집기 초기화 실패")?);

    // API 서버 시작
    let server = server::ApiServer::new(&args.api_addr, map_manager.clone(), telemetry.clone())
        .context("API 서버 생성 실패")?;
    
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.run().await {
            error!("API 서버 오류: {}", e);
        }
    });

    // Ctrl+C 대기
    info!("데몬 실행 중... Ctrl+C로 종료");
    signal::ctrl_c().await?;
    
    // 서버 종료
    server_handle.abort();
    
    // 종료 처리
    if let Some(interface) = &args.interface {
        info!("인터페이스 {}에서 XDP 프로그램 언로드 중...", interface);
        bpf::unload_xdp_program(interface)?;
    }

    info!("Swift-Guard 데몬 종료");
    Ok(())
}