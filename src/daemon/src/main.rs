//! Swift-Guard Daemon
//! 이 데몬은 BPF 맵을 관리하고 XDP 프로그램의 작동을 제어합니다.

use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::time;

mod bpf;
mod config;
mod maps;
mod server;
mod telemetry;
mod wasm;

use crate::bpf::XdpFilterSkel;
use crate::config::DaemonConfig;
use crate::maps::MapManager;
use crate::server::ApiServer;
use crate::telemetry::TelemetryCollector;

#[derive(Parser, Debug)]
#[clap(name = "swift-guard-daemon", about = "Swift-Guard Daemon")]
struct Args {
    /// BPF 오브젝트 파일 경로
    #[clap(short, long, default_value = "/usr/local/lib/swift-guard/xdp_filter.o")]
    bpf_obj: PathBuf,

    /// 구성 파일 경로
    #[clap(short, long, default_value = "/etc/swift-guard/config.yaml")]
    config: PathBuf,

    /// 대몬으로 실행
    #[clap(short, long)]
    daemon: bool,

    /// API 서버 바인드 주소
    #[clap(long, default_value = "127.0.0.1:7654")]
    api_addr: String,

    /// 상세 로깅
    #[clap(short, long)]
    verbose: bool,
}

async fn run_daemon(args: Args) -> Result<()> {
    // 구성 로드
    let config = config::load_config(&args.config)
        .context("Failed to load configuration")?;

    // BPF 프로그램 로드
    let skel_builder = XdpFilterSkel::builder()
        .obj_path(&args.bpf_obj);

    let open_skel = skel_builder.open()
        .context("Failed to open BPF program")?;

    let mut skel = open_skel.load()
        .context("Failed to load BPF program")?;

    // 맵 관리자 초기화
    let map_manager = Arc::new(MapManager::new(&mut skel)
        .context("Failed to initialize map manager")?);

    // 텔레메트리 수집기 초기화
    let telemetry = Arc::new(TelemetryCollector::new(&skel, &config)
        .context("Failed to initialize telemetry collector")?);

    // API 서버 시작
    let server = ApiServer::new(&args.api_addr, map_manager.clone(), telemetry.clone())
        .context("Failed to create API server")?;

    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.run().await {
            error!("API server error: {}", e);
        }
    });

    // 종료 신호 처리
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Shutting down gracefully...");
                r.store(false, Ordering::SeqCst);
            }
            Err(err) => {
                error!("Unable to listen for shutdown signal: {}", err);
            }
        }
    });

    // 메인 루프
    while running.load(Ordering::SeqCst) {
        telemetry.collect_stats().await?;
        time::sleep(Duration::from_secs(1)).await;
    }

    // 정리
    drop(skel);
    server_handle.abort();

    info!("Swift-Guard daemon stopped");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // 로깅 초기화
    env_logger::init();

    // 명령줄 인수 파싱
    let args = Args::parse();

    if args.verbose {
        std::env::set_var("RUST_LOG", "debug");
    } else {
        std::env::set_var("RUST_LOG", "info");
    }

    // 데몬 모드로 실행
    if args.daemon {
        // TODO: 데몬화 로직 구현
        info!("Running in daemon mode");
    }

    // 데몬 실행
    if let Err(e) = run_daemon(args).await {
        error!("Daemon error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
