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
mod wasm;

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

    // 특정 인터페이스에 XDP 프로그램 로드
    if let Some(interface) = &args.interface {
        info!("인터페이스 {}에 XDP 프로그램 로드 중...", interface);
        if let Err(e) = bpf::load_xdp_program(&args.bpf_obj, interface) {
            error!("XDP 프로그램 로드 실패: {}", e);
        }
    }

    // Ctrl+C 대기
    info!("데몬 실행 중... Ctrl+C로 종료");
    tokio::signal::ctrl_c().await?;
    
    // 종료 처리
    if let Some(interface) = &args.interface {
        info!("인터페이스 {}에서 XDP 프로그램 언로드 중...", interface);
        bpf::unload_xdp_program(interface)?;
    }

    info!("Swift-Guard 데몬 종료");
    Ok(())
}