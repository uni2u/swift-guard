// src/daemon/src/main.rs
//! Swift-Guard 데몬
//! BPF 오브젝트 load → (선택) XDP attach → API 서버 + 텔레메트리 → 종료 시 detach
//!
//! libbpf-rs Object/Map 은 !Send 라서 MapManager / XdpAttachManager 는 main 태스크에서만 쓴다.
//! API 서버(accept 루프 + BPF 요청 처리)와 텔레메트리 루프, 시그널은 tokio::select! 로 같은 태스크 안에서
//! 폴링한다. 연결 I/O 와 WASM 요청은 별도 태스크(로드는 spawn_blocking)라 이 루프를 막지 않는다 (R2-1).

use anyhow::{Context, Result};
use clap::Parser;
use log::{error, info, warn, LevelFilter};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};

mod bpf;
mod config;
mod maps;
mod server;
mod telemetry;
mod wasm;

use crate::bpf::{XdpAttachManager, XdpFilterSkel};
use crate::maps::MapManager;
use crate::server::ApiServer;
use crate::telemetry::TelemetryCollector;
use crate::wasm::WasmManager;

#[derive(Parser, Debug)]
#[clap(name = "swift-guard-daemon", about = "Swift-Guard Daemon")]
struct Args {
    /// BPF 오브젝트 파일 경로
    #[clap(short, long, default_value = "src/bpf/xdp_filter.o")]
    bpf_obj: PathBuf,

    /// 구성 파일 경로
    #[clap(short, long, default_value = "/etc/swift-guard/config.yaml")]
    config: PathBuf,

    /// 인터페이스 이름 (지정하면 기동 시 XDP 프로그램을 attach)
    #[clap(short, long)]
    interface: Option<String>,

    /// API 서버 바인드 주소
    #[clap(long, default_value = "127.0.0.1:7654")]
    api_addr: String,

    /// 상세 로깅
    #[clap(short, long)]
    verbose: bool,
}

/// 주기적으로 맵 통계를 읽어 텔레메트리에 반영 (반환하지 않음)
async fn telemetry_loop(
    map_manager: &Mutex<MapManager>,
    telemetry: &TelemetryCollector,
    interval: Duration,
) -> Result<()> {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        // MutexGuard 는 이 블록 안에서만 유지 (await 를 넘기지 않음)
        let totals = {
            let mm = map_manager
                .lock()
                .map_err(|_| anyhow::anyhow!("Failed to lock map_manager"))?;
            mm.get_stats()
        };
        match totals {
            Ok(t) => {
                if let Err(e) = telemetry.collect_stats(t) {
                    warn!("telemetry collect failed: {:#}", e);
                }
            }
            Err(e) => warn!("stats_map read failed: {:#}", e),
        }
    }
}

/// 스코프를 벗어날 때(정상 종료·`?` 에러 반환·main 태스크의 panic unwind) 붙인 XDP 를 모두 뗀다.
/// release 프로필도 `panic = "unwind"`(루트 Cargo.toml)라 panic 시 Drop 이 실행된다.
/// SIGKILL·abort 등 unwind 없는 종료는 정리할 수 없다 → `ip link set dev <if> xdp off` 로 수동 해제.
struct DetachGuard(Arc<Mutex<XdpAttachManager>>);

impl Drop for DetachGuard {
    fn drop(&mut self) {
        match self.0.lock() {
            Ok(mut a) => a.detach_all(),
            // poison 이어도 내부 상태는 유효하므로 꺼내서 정리한다
            Err(poisoned) => {
                error!("attach manager lock poisoned; detaching anyway");
                poisoned.into_inner().detach_all();
            }
        }
    }
}

/// 종료 시 남은 백그라운드 작업(진행 중인 WASM 컴파일 등)을 기다리는 최대 시간.
/// XDP detach 는 이보다 먼저(run 반환 시) 끝난다.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

fn main() -> Result<()> {
    // #[tokio::main] 의 런타임 drop 은 spawn_blocking 작업(WASM 컴파일)이 끝날 때까지 무기한 기다린다.
    // 직접 만든 런타임을 shutdown_timeout 으로 내려 시그널 후 종료가 지연되지 않게 한다.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to build tokio runtime")?;
    let result = rt.block_on(run());
    rt.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    result
}

async fn run() -> Result<()> {
    // 1. 인수 파싱
    let args = Args::parse();

    // 2. 로거 (--verbose → debug, 아니면 RUST_LOG 또는 info)
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    if args.verbose {
        logger.filter_level(LevelFilter::Debug);
    }
    logger.init();

    info!("Swift-Guard 데몬 시작 중...");

    // 3. 구성
    let cfg = config::load_config(&args.config)?;

    // 4. BPF 오브젝트 로드
    let skel = XdpFilterSkel::builder()
        .obj_path(&args.bpf_obj)
        .open()
        .context("BPF object load failed")?;

    // 5. 맵 관리자
    let map_manager = MapManager::new(skel)?;
    let prog_fd = map_manager.xdp_prog_fd()?;
    let map_manager = Arc::new(Mutex::new(map_manager));

    // 6. 시그널 핸들러를 attach 전에 설치한다 (N-3).
    //    attach 이후에 설치하면 그 사이의 SIGTERM/SIGINT 나 설치 실패로 detach 없이 종료된다.
    let mut sigterm = signal(SignalKind::terminate()).context("Failed to install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("Failed to install SIGINT handler")?;

    // 7. XDP attach (선택). 이 시점 이후로는 어떤 경로(에러 반환·main 태스크 panic unwind)로 끝나도
    //    DetachGuard 의 Drop 이 detach_all 을 호출한다. (SIGKILL 은 예외)
    let attach = Arc::new(Mutex::new(XdpAttachManager::new()));
    let _detach_guard = DetachGuard(attach.clone());
    if let Some(iface) = &args.interface {
        info!("인터페이스 {}에 XDP 프로그램 attach 중...", iface);
        attach
            .lock()
            .map_err(|_| anyhow::anyhow!("Failed to lock attach manager"))?
            .attach(prog_fd, iface, None, false)
            .with_context(|| format!("Failed to attach XDP program to {}", iface))?;
    }

    // 8~10. 텔레메트리, WASM, API 서버
    let telemetry = Arc::new(TelemetryCollector::new(&cfg));
    let wasm = Arc::new(WasmManager::new());
    let server = ApiServer::new(
        &args.api_addr,
        map_manager.clone(),
        attach.clone(),
        telemetry.clone(),
        wasm,
    );
    let interval = Duration::from_secs(cfg.telemetry.interval.max(1));

    // 11. 실행 (SIGTERM 은 systemd stop). WASM 로드 중에도 시그널 분기는 바로 선택된다.
    let result: Result<()> = tokio::select! {
        r = server.run() => r.context("API server stopped"),
        r = telemetry_loop(&map_manager, &telemetry, interval) => r.context("telemetry loop stopped"),
        _ = sigint.recv() => {
            info!("SIGINT 수신, 종료합니다");
            Ok(())
        }
        _ = sigterm.recv() => {
            info!("SIGTERM 수신, 종료합니다");
            Ok(())
        }
    };

    // 12. 종료 시 detach (netlink attach 는 프로세스 종료 후에도 남는다).
    //     정상 경로에서도 명시적으로 호출하고, guard 는 남은 것이 없으면 아무것도 하지 않는다.
    drop(_detach_guard);

    if let Err(e) = &result {
        error!("데몬 비정상 종료: {:#}", e);
    }
    info!("Swift-Guard 데몬 종료");
    result
}
