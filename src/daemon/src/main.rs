// src/daemon/src/main.rs
//! Swift-Guard 데몬
//! BPF 오브젝트 load → (선택) XDP attach → API 서버 + 텔레메트리 → 종료 시 detach
//!
//! libbpf-rs Object/Map 은 !Send 라서 MapManager / XdpAttachManager 는 main 태스크에서만 쓴다.
//! API 서버(accept 루프 + BPF 요청 처리)와 텔레메트리 루프, 시그널은 tokio::select! 로 같은 태스크 안에서
//! 폴링한다. 연결 I/O 와 WASM 요청은 별도 태스크(로드는 spawn_blocking)라 이 루프를 막지 않는다 (R2-1).
//!
//! API 는 기본으로 Unix 소켓 `/run/swift-guard/api.sock`(root:swift-guard 0660)에서 받는다.
//! 소켓은 BPF 로드 전에 확보한다 — 중복 기동을 XDP·맵을 건드리기 전에 거부한다 (D13).
//! 커널이 최소 버전(5.15) 미만이면 경고만 하고 계속한다 (D2, 실제 판정은 verifier).

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
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
use crate::server::{bind_api, ApiServer};
use swift_guard::endpoint::{ApiEndpoint, DEFAULT_API_ENDPOINT, DEFAULT_API_GROUP};
use swift_guard::utils::kernel_version_warning;
use crate::telemetry::TelemetryCollector;
use crate::wasm::{WasmLimits, WasmManager};

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

    /// API 주소: unix:/path (기본) 또는 tcp:<loopback-ip>:<port> (루프백만, 인증 없음)
    #[clap(long, value_name = "ENDPOINT", default_value = DEFAULT_API_ENDPOINT, value_parser = parse_endpoint)]
    api_addr: ApiEndpoint,

    /// Unix API 소켓 그룹 (기본 swift-guard). 그룹이 없으면 소켓은 0600(root 전용). TCP 면 무시
    #[clap(long, value_name = "GROUP")]
    api_group: Option<String>,

    /// 상세 로깅
    #[clap(short, long)]
    verbose: bool,
}

/// clap value_parser: 주소 문법·루프백 검사는 common::endpoint 가 원천이다
fn parse_endpoint(s: &str) -> std::result::Result<ApiEndpoint, String> {
    s.parse::<ApiEndpoint>().map_err(|e| format!("{:#}", e))
}

/// 최소 커널 검사 (C-2): 미만이면 경고만. 읽기·파싱 실패는 debug.
fn check_kernel_version() {
    match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        Ok(release) => match kernel_version_warning(&release) {
            Some(msg) => warn!("{}", msg),
            None => debug!("kernel {} (minimum 5.15)", release.trim()),
        },
        Err(e) => debug!("cannot read kernel release: {}", e),
    }
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

/// wasm.auto_load_modules 를 백그라운드 태스크에서 순차 로드한다(컴파일은 blocking 풀).
/// 서버의 동시 로드 상한과는 별개이며, 순차이므로 추가로 최대 1개만 겹친다.
fn spawn_auto_load(wasm: Arc<WasmManager>, modules_dir: &str, entries: &[String]) {
    let jobs: Vec<_> = entries
        .iter()
        .map(|e| config::resolve_module_entry(modules_dir, e))
        .collect();
    tokio::spawn(async move {
        for (name, path) in jobs {
            let w = wasm.clone();
            let (n, p) = (name.clone(), path.clone());
            let res = tokio::task::spawn_blocking(move || w.load_module(&n, &p)).await;
            match res {
                Ok(Ok(())) => info!("auto-loaded WASM module '{}' from {}", name, path.display()),
                Ok(Err(e)) => error!("failed to auto-load WASM module from {}: {:#}", path.display(), e),
                Err(e) => error!("failed to auto-load WASM module from {}: {}", path.display(), e),
            }
        }
    });
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

    // 2. 구성 (로거보다 먼저 읽어 general.log_level 을 적용한다. 경고는 로거 초기화 후 출력)
    let loaded = config::load_config(&args.config);

    // 3. 로거. 우선순위: -v(debug) > RUST_LOG > general.log_level > info
    //    구성 로드가 실패해도 에러를 출력할 수 있도록 로거는 먼저 초기화한다(info).
    let cfg_level = loaded
        .as_ref()
        .map(|l| l.config.general.log_level.clone())
        .unwrap_or_else(|_| "info".to_string());
    let rust_log = std::env::var("RUST_LOG").ok();
    let mut logger = env_logger::Builder::new();
    match config::resolve_log_filter(args.verbose, rust_log.as_deref(), &cfg_level) {
        config::LogFilter::Level(level) => logger.filter_level(level),
        config::LogFilter::Env(spec) => logger.parse_filters(&spec),
    };
    logger.init();

    info!("Swift-Guard 데몬 시작 중...");
    let loaded = loaded?;
    for n in &loaded.notes {
        info!("{}", n);
    }
    for w in &loaded.warnings {
        warn!("{}", w);
    }
    let cfg = loaded.config;

    // 3a. 커널 버전 경고 (D2: 실패로 막지 않는다)
    check_kernel_version();

    // 3b. API 소켓 확보 (D13: BPF 로드 전). stale 소켓 정리·중복 기동 거부·권한 설정.
    //     이후 어떤 경로로 끝나도 listener drop 시 자기 소켓만 지운다.
    if matches!(args.api_addr, ApiEndpoint::Tcp(_)) && args.api_group.is_some() {
        info!("--api-group is ignored for TCP API addresses");
    }
    let api_group = args.api_group.as_deref().unwrap_or(DEFAULT_API_GROUP);
    let listener = bind_api(&args.api_addr, api_group).await?;

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
    // config.rs 가 범위(1–10000ms, 1–4096MiB)를 먼저 검증했다
    let limits = WasmLimits {
        inspect_timeout: Duration::from_millis(cfg.wasm.execution_timeout_ms),
        memory_limit_bytes: cfg.wasm.memory_limit_mb as usize * 1024 * 1024,
    };
    let wasm = Arc::new(WasmManager::with_limits(limits));
    let server = ApiServer::new(
        map_manager.clone(),
        attach.clone(),
        telemetry.clone(),
        wasm.clone(),
    );
    let interval = Duration::from_secs(cfg.telemetry.interval.max(1));

    // 11. auto_load: bind(3b) 이후 백그라운드에서 순차 로드. 실패는 에러 로그 후 계속(데몬 유지).
    if cfg.wasm.auto_load && !cfg.wasm.auto_load_modules.is_empty() {
        spawn_auto_load(wasm, &cfg.wasm.modules_dir, &cfg.wasm.auto_load_modules);
    }

    // 12. 실행 (SIGTERM 은 systemd stop). WASM 로드 중에도 시그널 분기는 바로 선택된다.
    let result: Result<()> = tokio::select! {
        r = server.run(listener) => r.context("API server stopped"),
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

    // 13. 종료 시 detach (netlink attach 는 프로세스 종료 후에도 남는다).
    //     정상 경로에서도 명시적으로 호출하고, guard 는 남은 것이 없으면 아무것도 하지 않는다.
    drop(_detach_guard);

    if let Err(e) = &result {
        error!("데몬 비정상 종료: {:#}", e);
    }
    info!("Swift-Guard 데몬 종료");
    result
}
