//! WASM 통합 모듈
//! WebAssembly 검사 모듈 로드 및 실행 (wasmtime 호스트)
//!
//! ## 호스트-게스트 ABI (계획 문서 계약 3)
//! | 방향 | 이름 | 시그니처 | 의미 |
//! |------|------|---------|------|
//! | guest export | `memory` | Memory | 필수 (load 시 검증) |
//! | guest export | `inspect_packet` | `(i32 ptr, i32 len) -> i32` | 필수 (load 시 검증). 0=통과, ≠0=차단 |
//! | guest export | `allocate` | `(i32 size) -> i32` | 필수. 반환값 ≤0 이면 Err |
//! | guest export | `deallocate` | `(i32 ptr, i32 cap)` | 필수. 검사 후(에러 경로 포함) `deallocate(ptr, len)` 호출 |
//! | guest export | `init` | `() -> ()` | 선택. load 직후 1회 |
//! | host import | `env.log` | `(i32 ptr, i32 len) -> i32` | 0=성공, -1=잘못된 범위/UTF-8 |
//!
//! ## 실행 제한 (QA N-4)
//! - 시간: `Config::epoch_interruption` + 매니저 소유 epoch ticker 스레드(`EPOCH_TICK`마다
//!   `Engine::increment_epoch`). 게스트 호출마다 `Store::set_epoch_deadline`로 deadline을 다시 건다.
//!   인스턴스화(start 함수)+`init`은 `INIT_TIMEOUT`, `allocate`/`inspect_packet`/`deallocate`는
//!   각각 `INSPECT_TIMEOUT`. 초과 시 trap → Err. epoch 방식이라 실제 한도는 최대 1 tick 오차가 있다.
//! - 메모리: `StoreLimits`로 선형 메모리 `MEMORY_LIMIT_BYTES` 상한. 초기 크기가 넘으면 인스턴스화 실패,
//!   `memory.grow`가 넘으면 게스트에 -1 반환(trap 아님).

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wasmtime::{
    Caller, Config, Engine, Extern, Func, Instance, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, Trap, TypedFunc,
};

/// 게스트 로그 버퍼 상한(바이트). 넘으면 비운다(무한 증가 방지).
const LOG_BUFFER_CAP: usize = 64 * 1024;

/// epoch ticker 주기. 모든 deadline은 이 단위(tick)로 환산된다.
const EPOCH_TICK: Duration = Duration::from_millis(1);
/// 인스턴스화(start 함수) + 게스트 `init` 실행 시간 상한.
const INIT_TIMEOUT: Duration = Duration::from_secs(1);
/// 게스트 호출 1회(`allocate`/`inspect_packet`/`deallocate` 각각) 실행 시간 상한.
/// config `execution_timeout_ms` 기본값(10)과 같다.
const INSPECT_TIMEOUT: Duration = Duration::from_millis(10);
/// 모듈당 선형 메모리 상한. config `memory_limit_mb` 기본값(32)과 같다.
const MEMORY_LIMIT_BYTES: usize = 32 * 1024 * 1024;

/// timeout → epoch tick 수 (올림, 최소 1).
fn ticks_for(timeout: Duration) -> u64 {
    let tick = EPOCH_TICK.as_nanos().max(1);
    let n = (timeout.as_nanos() + tick - 1) / tick;
    u64::try_from(n).unwrap_or(u64::MAX).max(1)
}

/// epoch deadline 초과 trap이면 원인을 명시한 에러로 바꾼다.
fn annotate_timeout(err: anyhow::Error, what: &str, timeout: Duration) -> anyhow::Error {
    if matches!(err.downcast_ref::<Trap>(), Some(Trap::Interrupt)) {
        err.context(format!("WASM {} exceeded execution timeout of {:?}", what, timeout))
    } else {
        err
    }
}

/// WASM 모듈 상태
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Initialized/Running/Paused/Error 는 아직 전이 경로가 없음
pub enum ModuleState {
    /// 초기화됨
    Initialized,
    /// 로드됨
    Loaded,
    /// 실행 중
    Running,
    /// 일시 중지됨
    Paused,
    /// 오류 발생
    Error,
}

impl ModuleState {
    /// "initialized" | "loaded" | "running" | "paused" | "error"
    /// (common::types::WasmModuleState::to_str 와 같은 문자열)
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initialized => "initialized",
            Self::Loaded => "loaded",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Error => "error",
        }
    }
}

/// 모듈 목록 항목
#[derive(Debug, Clone)]
pub struct WasmModuleSummary {
    pub name: String,
    pub state: ModuleState,
    /// load 성공 시각, UNIX epoch 초
    pub loaded_at: u64,
}

/// 모듈 통계 스냅샷
#[derive(Debug, Clone)]
pub struct WasmModuleStatsSnapshot {
    pub name: String,
    pub processed_packets: u64,
    pub blocked_packets: u64,
    /// processed == 0 이면 0.0
    pub avg_processing_time_us: f64,
}

/// WASM 모듈 컨텍스트 데이터 (Store<T>의 T)
#[derive(Debug)]
struct WasmInspectorData {
    /// 게스트 `env.log` 메시지 누적 (상한 LOG_BUFFER_CAP)
    log_buffer: String,
    /// 선형 메모리 상한 (MEMORY_LIMIT_BYTES)
    limits: StoreLimits,
}

impl Default for WasmInspectorData {
    fn default() -> Self {
        Self {
            log_buffer: String::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(MEMORY_LIMIT_BYTES)
                .build(),
        }
    }
}

/// 로드 완료된 WASM 검사 모듈 하나.
/// 생성자(`load`)가 성공하면 필수 export가 모두 검증된 상태다.
struct WasmInspector {
    name: String,
    path: PathBuf,
    state: ModuleState,
    loaded_at: u64,
    store: Store<WasmInspectorData>,
    #[allow(dead_code)] // export 핸들은 아래 TypedFunc/Memory로 캐시됨. 인스턴스 수명 표시용
    instance: Instance,
    memory: Memory,
    inspect_fn: TypedFunc<(i32, i32), i32>,
    allocate_fn: TypedFunc<i32, i32>,
    deallocate_fn: TypedFunc<(i32, i32), ()>,
    processed_packets: u64,
    blocked_packets: u64,
    total_processing_time: Duration,
}

impl std::fmt::Debug for WasmInspector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmInspector")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("state", &self.state)
            .field("loaded_at", &self.loaded_at)
            .field("processed_packets", &self.processed_packets)
            .field("blocked_packets", &self.blocked_packets)
            .finish()
    }
}

/// `env.log` 호스트 함수 본체.
/// 음수 ptr/len, ptr+len 오버플로, 메모리 범위 밖, 잘못된 UTF-8 → -1.
fn host_log(mut caller: Caller<'_, WasmInspectorData>, ptr: i32, len: i32) -> i32 {
    if ptr < 0 || len < 0 {
        return -1;
    }
    let end = match ptr.checked_add(len) {
        Some(e) => e,
        None => return -1,
    };
    let mem = match caller.get_export("memory") {
        Some(Extern::Memory(mem)) => mem,
        _ => return -1,
    };

    // 불변 대여 구간: 메시지를 소유 String으로 복사한 뒤 대여를 끝낸다 (E0502 해소)
    let message: String = {
        let bytes = match mem.data(&caller).get(ptr as usize..end as usize) {
            Some(b) => b,
            None => return -1,
        };
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => return -1,
        }
    };

    info!("[WASM] {}", message);

    let buf = &mut caller.data_mut().log_buffer;
    if buf.len() + message.len() + 1 > LOG_BUFFER_CAP {
        buf.clear();
    }
    buf.push_str(&message);
    buf.push('\n');
    0
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl WasmInspector {
    /// 파일을 읽고 컴파일·인스턴스화하고 필수 export를 검증한다.
    fn load(engine: &Engine, name: &str, path: &Path) -> Result<Self> {
        debug!("Loading WASM module '{}': {}", name, path.display());

        let wasm_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read WASM file: {}", path.display()))?;

        let module = Module::new(engine, &wasm_bytes)
            .with_context(|| format!("Failed to compile WASM module: {}", path.display()))?;

        let mut store = Store::new(engine, WasmInspectorData::default());
        store.limiter(|data| &mut data.limits);
        store.epoch_deadline_trap();
        // start 함수와 init을 합쳐 INIT_TIMEOUT 안에 끝나야 한다.
        store.set_epoch_deadline(ticks_for(INIT_TIMEOUT));

        let log_func = Func::wrap(&mut store, host_log);
        let mut linker: Linker<WasmInspectorData> = Linker::new(engine);
        linker
            .define(&mut store, "env", "log", log_func)
            .context("Failed to define host function: env.log")?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| annotate_timeout(e, "start function", INIT_TIMEOUT))
            .context("Failed to instantiate WASM module")?;

        // 필수 export 검증 (이름 + 시그니처)
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("WASM module is missing required export: memory"))?;
        let inspect_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "inspect_packet")
            .context("WASM module is missing required export: inspect_packet (i32, i32) -> i32")?;
        let allocate_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "allocate")
            .context("WASM module is missing required export: allocate (i32) -> i32")?;
        let deallocate_fn = instance
            .get_typed_func::<(i32, i32), ()>(&mut store, "deallocate")
            .context("WASM module is missing required export: deallocate (i32, i32)")?;

        // 선택 export: init
        if let Ok(init_func) = instance.get_typed_func::<(), ()>(&mut store, "init") {
            init_func
                .call(&mut store, ())
                .map_err(|e| annotate_timeout(e, "init", INIT_TIMEOUT))
                .context("Failed to call init function")?;
            debug!("WASM module '{}' initialized", name);
        }

        info!("WASM module loaded: {} ({})", name, path.display());

        Ok(Self {
            name: name.to_string(),
            path: path.to_path_buf(),
            state: ModuleState::Loaded,
            loaded_at: unix_now_secs(),
            store,
            instance,
            memory,
            inspect_fn,
            allocate_fn,
            deallocate_fn,
            processed_packets: 0,
            blocked_packets: 0,
            total_processing_time: Duration::ZERO,
        })
    }

    fn is_active(&self) -> bool {
        matches!(self.state, ModuleState::Loaded | ModuleState::Running)
    }

    /// 패킷 1개 검사. Ok(true)=차단, Ok(false)=통과.
    fn inspect_packet(&mut self, packet: &[u8]) -> Result<bool> {
        if !self.is_active() {
            bail!("WASM module '{}' is not loaded", self.name);
        }
        // 길이 0: 게스트 호출 없이 통과 (allocate(0) 회피)
        if packet.is_empty() {
            return Ok(false);
        }
        let len: i32 = i32::try_from(packet.len())
            .map_err(|_| anyhow!("packet too large for WASM ABI: {} bytes", packet.len()))?;

        let started = Instant::now();
        let store = &mut self.store;

        let inspect_ticks = ticks_for(INSPECT_TIMEOUT);

        store.set_epoch_deadline(inspect_ticks);
        let ptr = self
            .allocate_fn
            .call(&mut *store, len)
            .map_err(|e| annotate_timeout(e, "allocate", INSPECT_TIMEOUT))
            .context("Failed to allocate memory in WASM")?;
        if ptr <= 0 {
            bail!("WASM allocate({}) returned invalid pointer {}", len, ptr);
        }

        // allocate 성공 이후 구간: 성공/실패와 무관하게 deallocate 호출
        let memory = self.memory;
        let inspect_fn = &self.inspect_fn;
        let result: Result<i32> = (|| {
            memory
                .write(&mut *store, ptr as usize, packet)
                .context("Failed to write packet data to WASM memory")?;
            store.set_epoch_deadline(inspect_ticks);
            inspect_fn
                .call(&mut *store, (ptr, len))
                .map_err(|e| annotate_timeout(e, "inspect_packet", INSPECT_TIMEOUT))
                .context("Failed to call inspect_packet function")
        })();

        // inspect가 timeout으로 끝났어도 deallocate에는 새 deadline을 준다.
        store.set_epoch_deadline(inspect_ticks);
        let dealloc = self
            .deallocate_fn
            .call(&mut *store, (ptr, len))
            .map_err(|e| annotate_timeout(e, "deallocate", INSPECT_TIMEOUT))
            .context("Failed to call deallocate function");

        let verdict = result?;
        if let Err(e) = dealloc {
            warn!("WASM module '{}': {:#}", self.name, e);
            return Err(e);
        }

        self.processed_packets += 1;
        self.total_processing_time += started.elapsed();

        // 결과 해석 (≠0 = 차단, 0 = 통과)
        if verdict != 0 {
            self.blocked_packets += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn summary(&self) -> WasmModuleSummary {
        WasmModuleSummary {
            name: self.name.clone(),
            state: self.state,
            loaded_at: self.loaded_at,
        }
    }

    fn stats_snapshot(&self) -> WasmModuleStatsSnapshot {
        let avg = if self.processed_packets == 0 {
            0.0
        } else {
            self.total_processing_time.as_secs_f64() * 1_000_000.0 / self.processed_packets as f64
        };
        WasmModuleStatsSnapshot {
            name: self.name.clone(),
            processed_packets: self.processed_packets,
            blocked_packets: self.blocked_packets,
            avg_processing_time_us: avg,
        }
    }
}

/// WASM 검사 모듈 관리자. `Arc<WasmManager>`로 공유한다 (Send + Sync, 'static).
pub struct WasmManager {
    engine: Engine,
    /// 로드 순서대로 보관
    inspectors: Mutex<Vec<WasmInspector>>,
    /// epoch ticker 종료 신호. drop(=송신측 닫힘) 시 ticker가 끝난다.
    ticker_stop: Option<Sender<()>>,
    ticker: Option<JoinHandle<()>>,
}

// wasmtime::Engine 은 Debug 미구현이라 수동 구현
impl std::fmt::Debug for WasmManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmManager")
            .field("inspectors", &self.inspectors)
            .finish_non_exhaustive()
    }
}

// WasmManager는 스레드 간 공유되므로 Send + Sync를 컴파일 타임에 고정한다.
const _: () = {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    #[allow(dead_code)]
    fn check() {
        assert_send_sync::<WasmManager>();
    }
};

impl WasmManager {
    /// 새로운 WASM 관리자 생성
    pub fn new() -> Self {
        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine = Engine::new(&config).unwrap_or_else(|e| {
            // 기본 설정 + epoch 플래그만 켠 Config라 실패는 사실상 없다.
            warn!("WASM engine with epoch interruption failed ({:#}); falling back to default engine (no timeout)", e);
            Engine::default()
        });

        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let tick_engine = engine.clone();
        let ticker = std::thread::Builder::new()
            .name("sg-wasm-epoch".into())
            .spawn(move || loop {
                match stop_rx.recv_timeout(EPOCH_TICK) {
                    Err(RecvTimeoutError::Timeout) => tick_engine.increment_epoch(),
                    // 송신측 drop 또는 명시적 신호 → 종료
                    _ => break,
                }
            });
        let (ticker_stop, ticker) = match ticker {
            Ok(h) => (Some(stop_tx), Some(h)),
            Err(e) => {
                // ticker 없이 epoch가 멈추면 deadline이 오지 않아 무한 루프를 못 끊는다(기존 동작과 동일).
                warn!("Failed to spawn WASM epoch ticker: {}; guest execution timeout disabled", e);
                (None, None)
            }
        };

        Self {
            engine,
            inspectors: Mutex::new(Vec::new()),
            ticker_stop,
            ticker,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<WasmInspector>>> {
        self.inspectors
            .lock()
            .map_err(|_| anyhow!("Failed to lock WASM inspectors (poisoned)"))
    }

    /// name 중복 → Err, 파일 없음/컴파일/인스턴스화 실패 → Err,
    /// export memory/inspect_packet/allocate/deallocate 중 하나라도 없음 → Err.
    pub fn load_module(&self, name: &str, path: &Path) -> Result<()> {
        if name.is_empty() {
            bail!("WASM module name must not be empty");
        }
        // 빠른 중복 검사 (컴파일 비용 회피). 컴파일은 잠금 밖에서 한다.
        if self.lock()?.iter().any(|i| i.name == name) {
            bail!("WASM module '{}' is already loaded", name);
        }

        let inspector = WasmInspector::load(&self.engine, name, path)?;

        // 컴파일 중 다른 호출이 같은 이름을 넣었을 수 있으므로 재검사
        let mut inspectors = self.lock()?;
        if inspectors.iter().any(|i| i.name == name) {
            bail!("WASM module '{}' is already loaded", name);
        }
        inspectors.push(inspector);
        Ok(())
    }

    /// 있으면 제거 후 Ok(true), 없으면 Ok(false).
    pub fn unload_module(&self, name: &str) -> Result<bool> {
        let mut inspectors = self.lock()?;
        match inspectors.iter().position(|i| i.name == name) {
            Some(idx) => {
                inspectors.remove(idx);
                info!("WASM module unloaded: {}", name);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// 로드 순서대로.
    pub fn list_modules(&self) -> Result<Vec<WasmModuleSummary>> {
        Ok(self.lock()?.iter().map(WasmInspector::summary).collect())
    }

    /// 없으면 Ok(None).
    pub fn module_stats(&self, name: &str) -> Result<Option<WasmModuleStatsSnapshot>> {
        Ok(self
            .lock()?
            .iter()
            .find(|i| i.name == name)
            .map(WasmInspector::stats_snapshot))
    }

    /// 데이터 경로용(이번 라운드에서 호출하지 않음).
    /// 활성 모듈을 로드 순서대로 실행하고, 하나라도 차단하면 Ok(true).
    #[allow(dead_code)]
    pub fn inspect_packet(&self, packet: &[u8]) -> Result<bool> {
        let mut inspectors = self.lock()?;
        for inspector in inspectors.iter_mut() {
            if inspector.is_active() && inspector.inspect_packet(packet)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Default for WasmManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WasmManager {
    fn drop(&mut self) {
        // 송신측을 닫으면 ticker의 recv_timeout이 Disconnected로 즉시 깨어난다.
        drop(self.ticker_stop.take());
        if let Some(h) = self.ticker.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 최소 게스트: bump allocator, deallocate 호출 횟수 기록(global 1),
    /// 첫 바이트가 0xFF면 차단.
    const GOOD_WAT: &str = r#"
        (module
          (import "env" "log" (func $log (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 4096))
          (global $deallocs (export "deallocs") (mut i32) (i32.const 0))
          (data (i32.const 16) "hello")
          (func (export "init") (drop (call $log (i32.const 16) (i32.const 5))))
          (func (export "allocate") (param $n i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $n)))
            (local.get $p))
          (func (export "deallocate") (param i32 i32)
            (global.set $deallocs (i32.add (global.get $deallocs) (i32.const 1))))
          (func (export "inspect_packet") (param $p i32) (param $l i32) (result i32)
            (i32.eq (i32.load8_u (local.get $p)) (i32.const 255))))
    "#;

    const NO_DEALLOC_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "allocate") (param i32) (result i32) (i32.const 1024))
          (func (export "inspect_packet") (param i32 i32) (result i32) (i32.const 0)))
    "#;

    const BAD_LOG_WAT: &str = r#"
        (module
          (import "env" "log" (func $log (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (global $r (export "r") (mut i32) (i32.const 0))
          (func (export "init")
            ;; ptr+len 오버플로, 음수, 범위 밖 → 모두 -1 이어야 함. 합계를 r에 저장
            (global.set $r
              (i32.add
                (i32.add (call $log (i32.const 2147483647) (i32.const 10))
                         (call $log (i32.const -1) (i32.const 1)))
                (call $log (i32.const 65530) (i32.const 100)))))
          (func (export "allocate") (param i32) (result i32) (i32.const 1024))
          (func (export "deallocate") (param i32 i32))
          (func (export "inspect_packet") (param i32 i32) (result i32) (i32.const 0)))
    "#;

    /// init이 무한 루프.
    const LOOP_INIT_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "init") (loop $l (br $l)))
          (func (export "allocate") (param i32) (result i32) (i32.const 1024))
          (func (export "deallocate") (param i32 i32))
          (func (export "inspect_packet") (param i32 i32) (result i32) (i32.const 0)))
    "#;

    /// 첫 바이트가 0xEE면 inspect_packet이 무한 루프, 아니면 통과. deallocate 횟수 기록.
    const LOOP_INSPECT_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $deallocs (export "deallocs") (mut i32) (i32.const 0))
          (func (export "allocate") (param i32) (result i32) (i32.const 1024))
          (func (export "deallocate") (param i32 i32)
            (global.set $deallocs (i32.add (global.get $deallocs) (i32.const 1))))
          (func (export "inspect_packet") (param $p i32) (param $l i32) (result i32)
            (if (i32.eq (i32.load8_u (local.get $p)) (i32.const 238))
              (then (loop $l (br $l))))
            (i32.const 0)))
    "#;

    /// 초기 메모리 64MB (1024 pages) > MEMORY_LIMIT_BYTES.
    const BIG_MEMORY_WAT: &str = r#"
        (module
          (memory (export "memory") 1024)
          (func (export "allocate") (param i32) (result i32) (i32.const 1024))
          (func (export "deallocate") (param i32 i32))
          (func (export "inspect_packet") (param i32 i32) (result i32) (i32.const 0)))
    "#;

    /// memory.grow로 상한을 넘기려 하면 -1. 결과를 global r에 저장.
    const GROW_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $r (export "r") (mut i32) (i32.const 0))
          (func (export "init") (global.set $r (memory.grow (i32.const 1024))))
          (func (export "allocate") (param i32) (result i32) (i32.const 1024))
          (func (export "deallocate") (param i32 i32))
          (func (export "inspect_packet") (param i32 i32) (result i32) (i32.const 0)))
    "#;

    fn write_tmp(tag: &str, wat: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sg_wasm_test_{}_{}_{}.wat",
            tag,
            std::process::id(),
            unix_now_secs()
        ));
        std::fs::write(&p, wat).unwrap();
        p
    }

    #[test]
    fn load_list_stats_unload() {
        let m = WasmManager::new();
        let p = write_tmp("good", GOOD_WAT);
        m.load_module("good", &p).unwrap();
        assert!(m.load_module("good", &p).is_err(), "duplicate name must be rejected");

        let list = m.list_modules().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "good");
        assert_eq!(list[0].state.as_str(), "loaded");
        assert!(list[0].loaded_at > 0);

        let s = m.module_stats("good").unwrap().unwrap();
        assert_eq!((s.processed_packets, s.blocked_packets), (0, 0));
        assert_eq!(s.avg_processing_time_us, 0.0);

        assert!(!m.inspect_packet(&[0x00, 0x01]).unwrap());
        assert!(m.inspect_packet(&[0xFF, 0x01]).unwrap());
        assert!(!m.inspect_packet(&[]).unwrap()); // 게스트 호출 없음

        let s = m.module_stats("good").unwrap().unwrap();
        assert_eq!((s.processed_packets, s.blocked_packets), (2, 1));

        // deallocate가 패킷마다 호출되었는지 (빈 패킷 제외 2회)
        {
            let mut g = m.lock().unwrap();
            let insp = &mut g[0];
            let inst = insp.instance;
            let d = inst
                .get_global(&mut insp.store, "deallocs")
                .unwrap()
                .get(&mut insp.store)
                .i32()
                .unwrap();
            assert_eq!(d, 2);
            assert!(insp.store.data().log_buffer.contains("hello"));
        }

        assert!(m.module_stats("nope").unwrap().is_none());
        assert!(m.unload_module("good").unwrap());
        assert!(!m.unload_module("good").unwrap());
        assert!(m.list_modules().unwrap().is_empty());
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn missing_export_rejected() {
        let m = WasmManager::new();
        let p = write_tmp("nodealloc", NO_DEALLOC_WAT);
        let err = m.load_module("x", &p).unwrap_err();
        assert!(format!("{:#}", err).contains("deallocate"), "{:#}", err);
        assert!(m.list_modules().unwrap().is_empty());
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn missing_file_rejected() {
        let m = WasmManager::new();
        assert!(m
            .load_module("x", Path::new("/nonexistent/sg_wasm_test.wasm"))
            .is_err());
    }

    #[test]
    fn host_log_rejects_bad_ranges() {
        let m = WasmManager::new();
        let p = write_tmp("badlog", BAD_LOG_WAT);
        m.load_module("b", &p).unwrap();
        let mut g = m.lock().unwrap();
        let insp = &mut g[0];
        let inst = insp.instance;
        let r = inst
            .get_global(&mut insp.store, "r")
            .unwrap()
            .get(&mut insp.store)
            .i32()
            .unwrap();
        assert_eq!(r, -3);
        drop(g);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn infinite_init_times_out_and_is_not_registered() {
        let m = WasmManager::new();
        let p = write_tmp("loopinit", LOOP_INIT_WAT);
        let started = Instant::now();
        let err = m.load_module("li", &p).unwrap_err();
        let elapsed = started.elapsed();
        let msg = format!("{:#}", err);
        assert!(msg.contains("timeout"), "{}", msg);
        assert!(elapsed < INIT_TIMEOUT * 5, "took {:?}", elapsed);
        assert!(m.list_modules().unwrap().is_empty());
        // 같은 이름으로 정상 모듈을 다시 로드할 수 있어야 한다(등록 안 됨)
        let good = write_tmp("good2", GOOD_WAT);
        m.load_module("li", &good).unwrap();
        assert!(!m.inspect_packet(&[0x00]).unwrap());
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(good);
    }

    #[test]
    fn infinite_inspect_times_out_and_module_stays_consistent() {
        let m = WasmManager::new();
        let p = write_tmp("loopinsp", LOOP_INSPECT_WAT);
        m.load_module("lp", &p).unwrap();

        let started = Instant::now();
        let err = m.inspect_packet(&[0xEE, 0x00]).unwrap_err();
        let elapsed = started.elapsed();
        let msg = format!("{:#}", err);
        assert!(msg.contains("timeout"), "{}", msg);
        assert!(elapsed < Duration::from_secs(1), "took {:?}", elapsed);

        // 실패한 검사는 통계에 들어가지 않고, 모듈은 계속 사용 가능
        let s = m.module_stats("lp").unwrap().unwrap();
        assert_eq!((s.processed_packets, s.blocked_packets), (0, 0));
        assert_eq!(m.list_modules().unwrap()[0].state.as_str(), "loaded");
        assert!(!m.inspect_packet(&[0x01, 0x00]).unwrap());
        let s = m.module_stats("lp").unwrap().unwrap();
        assert_eq!(s.processed_packets, 1);

        // timeout 경로에서도 deallocate가 호출됨 (2회: timeout 1 + 정상 1)
        let mut g = m.lock().unwrap();
        let insp = &mut g[0];
        let inst = insp.instance;
        let d = inst
            .get_global(&mut insp.store, "deallocs")
            .unwrap()
            .get(&mut insp.store)
            .i32()
            .unwrap();
        assert_eq!(d, 2);
        drop(g);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn memory_limit_enforced() {
        let m = WasmManager::new();
        let p = write_tmp("bigmem", BIG_MEMORY_WAT);
        assert!(m.load_module("big", &p).is_err());
        assert!(m.list_modules().unwrap().is_empty());

        let g = write_tmp("grow", GROW_WAT);
        m.load_module("grow", &g).unwrap();
        let mut guard = m.lock().unwrap();
        let insp = &mut guard[0];
        let inst = insp.instance;
        let r = inst
            .get_global(&mut insp.store, "r")
            .unwrap()
            .get(&mut insp.store)
            .i32()
            .unwrap();
        assert_eq!(r, -1, "memory.grow beyond limit must fail");
        drop(guard);
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(g);
    }

    #[test]
    fn ticks_rounding() {
        assert_eq!(ticks_for(Duration::ZERO), 1);
        assert_eq!(ticks_for(INSPECT_TIMEOUT), 10);
        assert_eq!(ticks_for(INIT_TIMEOUT), 1000);
        assert_eq!(ticks_for(Duration::from_micros(1500)), 2);
    }
}
