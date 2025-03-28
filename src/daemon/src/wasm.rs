//! WASM 통합 모듈
//! WebAssembly 검사 모듈 로드 및 실행

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wasmtime::*;

/// WASM 모듈 상태
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// WASM 검사 모듈
//#[derive(Debug)]
pub struct WasmInspector {
    /// 모듈 ID
    id: String,
    /// 모듈 경로
    path: PathBuf,
    /// 상태
    state: ModuleState,
    /// wasmtime 엔진
    engine: Engine,
    /// wasmtime 스토어
    store: Option<Store<WasmInspectorData>>,
    /// wasmtime 인스턴스
    instance: Option<Instance>,
    /// 처리된 패킷 수
    processed_packets: u64,
    /// 차단된 패킷 수
    blocked_packets: u64,
}

/// WASM 모듈 컨텍스트 데이터
#[derive(Debug)]
pub struct WasmInspectorData {
    /// 메모리 버퍼
    memory_buffer: Vec<u8>,
    /// 패킷 데이터
    packet_data: Vec<u8>,
    /// 패킷 길이
    packet_len: usize,
    /// 결과 버퍼
    result_buffer: Vec<u8>,
    /// 로그 버퍼
    log_buffer: String,
}

// Debug 구현
impl std::fmt::Debug for WasmInspector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmInspector")
            .field("id", &self.id)
            .field("path", &self.path)
            .field("state", &self.state)
            .field("processed_packets", &self.processed_packets)
            .field("blocked_packets", &self.blocked_packets)
            .finish()
    }
}

impl WasmInspector {
    /// 새로운 WASM 검사 모듈 생성
    pub fn new(id: &str, path: &Path) -> Result<Self> {
        let engine = Engine::default();
        
        Ok(Self {
            id: id.to_string(),
            path: path.to_path_buf(),
            state: ModuleState::Initialized,
            engine,
            store: None,
            instance: None,
            processed_packets: 0,
            blocked_packets: 0,
        })
    }
    
    /// 모듈 로드
    pub fn load(&mut self) -> Result<()> {
        debug!("Loading WASM module: {}", self.path.display());
        
        // WASM 파일 읽기
        let mut file = File::open(&self.path)
            .context(format!("Failed to open WASM file: {}", self.path.display()))?;
        
        let mut wasm_bytes = Vec::new();
        file.read_to_end(&mut wasm_bytes)
            .context("Failed to read WASM file")?;
        
        // 모듈 및 인스턴스 생성
        let module = Module::new(&self.engine, wasm_bytes)
            .context("Failed to compile WASM module")?;
        
        let mut store = Store::new(
            &self.engine,
            WasmInspectorData {
                memory_buffer: Vec::new(),
                packet_data: Vec::new(),
                packet_len: 0,
                result_buffer: Vec::new(),
                log_buffer: String::new(),
            },
        );
        
        // WASM에 노출할 호스트 함수 정의
        let log_func = Func::wrap(&mut store, |caller: Caller<'_, WasmInspectorData>, ptr: i32, len: i32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => return -1,
            };
            
            let data = match mem.data(&caller).get(ptr as usize..(ptr + len) as usize) {
                Some(data) => data,
                None => return -1,
            };
            
            let message = match std::str::from_utf8(data) {
                Ok(s) => s,
                Err(_) => return -1,
            };
            
            info!("[WASM] {}", message);
            
            caller.data_mut().log_buffer.push_str(message);
            caller.data_mut().log_buffer.push('\n');
            
            0
        });
        
        // WASM 인스턴스 생성 및 링커 설정
        let mut linker = Linker::new(&self.engine);
//        linker.define("env", "log", log_func)
        linker.define(&mut store, "env", "log", log_func)
            .context("Failed to define host function: log")?;
        
        let instance = linker.instantiate(&mut store, &module)
            .context("Failed to instantiate WASM module")?;
        
        // 메모리 획득
        let memory = instance
//            .get_memory(&mut store, "memory")
            .get_memory(store, "memory")
            .ok_or_else(|| anyhow!("WASM module has no exported memory"))?;
        
        // 초기화 함수 호출 (있는 경우)
        if let Ok(init_func) = instance.get_typed_func::<(), ()>(&mut store, "init") {
            init_func.call(&mut store, ())
                .context("Failed to call init function")?;
            debug!("WASM module initialized");
        }
        
        self.store = Some(store);
        self.instance = Some(instance);
        self.state = ModuleState::Loaded;
        
        info!("WASM module loaded: {}", self.id);
        Ok(())
    }
    
    /// 패킷 검사
    pub fn inspect_packet(&mut self, packet: &[u8]) -> Result<bool> {
        if self.state != ModuleState::Loaded && self.state != ModuleState::Running {
            return Err(anyhow!("WASM module not loaded"));
        }
        
        let store = self.store.as_mut()
            .ok_or_else(|| anyhow!("WASM store not initialized"))?;
        
        let instance = self.instance.as_ref()
            .ok_or_else(|| anyhow!("WASM instance not initialized"))?;
        
        // 메모리 획득
        let memory = instance
//            .get_memory(store, "memory")
            .get_memory(store, "memory")
            .ok_or_else(|| anyhow!("WASM module has no exported memory"))?;
            
        // 검사 함수 획득
        let inspect_func = instance
            .get_typed_func::<(i32, i32), i32>(store, "inspect_packet")
            .context("WASM module has no inspect_packet function")?;
        
        // 패킷 데이터를 WASM 메모리에 복사
        store.data_mut().packet_data = packet.to_vec();
        store.data_mut().packet_len = packet.len();
        
        // 메모리 할당 (필요한 경우)
        let alloc_func = instance.get_typed_func::<i32, i32>(store, "allocate");
        let ptr = if let Ok(alloc) = alloc_func {
            alloc.call(store, packet.len() as i32)
                .context("Failed to allocate memory in WASM")?
        } else {
            // 할당 함수가 없는 경우 고정 오프셋 사용
            1024
        };
        
        // 패킷 데이터 복사
        memory.write(store, ptr as usize, packet)
            .context("Failed to write packet data to WASM memory")?;
        
        // 검사 함수 호출
        let result = inspect_func.call(store, (ptr, packet.len() as i32))
            .context("Failed to call inspect_packet function")?;
        
        self.processed_packets += 1;
        
        // 결과 해석 (1 = 차단, 0 = 통과)
        if result != 0 {
            self.blocked_packets += 1;
            Ok(true) // 차단
        } else {
            Ok(false) // 통과
        }
    }
    
    /// 상태 획득
    pub fn state(&self) -> ModuleState {
        self.state
    }
    
    /// 통계 획득
    pub fn stats(&self) -> (u64, u64) {
        (self.processed_packets, self.blocked_packets)
    }
    
    /// 모듈 ID 획득
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// WASM 검사 모듈 관리자
#[derive(Debug)]
pub struct WasmManager {
    /// 로드된 검사 모듈
    inspectors: Arc<Mutex<Vec<WasmInspector>>>,
}

impl WasmManager {
    /// 새로운 WASM 관리자 생성
    pub fn new() -> Self {
        Self {
            inspectors: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    /// 모듈 로드
    pub fn load_module(&self, id: &str, path: &Path) -> Result<()> {
        let mut inspector = WasmInspector::new(id, path)?;
        inspector.load()?;
        
        let mut inspectors = self.inspectors.lock()
            .map_err(|_| anyhow!("Failed to lock inspectors"))?;
        
        inspectors.push(inspector);
        
        Ok(())
    }
    
    /// 패킷 검사 (모든 모듈)
    pub fn inspect_packet(&self, packet: &[u8]) -> Result<bool> {
        let mut inspectors = self.inspectors.lock()
            .map_err(|_| anyhow!("Failed to lock inspectors"))?;
        
        for inspector in inspectors.iter_mut() {
            if inspector.state() == ModuleState::Loaded || inspector.state() == ModuleState::Running {
                if inspector.inspect_packet(packet)? {
                    return Ok(true); // 하나라도 차단하면 차단으로 처리
                }
            }
        }
        
        Ok(false) // 모든 모듈이 통과하면 통과로 처리
    }
    
    /// 모듈 목록 획득
    pub fn list_modules(&self) -> Result<Vec<(String, ModuleState, u64, u64)>> {
        let inspectors = self.inspectors.lock()
            .map_err(|_| anyhow!("Failed to lock inspectors"))?;
        
        let mut result = Vec::new();
        for inspector in inspectors.iter() {
            let (processed, blocked) = inspector.stats();
            result.push((
                inspector.id().to_string(),
                inspector.state(),
                processed,
                blocked,
            ));
        }
        
        Ok(result)
    }
}

impl Default for WasmManager {
    fn default() -> Self {
        Self::new()
    }
}
