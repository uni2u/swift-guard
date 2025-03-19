//! 구성 모듈
//! 데몬 구성 로드 및 관리

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// 데몬 구성
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    /// 일반 구성
    pub general: GeneralConfig,
    /// 텔레메트리 구성
    pub telemetry: TelemetryConfig,
    /// WASM 구성
    pub wasm: WasmConfig,
}

/// 일반 구성
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeneralConfig {
    /// 로그 수준
    pub log_level: String,
    /// 작업 디렉토리
    pub work_dir: String,
    /// PID 파일 경로
    pub pid_file: String,
}

/// 텔레메트리 구성
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// 통계 로깅 활성화
    pub log_stats: bool,
    /// 통계 수집 간격 (초)
    pub interval: u64,
    /// 텔레메트리 내보내기 활성화
    pub export_enabled: bool,
    /// 내보내기 URL
    pub export_url: Option<String>,
}

/// WASM 구성
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WasmConfig {
    /// WASM 모듈 디렉토리
    pub modules_dir: String,
    /// 자동 로드 활성화
    pub auto_load: bool,
    /// 자동 로드 모듈 목록
    pub auto_load_modules: Vec<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                log_level: "info".to_string(),
                work_dir: "/var/lib/swift-guard".to_string(),
                pid_file: "/var/run/swift-guard.pid".to_string(),
            },
            telemetry: TelemetryConfig {
                log_stats: true,
                interval: 10,
                export_enabled: false,
                export_url: None,
            },
            wasm: WasmConfig {
                modules_dir: "/usr/local/lib/swift-guard/wasm".to_string(),
                auto_load: false,
                auto_load_modules: Vec::new(),
            },
        }
    }
}

/// 구성 파일 로드
pub fn load_config(path: &Path) -> Result<DaemonConfig> {
    // 파일이 없는 경우 기본 구성 반환
    if !path.exists() {
        warn!("Config file not found at {}, using default config", path.display());
        return Ok(DaemonConfig::default());
    }
    
    // 파일 읽기
    let mut file = File::open(path)
        .context(format!("Failed to open config file: {}", path.display()))?;
    
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .context("Failed to read config file")?;
    
    // YAML 파싱
    let config: DaemonConfig = serde_yaml::from_str(&contents)
        .context("Failed to parse config YAML")?;
    
    info!("Config loaded from {}", path.display());
    
    Ok(config)
}

/// 구성 파일 저장
pub fn save_config(config: &DaemonConfig, path: &Path) -> Result<()> {
    // YAML 직렬화
    let yaml = serde_yaml::to_string(config)
        .context("Failed to serialize config to YAML")?;
    
    // 디렉토리 생성
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .context(format!("Failed to create directory: {}", parent.display()))?;
    }
    
    // 파일 쓰기
    std::fs::write(path, yaml)
        .context(format!("Failed to write config file: {}", path.display()))?;
    
    info!("Config saved to {}", path.display());
    
    Ok(())
}

/// 구성 예시 생성
pub fn create_example_config() -> DaemonConfig {
    let mut config = DaemonConfig::default();
    
    config.wasm.auto_load = true;
    config.wasm.auto_load_modules = vec![
        "http_inspector.wasm".to_string(),
        "ddos_detector.wasm".to_string(),
    ];
    
    config
}
