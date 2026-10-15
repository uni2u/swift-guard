//! 구성 모듈
//! 데몬 구성(YAML) 로드와 검증.
//!
//! - 모든 키는 선택이다. 빠진 키는 기본값을 쓴다(`#[serde(default)]`).
//! - 모르는 키·삭제된 키는 **경고 후 무시**한다(`deny_unknown_fields` 를 쓰지 않음).
//!   `make install-conf` 는 기존 `/etc/swift-guard/config.yaml` 을 덮어쓰지 않으므로,
//!   거부하면 업그레이드한 기존 설치가 기동에 실패한다.
//! - 로거는 설정을 읽은 뒤에 초기화되므로(`general.log_level` 적용) 이 모듈은 로그를 직접 남기지 않고
//!   경고·안내 문구를 `LoadedConfig` 에 모아 돌려준다. main 이 로거 초기화 후 출력한다.

use anyhow::{anyhow, Context, Result};
use log::LevelFilter;
use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::path::{Path, PathBuf};

/// 허용 log_level 값 (env_logger LevelFilter 이름)
pub const LOG_LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];
/// wasm.execution_timeout_ms 허용 범위
pub const EXEC_TIMEOUT_RANGE: std::ops::RangeInclusive<u64> = 1..=10_000;
/// wasm.memory_limit_mb 허용 범위
pub const MEMORY_LIMIT_RANGE: std::ops::RangeInclusive<u64> = 1..=4096;

/// 섹션별 알려진 키
const KNOWN_KEYS: [(&str, &[&str]); 3] = [
    ("general", &["log_level"]),
    ("telemetry", &["log_stats", "interval"]),
    (
        "wasm",
        &[
            "modules_dir",
            "auto_load",
            "auto_load_modules",
            "execution_timeout_ms",
            "memory_limit_mb",
        ],
    ),
];

/// 예전 템플릿에 있었으나 삭제된 키 (점 경로)
const REMOVED_KEYS: [&str; 6] = [
    "general.work_dir",
    "general.pid_file",
    "telemetry.export_enabled",
    "telemetry.export_url",
    "interfaces",
    "rules",
];

/// 데몬 구성
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    /// 일반 구성
    pub general: GeneralConfig,
    /// 텔레메트리 구성
    pub telemetry: TelemetryConfig,
    /// WASM 구성
    pub wasm: WasmConfig,
}

/// 일반 구성
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// 로그 수준 (off, error, warn, info, debug, trace).
    /// 우선순위: `-v` > `RUST_LOG` > 이 값 > info
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
        }
    }
}

/// 텔레메트리 구성
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// 주기 통계 로그 출력
    pub log_stats: bool,
    /// 통계 수집 간격 (초, 0 은 1 로 취급)
    pub interval: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_stats: true,
            interval: 10,
        }
    }
}

/// WASM 구성
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WasmConfig {
    /// auto_load_modules 의 상대경로 기준 디렉토리
    pub modules_dir: String,
    /// 기동 시 auto_load_modules 로드
    pub auto_load: bool,
    /// 자동 로드할 모듈 (.wasm 파일. 절대경로 또는 modules_dir 기준 상대경로)
    pub auto_load_modules: Vec<String>,
    /// 게스트 호출(allocate/inspect_packet/deallocate) 시간 상한 (ms, 1–10000)
    pub execution_timeout_ms: u64,
    /// 모듈당 선형 메모리 상한 (MiB, 1–4096)
    pub memory_limit_mb: u64,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            modules_dir: "/usr/local/lib/swift-guard/wasm".to_string(),
            auto_load: false,
            auto_load_modules: Vec::new(),
            execution_timeout_ms: 10,
            memory_limit_mb: 32,
        }
    }
}

/// 로드 결과. 경고(warn)·안내(info)는 로거 초기화 후 main 이 출력한다.
#[derive(Debug)]
pub struct LoadedConfig {
    pub config: DaemonConfig,
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
}

fn key_name(k: &Value) -> String {
    match k {
        Value::String(s) => s.clone(),
        other => serde_yaml::to_string(other)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| format!("{:?}", other)),
    }
}

fn key_warning(path: &str) -> String {
    if REMOVED_KEYS.contains(&path) {
        format!("config key '{}' is no longer supported and is ignored", path)
    } else {
        format!("unknown config key '{}' is ignored", path)
    }
}

/// 알려진 키 트리와 비교해 경고를 모으고, null 섹션(`general:` 처럼 값이 빈 것)은 빈 매핑으로 바꾼다.
fn check_keys(root: &mut Mapping, warnings: &mut Vec<String>) {
    for (k, v) in root.iter_mut() {
        let section = key_name(k);
        let Some((_, known)) = KNOWN_KEYS.iter().find(|(s, _)| *s == section) else {
            warnings.push(key_warning(&section));
            continue;
        };
        if v.is_null() {
            *v = Value::Mapping(Mapping::new());
        }
        if let Value::Mapping(m) = v {
            for sk in m.keys() {
                let sub = key_name(sk);
                if !known.contains(&sub.as_str()) {
                    warnings.push(key_warning(&format!("{}.{}", section, sub)));
                }
            }
        }
        // 매핑이 아니면 from_value 가 타입 오류를 낸다
    }
}

/// 값 검증 (기동 에러). log_level 은 소문자로 정규화한다.
fn validate(cfg: &mut DaemonConfig, warnings: &mut Vec<String>) -> Result<()> {
    let level = cfg.general.log_level.trim().to_ascii_lowercase();
    if !LOG_LEVELS.contains(&level.as_str()) {
        return Err(anyhow!(
            "invalid general.log_level '{}' (expected one of: {})",
            cfg.general.log_level,
            LOG_LEVELS.join(", ")
        ));
    }
    cfg.general.log_level = level;

    let t = cfg.wasm.execution_timeout_ms;
    if !EXEC_TIMEOUT_RANGE.contains(&t) {
        return Err(anyhow!(
            "wasm.execution_timeout_ms must be between {} and {} (got {})",
            EXEC_TIMEOUT_RANGE.start(),
            EXEC_TIMEOUT_RANGE.end(),
            t
        ));
    }
    let m = cfg.wasm.memory_limit_mb;
    if !MEMORY_LIMIT_RANGE.contains(&m) {
        return Err(anyhow!(
            "wasm.memory_limit_mb must be between {} and {} (got {})",
            MEMORY_LIMIT_RANGE.start(),
            MEMORY_LIMIT_RANGE.end(),
            m
        ));
    }
    if !cfg.wasm.auto_load && !cfg.wasm.auto_load_modules.is_empty() {
        warnings.push(
            "wasm.auto_load_modules is set but wasm.auto_load is false; modules are not loaded"
                .to_string(),
        );
    }
    Ok(())
}

/// YAML 문자열 파싱 + 키 경고 + 검증 → (구성, 경고)
pub fn parse_config(contents: &str) -> Result<(DaemonConfig, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut value: Value = serde_yaml::from_str(contents).context("Failed to parse config YAML")?;
    if value.is_null() {
        // 빈 파일 (또는 주석만)
        value = Value::Mapping(Mapping::new());
    }
    if let Value::Mapping(root) = &mut value {
        check_keys(root, &mut warnings);
    }
    let mut cfg: DaemonConfig =
        serde_yaml::from_value(value).context("Failed to parse config YAML")?;
    validate(&mut cfg, &mut warnings)?;
    Ok((cfg, warnings))
}

/// 구성 파일 로드. 파일이 없으면 기본값 + 경고.
pub fn load_config(path: &Path) -> Result<LoadedConfig> {
    if !path.exists() {
        return Ok(LoadedConfig {
            config: DaemonConfig::default(),
            warnings: vec![format!(
                "Config file not found at {}, using default config",
                path.display()
            )],
            notes: Vec::new(),
        });
    }
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    let (config, warnings) = parse_config(&contents)
        .with_context(|| format!("Invalid config file {}", path.display()))?;
    Ok(LoadedConfig {
        config,
        warnings,
        notes: vec![format!("Config loaded from {}", path.display())],
    })
}

/// 로거 필터 결정 결과
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFilter {
    /// 단일 수준 (`-v` 또는 general.log_level)
    Level(LevelFilter),
    /// RUST_LOG 필터 문자열 (env_logger 문법)
    Env(String),
}

/// 우선순위: `-v/--verbose`(debug) > `RUST_LOG`(비어 있지 않으면) > general.log_level > info.
/// cfg_level 은 validate 를 통과한 값이어야 한다(알 수 없으면 info).
pub fn resolve_log_filter(verbose: bool, rust_log: Option<&str>, cfg_level: &str) -> LogFilter {
    if verbose {
        return LogFilter::Level(LevelFilter::Debug);
    }
    if let Some(env) = rust_log.map(str::trim).filter(|s| !s.is_empty()) {
        return LogFilter::Env(env.to_string());
    }
    LogFilter::Level(cfg_level.parse().unwrap_or(LevelFilter::Info))
}

/// auto_load_modules 항목 → (모듈 이름, 경로).
/// 절대경로는 그대로, 상대경로는 modules_dir/항목. 이름은 파일 이름에서 확장자를 뺀 것.
pub fn resolve_module_entry(modules_dir: &str, entry: &str) -> (String, PathBuf) {
    let p = Path::new(entry);
    let path = if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(modules_dir).join(p)
    };
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| entry.to_string());
    (name, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATE: &str = include_str!("../../../config/swift-guard.yaml");

    /// 이전 버전 템플릿 (삭제 키 포함). 업그레이드 설치에서 그대로 남아 있는 파일을 흉내 낸다.
    const OLD_TEMPLATE: &str = r#"
general:
  log_level: "info"
  work_dir: "/var/lib/swift-guard"
  pid_file: "/var/run/swift-guard.pid"
telemetry:
  log_stats: true
  interval: 10
  export_enabled: false
  export_url: null
wasm:
  modules_dir: "/usr/local/lib/swift-guard/wasm"
  auto_load: false
  auto_load_modules: []
  execution_timeout_ms: 10
  memory_limit_mb: 32
interfaces:
  # - name: "eth0"
rules:
  # - label: "block-external-ssh"
"#;

    #[test]
    fn new_template_parses_without_warnings() {
        let (cfg, w) = parse_config(TEMPLATE).unwrap();
        assert!(w.is_empty(), "{:?}", w);
        assert_eq!(cfg.general.log_level, "info");
        assert!(cfg.telemetry.log_stats);
        assert_eq!(cfg.telemetry.interval, 10);
        assert_eq!(cfg.wasm.modules_dir, "/usr/local/lib/swift-guard/wasm");
        assert!(!cfg.wasm.auto_load);
        assert!(cfg.wasm.auto_load_modules.is_empty());
        assert_eq!(cfg.wasm.execution_timeout_ms, 10);
        assert_eq!(cfg.wasm.memory_limit_mb, 32);
    }

    #[test]
    fn old_template_ok_with_removed_key_warnings() {
        let (cfg, w) = parse_config(OLD_TEMPLATE).unwrap();
        let mut expected: Vec<String> = REMOVED_KEYS
            .iter()
            .map(|k| format!("config key '{}' is no longer supported and is ignored", k))
            .collect();
        let mut got = w.clone();
        expected.sort();
        got.sort();
        assert_eq!(got, expected);
        assert_eq!(w.len(), 6);
        assert_eq!(cfg.wasm.memory_limit_mb, 32);
    }

    #[test]
    fn empty_and_partial_files_use_defaults() {
        for src in ["", "# only a comment\n", "general:\n", "telemetry:\n  interval: 3\n"] {
            let (cfg, w) = parse_config(src).unwrap();
            assert!(w.is_empty(), "{:?}: {:?}", src, w);
            assert_eq!(cfg.general.log_level, "info");
            assert_eq!(cfg.wasm.execution_timeout_ms, 10);
            assert_eq!(cfg.wasm.memory_limit_mb, 32);
            assert!(cfg.telemetry.log_stats);
        }
        let (cfg, _) = parse_config("telemetry:\n  interval: 3\n").unwrap();
        assert_eq!(cfg.telemetry.interval, 3);
        let (cfg, _) = parse_config("wasm:\n  memory_limit_mb: 64\n").unwrap();
        assert_eq!((cfg.wasm.memory_limit_mb, cfg.wasm.execution_timeout_ms), (64, 10));
    }

    #[test]
    fn invalid_values_are_errors() {
        let e = parse_config("general:\n  log_level: loud\n").unwrap_err();
        assert_eq!(
            format!("{:#}", e),
            "invalid general.log_level 'loud' (expected one of: off, error, warn, info, debug, trace)"
        );
        let e = parse_config("wasm:\n  execution_timeout_ms: 0\n").unwrap_err();
        assert_eq!(format!("{:#}", e), "wasm.execution_timeout_ms must be between 1 and 10000 (got 0)");
        let e = parse_config("wasm:\n  execution_timeout_ms: 10001\n").unwrap_err();
        assert!(format!("{:#}", e).contains("(got 10001)"));
        let e = parse_config("wasm:\n  memory_limit_mb: 4097\n").unwrap_err();
        assert_eq!(format!("{:#}", e), "wasm.memory_limit_mb must be between 1 and 4096 (got 4097)");
        let e = parse_config("wasm:\n  memory_limit_mb: 0\n").unwrap_err();
        assert!(format!("{:#}", e).contains("(got 0)"));
        // 타입 오류는 기존 컨텍스트
        let e = parse_config("telemetry:\n  interval: soon\n").unwrap_err();
        assert!(format!("{:#}", e).starts_with("Failed to parse config YAML"), "{:#}", e);
        // 경계값은 허용
        assert!(parse_config("wasm:\n  execution_timeout_ms: 1\n  memory_limit_mb: 4096\n").is_ok());
        assert!(parse_config("wasm:\n  execution_timeout_ms: 10000\n  memory_limit_mb: 1\n").is_ok());
    }

    #[test]
    fn log_level_is_case_insensitive_and_normalized() {
        let (cfg, _) = parse_config("general:\n  log_level: WARN\n").unwrap();
        assert_eq!(cfg.general.log_level, "warn");
    }

    #[test]
    fn unknown_keys_warn() {
        let (_, w) = parse_config("general:\n  colour: red\nextra: 1\n").unwrap();
        assert_eq!(
            w,
            vec![
                "unknown config key 'general.colour' is ignored".to_string(),
                "unknown config key 'extra' is ignored".to_string(),
            ]
        );
    }

    #[test]
    fn auto_load_disabled_with_modules_warns() {
        let (_, w) =
            parse_config("wasm:\n  auto_load: false\n  auto_load_modules: [a.wasm]\n").unwrap();
        assert_eq!(
            w,
            vec!["wasm.auto_load_modules is set but wasm.auto_load is false; modules are not loaded"]
        );
        let (cfg, w) =
            parse_config("wasm:\n  auto_load: true\n  auto_load_modules: [a.wasm]\n").unwrap();
        assert!(w.is_empty());
        assert_eq!(cfg.wasm.auto_load_modules, vec!["a.wasm"]);
    }

    #[test]
    fn missing_file_uses_default_with_warning() {
        let p = Path::new("/nonexistent/swift-guard-test/config.yaml");
        let l = load_config(p).unwrap();
        assert_eq!(l.warnings.len(), 1);
        assert!(l.warnings[0].starts_with("Config file not found at /nonexistent"));
        assert_eq!(l.config.wasm.memory_limit_mb, 32);
    }

    #[test]
    fn log_filter_priority() {
        assert_eq!(
            resolve_log_filter(true, Some("trace"), "error"),
            LogFilter::Level(LevelFilter::Debug)
        );
        assert_eq!(
            resolve_log_filter(false, Some("swift_guard_daemon=trace"), "error"),
            LogFilter::Env("swift_guard_daemon=trace".into())
        );
        assert_eq!(resolve_log_filter(false, Some("  "), "warn"), LogFilter::Level(LevelFilter::Warn));
        assert_eq!(resolve_log_filter(false, None, "off"), LogFilter::Level(LevelFilter::Off));
        assert_eq!(resolve_log_filter(false, None, "info"), LogFilter::Level(LevelFilter::Info));
    }

    #[test]
    fn module_entry_resolution() {
        assert_eq!(
            resolve_module_entry("/opt/wasm", "http_inspector.wasm"),
            ("http_inspector".to_string(), PathBuf::from("/opt/wasm/http_inspector.wasm"))
        );
        assert_eq!(
            resolve_module_entry("/opt/wasm", "/srv/x/dns.wasm"),
            ("dns".to_string(), PathBuf::from("/srv/x/dns.wasm"))
        );
        assert_eq!(
            resolve_module_entry("/opt/wasm", "sub/a.b.wasm"),
            ("a.b".to_string(), PathBuf::from("/opt/wasm/sub/a.b.wasm"))
        );
    }
}
