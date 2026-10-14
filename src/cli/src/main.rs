//! Swift-Guard CLI 도구
//! XDP 필터링 규칙을 관리하고 상태를 확인하는 CLI 인터페이스

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use log::{debug, warn, LevelFilter};
use std::path::PathBuf;

mod api;

use api::ApiClient;
use swift_guard_common::api::{ApiRequest, ApiResponse, RuleInfo, WasmModuleInfo};
use swift_guard_common::utils::parse_port_range;

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

/// `stats` 출력 형식
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum StatsFormat {
    Text,
    Csv,
}

/// `stats --format csv` 헤더 (벤치 스크립트·분석기와의 고정 계약)
const STATS_CSV_HEADER: &str = "timestamp_ms,total_packets,total_bytes,pps,mbps";

/// stats 샘플 1개: GetStats 응답 직후의 총계와 시각
#[derive(Debug, Clone)]
struct StatsSample {
    /// 단조 시계 (비율 계산용)
    instant: std::time::Instant,
    /// UNIX epoch 밀리초 (클라이언트 벽시계)
    timestamp_ms: u128,
    total_packets: u64,
    total_bytes: u64,
}

/// 직전 샘플 대비 (pps, mbps). 첫 샘플·총계 감소(daemon 재시작 등)·경과 0이면 None
fn compute_rates(prev: Option<&StatsSample>, cur: &StatsSample) -> Option<(u64, f64)> {
    let prev = prev?;
    if cur.total_packets < prev.total_packets || cur.total_bytes < prev.total_bytes {
        return None;
    }
    let elapsed = cur.instant.checked_duration_since(prev.instant)?.as_secs_f64();
    if elapsed <= 0.0 {
        return None;
    }
    let pps = ((cur.total_packets - prev.total_packets) as f64 / elapsed).round() as u64;
    let mbps = (cur.total_bytes - prev.total_bytes) as f64 * 8.0 / elapsed / 1e6;
    Some((pps, mbps))
}

/// CSV 데이터 행. 비율 없음이면 pps·mbps 빈 칸
fn format_stats_csv_row(cur: &StatsSample, rates: Option<(u64, f64)>) -> String {
    let (pps, mbps) = match rates {
        Some((pps, mbps)) => (pps.to_string(), format!("{:.3}", mbps)),
        None => (String::new(), String::new()),
    };
    format!(
        "{},{},{},{},{}",
        cur.timestamp_ms, cur.total_packets, cur.total_bytes, pps, mbps
    )
}

/// 텍스트 모드 시작 줄
fn stats_text_banner(interval: u64, count: u64) -> String {
    match count {
        0 => "Collecting statistics (press Ctrl+C to exit)...".to_string(),
        1 => format!("Collecting 1 sample every {}s...", interval),
        n => format!("Collecting {} samples every {}s...", n, interval),
    }
}

/// 텍스트 모드 샘플 블록 (`Total packets:`/`Total bytes:` 줄 형식은 테스트 스크립트가 파싱하므로 불변)
fn format_stats_text(cur: &StatsSample, rates: Option<(u64, f64)>) -> String {
    let (pps, bw) = match rates {
        Some((pps, mbps)) => (pps.to_string(), format!("{:.2} Mbps", mbps)),
        None => ("n/a".to_string(), "n/a".to_string()),
    };
    format!(
        "Timestamp: {}\nTotal packets: {}\nTotal bytes: {} ({:.2} MB)\nPackets/sec: {}\nBandwidth: {}\n{}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        cur.total_packets,
        cur.total_bytes,
        cur.total_bytes as f64 / (1024.0 * 1024.0),
        pps,
        bw,
        "-".repeat(40)
    )
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

        /// 이미 연결된 경우 교체
        #[clap(long)]
        force: bool,
    },

    /// XDP 프로그램을 인터페이스에서 분리
    Detach {
        /// 네트워크 인터페이스 이름
        interface: String,
    },

    /// 필터링 규칙 추가 (--src-ip 또는 --dst-ip 중 하나, prefix당 룰 1개)
    AddRule {
        /// 출발지 IP 또는 대역 (a.b.c.d[/N]) — --dst-ip와 둘 중 하나
        #[clap(long)]
        src_ip: Option<String>,

        /// 목적지 IP 또는 대역 (a.b.c.d[/N]) — --src-ip와 둘 중 하나. 출발지 룰이 매치하지 않을 때 평가
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

        /// 패킷 길이 범위 (min-max) — 현재 무시됨
        #[clap(long)]
        pkt_len: Option<String>,

        /// 액션 (pass, drop, redirect, count)
        #[clap(long)]
        action: String,

        /// 리디렉션 인터페이스 이름 (redirect 액션에 필요, 존재하는 인터페이스여야 함)
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

        /// 규칙 이름/레이블 (최대 31바이트)
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
    ///
    /// 총계는 룰에 매치한 패킷만 집계된다. 비율(pps/Mbps)은 CLI가 연속 두 샘플의 총계 차이로 계산한다(첫 샘플은 n/a).
    Stats {
        /// 샘플 간격 (초, 0은 1로 취급)
        #[clap(long, default_value = "1")]
        interval: u64,

        /// N개 샘플을 출력한 뒤 종료 (0 = Ctrl+C까지 무한)
        #[clap(long, default_value = "0")]
        count: u64,

        /// 출력 형식 (text | csv)
        #[clap(long, value_enum, default_value = "text")]
        format: StatsFormat,
    },

    /// WASM 검사 모듈 관리
    Wasm {
        #[clap(subcommand)]
        command: WasmCommands,
    },
}

#[derive(Subcommand, Debug)]
enum WasmCommands {
    /// WASM 모듈 로드
    Load {
        /// 모듈 이름
        #[clap(long)]
        name: String,

        /// .wasm 파일 경로 (daemon에는 절대경로로 전달됨)
        #[clap(long)]
        file: PathBuf,
    },

    /// WASM 모듈 언로드
    Unload {
        /// 모듈 이름
        #[clap(long)]
        name: String,
    },

    /// 로드된 WASM 모듈 목록
    List,

    /// WASM 모듈 통계
    Stats {
        /// 모듈 이름
        #[clap(long)]
        name: String,
    },
}

/// 규칙 한 줄 출력 형식 (LABEL 20, ACTION 15, SOURCE 20, DEST 20, PROTOCOL 10).
/// 출발지 룰은 SOURCE에, 목적지 룰은 DEST에 prefix가 나온다(`ip:port`, `*:port`, `*`).
/// DEST 폭 20은 `10.200.0.11:8080` 같은 목적지+포트 표기를 정렬하기 위함이다.
fn format_rule_row(r: &RuleInfo) -> String {
    let src = match (&r.src_ip, &r.src_port) {
        (Some(ip), Some(port)) => format!("{}:{}", ip, port),
        (Some(ip), None) => ip.clone(),
        (None, Some(port)) => format!("*:{}", port),
        (None, None) => "*".to_string(),
    };

    let dst = match (&r.dst_ip, &r.dst_port) {
        (Some(ip), Some(port)) => format!("{}:{}", ip, port),
        (Some(ip), None) => ip.clone(),
        (None, Some(port)) => format!("*:{}", port),
        (None, None) => "*".to_string(),
    };

    format!(
        "{:<20} {:<15} {:<20} {:<20} {:<10}",
        r.label, r.action, src, dst, r.protocol
    )
}

/// WASM 모듈 한 줄 출력 형식 (NAME STATE LOADED_AT)
fn format_wasm_row(m: &WasmModuleInfo) -> String {
    let loaded_at = chrono::DateTime::from_timestamp(m.loaded_at as i64, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| m.loaded_at.to_string());
    format!("{:<24} {:<12} {}", m.name, m.state, loaded_at)
}

/// Success 응답이면 메시지를 출력하고, 그 외는 에러로 변환
fn expect_success(response: ApiResponse, prefix: &str) -> Result<()> {
    match response {
        ApiResponse::Success { message } => {
            println!("{}: {}", prefix, message);
            Ok(())
        }
        ApiResponse::Error { message } => Err(anyhow!("{}", message)),
        other => Err(anyhow!("Unexpected response: {:?}", other)),
    }
}

fn parse_action(action: &str) -> Result<u8> {
    match action {
        "pass" => Ok(1),
        "drop" => Ok(2),
        "redirect" => Ok(3),
        "count" => Ok(4),
        _ => Err(anyhow!("Invalid action: {}", action)),
    }
}

fn parse_protocol(protocol: Option<&str>) -> Result<u8> {
    match protocol {
        Some("tcp") => Ok(6),
        Some("udp") => Ok(17),
        Some("icmp") => Ok(1),
        Some("any") | None => Ok(255),
        Some(p) => Err(anyhow!("Invalid protocol: {}", p)),
    }
}

fn parse_tcp_flags(flags: Option<&str>) -> Result<u8> {
    let Some(f) = flags else { return Ok(0) };
    let mut value = 0u8;
    for flag in f.split(',') {
        value |= match flag.trim() {
            "FIN" => 0x01,
            "SYN" => 0x02,
            "RST" => 0x04,
            "PSH" => 0x08,
            "ACK" => 0x10,
            "URG" => 0x20,
            _ => return Err(anyhow!("Invalid TCP flag: {}", flag)),
        };
    }
    Ok(value)
}

#[tokio::main]
async fn main() -> Result<()> {
    // 명령줄 인수 파싱 후 로거 초기화 (--verbose → debug, 아니면 RUST_LOG 또는 info)
    let cli = Cli::parse();

    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    if cli.verbose {
        logger.filter_level(LevelFilter::Debug);
    }
    logger.init();

    // API 클라이언트 생성
    let client = ApiClient::new(&cli.api_server).context("Failed to create API client")?;

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

            let response = client
                .send_request(&request)
                .await
                .context("Failed to send attach request")?;
            expect_success(response, "Success")?;
        }

        Commands::Detach { interface } => {
            debug!("Detaching XDP program from interface: {}", interface);

            let request = ApiRequest::Detach {
                interface: interface.clone(),
            };

            let response = client
                .send_request(&request)
                .await
                .context("Failed to send detach request")?;
            expect_success(response, "Success")?;
        }

        Commands::AddRule {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            tcp_flags,
            pkt_len,
            action,
            redirect_if,
            priority,
            rate_limit,
            expire,
            label,
        } => {
            debug!("Adding filter rule: {}", label);

            if pkt_len.is_some() {
                warn!("--pkt-len is not supported yet and is ignored");
            }

            let action_value = parse_action(action)?;
            let protocol_value = parse_protocol(protocol.as_deref())?;

            let (src_port_min, src_port_max) = match src_port {
                Some(p) => parse_port_range(p)?,
                None => (0, 65535),
            };

            let (dst_port_min, dst_port_max) = match dst_port {
                Some(p) => parse_port_range(p)?,
                None => (0, 65535),
            };

            let tcp_flags_value = parse_tcp_flags(tcp_flags.as_deref())?;

            if action_value == 3 && redirect_if.is_none() {
                return Err(anyhow!("Redirect action requires '--redirect-if' parameter"));
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

            let response = client
                .send_request(&request)
                .await
                .context("Failed to send add rule request")?;
            expect_success(response, "Rule added")?;
        }

        Commands::DeleteRule { label } => {
            debug!("Deleting filter rule: {}", label);

            let request = ApiRequest::DeleteRule {
                label: label.clone(),
            };

            let response = client
                .send_request(&request)
                .await
                .context("Failed to send delete rule request")?;
            expect_success(response, "Rule deleted")?;
        }

        Commands::ListRules { stats } => {
            debug!("Listing filter rules");

            let request = ApiRequest::ListRules {
                include_stats: *stats,
            };

            let response = client
                .send_request(&request)
                .await
                .context("Failed to send list rules request")?;

            match response {
                ApiResponse::Rules { rules } => {
                    if rules.is_empty() {
                        println!("No rules found");
                    } else {
                        println!(
                            "{:<20} {:<15} {:<20} {:<20} {:<10}",
                            "LABEL", "ACTION", "SOURCE", "DEST", "PROTOCOL"
                        );
                        println!("{}", "-".repeat(90));

                        for rule in &rules {
                            println!("{}", format_rule_row(rule));
                            if *stats {
                                println!(
                                    "  Packets: {}, Bytes: {}",
                                    rule.stats.packets, rule.stats.bytes
                                );
                            }
                        }
                    }
                }
                ApiResponse::Error { message } => return Err(anyhow!("{}", message)),
                other => return Err(anyhow!("Unexpected response: {:?}", other)),
            }
        }

        Commands::Stats { interval, count, format } => {
            use std::io::Write;
            debug!("Showing performance statistics");

            let interval = (*interval).max(1);
            let count = *count;
            let format = *format;
            let mut out = std::io::stdout();

            match format {
                StatsFormat::Text => writeln!(out, "{}", stats_text_banner(interval, count))?,
                StatsFormat::Csv => writeln!(out, "{}", STATS_CSV_HEADER)?,
            }
            out.flush()?;

            let mut prev: Option<StatsSample> = None;
            let mut taken: u64 = 0;
            loop {
                let response = client
                    .send_request(&ApiRequest::GetStats {})
                    .await
                    .context("Failed to send get stats request")?;

                // daemon의 packets_per_sec/mbps(telemetry 주기 값)는 쓰지 않는다
                let cur = match response {
                    ApiResponse::Stats { stats } => StatsSample {
                        instant: std::time::Instant::now(),
                        timestamp_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0),
                        total_packets: stats.total_packets,
                        total_bytes: stats.total_bytes,
                    },
                    ApiResponse::Error { message } => return Err(anyhow!("{}", message)),
                    other => return Err(anyhow!("Unexpected response: {:?}", other)),
                };

                let rates = compute_rates(prev.as_ref(), &cur);
                match format {
                    StatsFormat::Text => writeln!(out, "{}", format_stats_text(&cur, rates))?,
                    StatsFormat::Csv => writeln!(out, "{}", format_stats_csv_row(&cur, rates))?,
                }
                out.flush()?;
                prev = Some(cur);

                taken += 1;
                if count > 0 && taken >= count {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        }

        Commands::Wasm { command } => match command {
            WasmCommands::Load { name, file } => {
                // daemon의 cwd는 CLI와 다르므로 절대경로로 바꿔서 보낸다
                let abs = std::fs::canonicalize(file)
                    .with_context(|| format!("WASM file not found: {}", file.display()))?;
                let file_path = abs
                    .to_str()
                    .ok_or_else(|| anyhow!("WASM file path is not valid UTF-8: {}", abs.display()))?
                    .to_string();
                debug!("Loading WASM module {} from {}", name, file_path);

                let request = ApiRequest::LoadWasmModule {
                    name: name.clone(),
                    file_path,
                };
                let response = client
                    .send_request(&request)
                    .await
                    .context("Failed to send wasm load request")?;
                expect_success(response, "Module loaded")?;
            }

            WasmCommands::Unload { name } => {
                let request = ApiRequest::UnloadWasmModule { name: name.clone() };
                let response = client
                    .send_request(&request)
                    .await
                    .context("Failed to send wasm unload request")?;
                expect_success(response, "Module unloaded")?;
            }

            WasmCommands::List => {
                let request = ApiRequest::ListWasmModules {};
                let response = client
                    .send_request(&request)
                    .await
                    .context("Failed to send wasm list request")?;
                match response {
                    ApiResponse::WasmModules { modules } => {
                        if modules.is_empty() {
                            println!("No WASM modules loaded");
                        } else {
                            println!("{:<24} {:<12} {}", "NAME", "STATE", "LOADED_AT");
                            println!("{}", "-".repeat(60));
                            for m in &modules {
                                println!("{}", format_wasm_row(m));
                            }
                        }
                    }
                    ApiResponse::Error { message } => return Err(anyhow!("{}", message)),
                    other => return Err(anyhow!("Unexpected response: {:?}", other)),
                }
            }

            WasmCommands::Stats { name } => {
                let request = ApiRequest::WasmModuleStats { name: name.clone() };
                let response = client
                    .send_request(&request)
                    .await
                    .context("Failed to send wasm stats request")?;
                match response {
                    ApiResponse::WasmModuleStats {
                        name,
                        processed_packets,
                        blocked_packets,
                        avg_processing_time_us,
                    } => {
                        println!("Module: {}", name);
                        println!("Processed packets: {}", processed_packets);
                        println!("Blocked packets: {}", blocked_packets);
                        println!("Avg processing time: {:.2} us", avg_processing_time_us);
                    }
                    ApiResponse::Error { message } => return Err(anyhow!("{}", message)),
                    other => return Err(anyhow!("Unexpected response: {:?}", other)),
                }
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_guard_common::api::RuleStats;

    #[test]
    fn rule_row_dst_rule_alignment() {
        let r = RuleInfo {
            label: "protect-web2".into(),
            action: "drop".into(),
            src_ip: None,
            dst_ip: Some("10.200.0.11".into()),
            src_port: None,
            dst_port: Some("8080".into()),
            protocol: "tcp".into(),
            tcp_flags: None,
            priority: 0,
            redirect_if: None,
            rate_limit: 0,
            expire: 0,
            stats: RuleStats { packets: 0, bytes: 0, last_matched: 0 },
        };
        assert_eq!(
            format_rule_row(&r).trim_end(),
            "protect-web2         drop            *                    10.200.0.11:8080     tcp"
        );
    }

    fn sample(at: std::time::Instant, packets: u64, bytes: u64) -> StatsSample {
        StatsSample { instant: at, timestamp_ms: 1, total_packets: packets, total_bytes: bytes }
    }

    #[test]
    fn stats_csv_header_is_fixed() {
        assert_eq!(STATS_CSV_HEADER, "timestamp_ms,total_packets,total_bytes,pps,mbps");
    }

    #[test]
    fn stats_first_row_has_empty_rates() {
        let cur = sample(std::time::Instant::now(), 37, 3020);
        let rates = compute_rates(None, &cur);
        assert!(rates.is_none());
        assert_eq!(format_stats_csv_row(&cur, rates), "1,37,3020,,");
        assert!(format_stats_text(&cur, rates).contains("Packets/sec: n/a\nBandwidth: n/a"));
    }

    #[test]
    fn stats_rates_over_one_second() {
        let t0 = std::time::Instant::now();
        let t1 = t0 + std::time::Duration::from_secs(1);
        let prev = sample(t0, 100, 10_000);
        let cur = sample(t1, 1100, 135_000);
        let (pps, mbps) = compute_rates(Some(&prev), &cur).unwrap();
        assert_eq!(pps, 1000);
        assert!((mbps - 1.0).abs() < 1e-9);
        assert_eq!(format_stats_csv_row(&cur, Some((pps, mbps))), "1,1100,135000,1000,1.000");
        let text = format_stats_text(&cur, Some((pps, mbps)));
        assert!(text.contains("\nTotal packets: 1100\n"));
        assert!(text.contains("Packets/sec: 1000\nBandwidth: 1.00 Mbps"));
    }

    #[test]
    fn stats_rates_none_when_totals_decrease() {
        let t0 = std::time::Instant::now();
        let t1 = t0 + std::time::Duration::from_secs(1);
        assert!(compute_rates(Some(&sample(t0, 500, 9000)), &sample(t1, 10, 800)).is_none());
    }

    #[test]
    fn stats_banner_variants() {
        assert_eq!(stats_text_banner(1, 0), "Collecting statistics (press Ctrl+C to exit)...");
        assert_eq!(stats_text_banner(1, 1), "Collecting 1 sample every 1s...");
        assert_eq!(stats_text_banner(2, 3), "Collecting 3 samples every 2s...");
    }

    #[test]
    fn stats_cli_parsing() {
        let cli = Cli::try_parse_from(["xdp-filter", "stats", "--format", "csv", "--count", "3"])
            .expect("parse");
        match cli.command {
            Commands::Stats { interval, count, format } => {
                assert_eq!((interval, count, format), (1, 3, StatsFormat::Csv));
            }
            other => panic!("unexpected: {:?}", other),
        }
        let cli = Cli::try_parse_from(["xdp-filter", "stats"]).expect("parse");
        assert!(matches!(
            cli.command,
            Commands::Stats { interval: 1, count: 0, format: StatsFormat::Text }
        ));
        assert!(Cli::try_parse_from(["xdp-filter", "stats", "--format", "json"]).is_err());
    }
}
