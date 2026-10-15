//! Swift-Guard CLI 도구
//! XDP 필터링 규칙을 관리하고 상태를 확인하는 CLI 인터페이스

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use log::{debug, LevelFilter};
use std::path::PathBuf;

mod api;

use api::ApiClient;
use swift_guard_common::api::{ApiRequest, ApiResponse, RuleInfo, WasmModuleInfo, XdpCounters};
use swift_guard_common::endpoint::{ApiEndpoint, DEFAULT_API_ENDPOINT};
use swift_guard_common::utils::parse_port_range;

/// clap value_parser: 주소 문법은 common::endpoint 가 원천이다 (루프백 검사 포함)
fn parse_endpoint(s: &str) -> Result<ApiEndpoint, String> {
    s.parse::<ApiEndpoint>().map_err(|e| format!("{:#}", e))
}

#[derive(Parser, Debug)]
#[clap(name = "xdp-filter", about = "XDP Filtering Tool", version)]
struct Cli {
    /// daemon API address: unix:/path or tcp:<loopback-ip>:<port>
    #[clap(long, value_name = "ENDPOINT", default_value = DEFAULT_API_ENDPOINT, value_parser = parse_endpoint)]
    api_server: ApiEndpoint,

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

/// `stats --format csv` 헤더 (벤치 스크립트·분석기와의 고정 계약, 17열).
/// 1–5열은 룰 매치(stats_map), 6–17열은 XDP 전체·결과별(xdp_stats_map).
const STATS_CSV_HEADER: &str = "timestamp_ms,total_packets,total_bytes,pps,mbps,\
xdp_rx_packets,xdp_rx_bytes,xdp_rx_pps,xdp_rx_mbps,\
xdp_drop_packets,xdp_pass_packets,xdp_redirect_packets,xdp_count_packets,\
xdp_no_match_packets,xdp_invalid_packets,xdp_non_ipv4_packets,xdp_action_error_packets";

/// stats 샘플 1개: GetStats 응답 직후의 총계와 시각
#[derive(Debug, Clone)]
struct StatsSample {
    /// 단조 시계 (비율 계산용)
    instant: std::time::Instant,
    /// UNIX epoch 밀리초 (클라이언트 벽시계)
    timestamp_ms: u128,
    /// 룰 매치 패킷 (stats_map)
    total_packets: u64,
    total_bytes: u64,
    /// XDP 전체·결과별 카운터. 구 daemon 이면 None
    xdp: Option<XdpCounters>,
}

/// (packets, bytes) 누적값 두 개 사이의 (pps, mbps). 감소(daemon 재시작 등)·경과 0이면 None
fn rate_between(
    prev: (u64, u64),
    cur: (u64, u64),
    elapsed: std::time::Duration,
) -> Option<(u64, f64)> {
    if cur.0 < prev.0 || cur.1 < prev.1 {
        return None;
    }
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return None;
    }
    let pps = ((cur.0 - prev.0) as f64 / secs).round() as u64;
    let mbps = (cur.1 - prev.1) as f64 * 8.0 / secs / 1e6;
    Some((pps, mbps))
}

/// 직전 샘플 대비 룰 매치 (pps, mbps). 첫 샘플이면 None
fn compute_rates(prev: Option<&StatsSample>, cur: &StatsSample) -> Option<(u64, f64)> {
    let prev = prev?;
    let elapsed = cur.instant.checked_duration_since(prev.instant)?;
    rate_between(
        (prev.total_packets, prev.total_bytes),
        (cur.total_packets, cur.total_bytes),
        elapsed,
    )
}

/// 직전 샘플 대비 XDP rx (pps, mbps). 첫 샘플·어느 쪽이든 xdp 없음·rx 총계 감소면 None
fn compute_xdp_rates(prev: Option<&StatsSample>, cur: &StatsSample) -> Option<(u64, f64)> {
    let prev = prev?;
    let (p, c) = (prev.xdp?, cur.xdp?);
    let elapsed = cur.instant.checked_duration_since(prev.instant)?;
    rate_between((p.rx_packets, p.rx_bytes), (c.rx_packets, c.rx_bytes), elapsed)
}

/// 비율 → (pps 문자열, mbps 문자열). 없으면 빈 칸
fn csv_rate_cells(rates: Option<(u64, f64)>) -> (String, String) {
    match rates {
        Some((pps, mbps)) => (pps.to_string(), format!("{:.3}", mbps)),
        None => (String::new(), String::new()),
    }
}

/// CSV 데이터 행 (17열). 비율 없음이면 해당 칸 빈 칸, xdp 없음이면 6–17열 빈 칸
fn format_stats_csv_row(
    cur: &StatsSample,
    rates: Option<(u64, f64)>,
    xdp_rates: Option<(u64, f64)>,
) -> String {
    let (pps, mbps) = csv_rate_cells(rates);
    let xdp_cells = match cur.xdp {
        Some(x) => {
            let (xpps, xmbps) = csv_rate_cells(xdp_rates);
            format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}",
                x.rx_packets,
                x.rx_bytes,
                xpps,
                xmbps,
                x.drop_packets,
                x.pass_packets,
                x.redirect_packets,
                x.count_packets,
                x.no_match_packets,
                x.invalid_packets,
                x.non_ipv4_packets,
                x.action_error_packets
            )
        }
        None => ",".repeat(11),
    };
    format!(
        "{},{},{},{},{},{}",
        cur.timestamp_ms, cur.total_packets, cur.total_bytes, pps, mbps, xdp_cells
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

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// 텍스트 모드 샘플 블록 (`Total packets:`/`Total bytes:` 줄 형식은 테스트 스크립트가 파싱하므로 불변).
/// 기존 5줄 뒤에 XDP 5줄(구 daemon 이면 n/a 1줄)을 붙인다.
fn format_stats_text(
    cur: &StatsSample,
    rates: Option<(u64, f64)>,
    xdp_rates: Option<(u64, f64)>,
) -> String {
    let fmt_rates = |r: Option<(u64, f64)>| match r {
        Some((pps, mbps)) => (pps.to_string(), format!("{:.2} Mbps", mbps)),
        None => ("n/a".to_string(), "n/a".to_string()),
    };
    let (pps, bw) = fmt_rates(rates);
    let xdp = match cur.xdp {
        Some(x) => {
            let (xpps, xbw) = fmt_rates(xdp_rates);
            format!(
                "XDP rx packets: {}\nXDP rx bytes: {} ({:.2} MB)\nXDP rx packets/sec: {}\nXDP rx bandwidth: {}\n\
                 XDP verdicts: drop={} pass={} redirect={} count={} no_match={} invalid={} non_ipv4={} action_error={}",
                x.rx_packets,
                x.rx_bytes,
                mib(x.rx_bytes),
                xpps,
                xbw,
                x.drop_packets,
                x.pass_packets,
                x.redirect_packets,
                x.count_packets,
                x.no_match_packets,
                x.invalid_packets,
                x.non_ipv4_packets,
                x.action_error_packets
            )
        }
        None => "XDP counters: n/a (daemon does not report them)".to_string(),
    };
    format!(
        "Timestamp: {}\nTotal packets: {}\nTotal bytes: {} ({:.2} MB)\nPackets/sec: {}\nBandwidth: {}\n{}\n{}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        cur.total_packets,
        cur.total_bytes,
        mib(cur.total_bytes),
        pps,
        bw,
        xdp,
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

        /// 패킷 길이 범위 (min-max) — 미구현: 지정하면 거부된다
        #[clap(long)]
        pkt_len: Option<String>,

        /// 액션 (pass, drop, redirect, count)
        #[clap(long)]
        action: String,

        /// 리디렉션 인터페이스 이름 (redirect 액션에 필요, 존재하는 인터페이스여야 함)
        #[clap(long)]
        redirect_if: Option<String>,

        /// 규칙 우선순위 — 미구현: 0 이외의 값은 daemon이 거부한다
        #[clap(long, default_value = "0")]
        priority: u32,

        /// 초당 패킷 수 레이트 리밋 — 미구현: 0 이외의 값은 daemon이 거부한다
        #[clap(long, default_value = "0")]
        rate_limit: u32,

        /// 규칙 만료 시간(초) — 미구현: 0 이외의 값은 daemon이 거부한다
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
    /// Total packets/bytes = 룰에 매치한 패킷만(stats_map). XDP rx = XDP가 본 전체 패킷(룰과 무관),
    /// XDP verdicts = 결과별 패킷 수(drop/pass/redirect/count/no_match/invalid/non_ipv4/action_error).
    /// 비율(pps/Mbps)은 CLI가 연속 두 샘플의 총계 차이로 계산한다(첫 샘플은 n/a, CSV는 빈 칸).
    /// CSV는 17열 고정이다.
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

/// `--pkt-len` 은 미구현: 값과 무관하게 지정하면 거부
fn check_pkt_len(pkt_len: Option<&str>) -> Result<()> {
    match pkt_len {
        Some(_) => Err(anyhow!("--pkt-len is not implemented yet")),
        None => Ok(()),
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
    let client = ApiClient::new(cli.api_server.clone());

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

            // 와이어 필드가 없어 daemon이 알 수 없으므로 CLI가 거부한다(요청을 보내지 않음).
            // priority/rate_limit/expire 는 daemon 이 검사한다(문구 원천 1곳).
            check_pkt_len(pkt_len.as_deref())?;

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
                        xdp: stats.xdp,
                    },
                    ApiResponse::Error { message } => return Err(anyhow!("{}", message)),
                    other => return Err(anyhow!("Unexpected response: {:?}", other)),
                };

                let rates = compute_rates(prev.as_ref(), &cur);
                let xdp_rates = compute_xdp_rates(prev.as_ref(), &cur);
                match format {
                    StatsFormat::Text => {
                        writeln!(out, "{}", format_stats_text(&cur, rates, xdp_rates))?
                    }
                    StatsFormat::Csv => {
                        writeln!(out, "{}", format_stats_csv_row(&cur, rates, xdp_rates))?
                    }
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
        StatsSample { instant: at, timestamp_ms: 1, total_packets: packets, total_bytes: bytes, xdp: None }
    }

    fn xdp(rx: u64, rx_bytes: u64) -> XdpCounters {
        XdpCounters {
            rx_packets: rx,
            rx_bytes,
            drop_packets: 1,
            pass_packets: 2,
            redirect_packets: 3,
            count_packets: 4,
            no_match_packets: 5,
            invalid_packets: 6,
            non_ipv4_packets: 7,
            action_error_packets: 8,
        }
    }

    fn sample_x(at: std::time::Instant, packets: u64, bytes: u64, x: XdpCounters) -> StatsSample {
        StatsSample { xdp: Some(x), ..sample(at, packets, bytes) }
    }

    /// C5 첫 데이터 행 정규식 `^[0-9]+,[0-9]+,[0-9]+,,,[0-9]+,[0-9]+,,,([0-9]+,){7}[0-9]+$` 를 손으로 검사
    fn matches_first_row_contract(row: &str) -> bool {
        let f: Vec<&str> = row.split(',').collect();
        let num = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        f.len() == 17
            && f[..3].iter().all(|s| num(s))
            && f[3].is_empty()
            && f[4].is_empty()
            && num(f[5])
            && num(f[6])
            && f[7].is_empty()
            && f[8].is_empty()
            && f[9..].iter().all(|s| num(s))
    }

    #[test]
    fn stats_csv_header_is_fixed() {
        assert_eq!(
            STATS_CSV_HEADER,
            "timestamp_ms,total_packets,total_bytes,pps,mbps,xdp_rx_packets,xdp_rx_bytes,xdp_rx_pps,xdp_rx_mbps,xdp_drop_packets,xdp_pass_packets,xdp_redirect_packets,xdp_count_packets,xdp_no_match_packets,xdp_invalid_packets,xdp_non_ipv4_packets,xdp_action_error_packets"
        );
        assert_eq!(STATS_CSV_HEADER.split(',').count(), 17);
    }

    #[test]
    fn stats_first_row_has_empty_rates() {
        let cur = sample_x(std::time::Instant::now(), 37, 3020, xdp(50, 4900));
        let rates = compute_rates(None, &cur);
        let xr = compute_xdp_rates(None, &cur);
        assert!(rates.is_none() && xr.is_none());
        let row = format_stats_csv_row(&cur, rates, xr);
        assert_eq!(row, "1,37,3020,,,50,4900,,,1,2,3,4,5,6,7,8");
        assert!(matches_first_row_contract(&row), "{}", row);
        let text = format_stats_text(&cur, rates, xr);
        assert!(text.contains("Packets/sec: n/a\nBandwidth: n/a\n"));
        assert!(text.contains("\nXDP rx packets: 50\nXDP rx bytes: 4900 (0.00 MB)\nXDP rx packets/sec: n/a\nXDP rx bandwidth: n/a\n"));
        assert!(text.contains(
            "\nXDP verdicts: drop=1 pass=2 redirect=3 count=4 no_match=5 invalid=6 non_ipv4=7 action_error=8\n----"
        ));
    }

    #[test]
    fn stats_rates_over_one_second() {
        let t0 = std::time::Instant::now();
        let t1 = t0 + std::time::Duration::from_secs(1);
        let prev = sample_x(t0, 100, 10_000, xdp(1000, 100_000));
        let cur = sample_x(t1, 1100, 135_000, xdp(3000, 350_000));
        let (pps, mbps) = compute_rates(Some(&prev), &cur).unwrap();
        assert_eq!(pps, 1000);
        assert!((mbps - 1.0).abs() < 1e-9);
        let (xpps, xmbps) = compute_xdp_rates(Some(&prev), &cur).unwrap();
        assert_eq!(xpps, 2000);
        assert!((xmbps - 2.0).abs() < 1e-9);
        assert_eq!(
            format_stats_csv_row(&cur, Some((pps, mbps)), Some((xpps, xmbps))),
            "1,1100,135000,1000,1.000,3000,350000,2000,2.000,1,2,3,4,5,6,7,8"
        );
        let text = format_stats_text(&cur, Some((pps, mbps)), Some((xpps, xmbps)));
        assert!(text.contains("\nTotal packets: 1100\n"));
        assert!(text.contains("Packets/sec: 1000\nBandwidth: 1.00 Mbps"));
        assert!(text.contains("XDP rx packets/sec: 2000\nXDP rx bandwidth: 2.00 Mbps"));
    }

    #[test]
    fn stats_rates_none_when_totals_decrease() {
        let t0 = std::time::Instant::now();
        let t1 = t0 + std::time::Duration::from_secs(1);
        assert!(compute_rates(Some(&sample(t0, 500, 9000)), &sample(t1, 10, 800)).is_none());
        // rx 총계 감소 → xdp 비율만 None (룰 매치 비율은 독립)
        let prev = sample_x(t0, 1, 100, xdp(900, 90_000));
        let cur = sample_x(t1, 2, 200, xdp(10, 1000));
        assert!(compute_xdp_rates(Some(&prev), &cur).is_none());
        assert!(compute_rates(Some(&prev), &cur).is_some());
    }

    #[test]
    fn stats_without_xdp_old_daemon() {
        let t0 = std::time::Instant::now();
        let t1 = t0 + std::time::Duration::from_secs(1);
        let prev = sample(t0, 100, 10_000);
        let cur = sample(t1, 1100, 135_000);
        let rates = compute_rates(Some(&prev), &cur);
        let xr = compute_xdp_rates(Some(&prev), &cur);
        assert!(xr.is_none());
        let row = format_stats_csv_row(&cur, rates, xr);
        assert_eq!(row, "1,1100,135000,1000,1.000,,,,,,,,,,,,");
        assert_eq!(row.split(',').count(), 17);
        let text = format_stats_text(&cur, rates, xr);
        assert!(text.contains("Bandwidth: 1.00 Mbps\nXDP counters: n/a (daemon does not report them)\n----"));
        assert!(!text.contains("XDP rx packets"));
        // 이전 샘플만 xdp 가 있어도 비율 없음
        let prev_x = sample_x(t0, 100, 10_000, xdp(1, 1));
        assert!(compute_xdp_rates(Some(&prev_x), &cur).is_none());
    }

    #[test]
    fn pkt_len_rejected() {
        assert!(check_pkt_len(None).is_ok());
        assert_eq!(
            check_pkt_len(Some("64-128")).unwrap_err().to_string(),
            "--pkt-len is not implemented yet"
        );
        // clap 은 옵션을 계속 받는다 (unexpected argument 가 아니라 위 문구로 거부)
        let cli = Cli::try_parse_from([
            "xdp-filter", "add-rule", "--src-ip", "10.0.0.1", "--action", "drop",
            "--label", "x", "--pkt-len", "64-128",
        ])
        .expect("parse");
        match cli.command {
            Commands::AddRule { pkt_len, priority, rate_limit, expire, .. } => {
                assert_eq!(pkt_len.as_deref(), Some("64-128"));
                assert_eq!((priority, rate_limit, expire), (0, 0, 0));
                assert!(check_pkt_len(pkt_len.as_deref()).is_err());
            }
            other => panic!("unexpected: {:?}", other),
        }
        // priority 등은 CLI 가 미리 거부하지 않는다 (daemon 문구가 원천)
        assert!(Cli::try_parse_from([
            "xdp-filter", "add-rule", "--src-ip", "10.0.0.1", "--action", "drop",
            "--label", "x", "--priority", "5", "--rate-limit", "100", "--expire", "60",
        ])
        .is_ok());
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

    #[test]
    fn api_server_default_is_unix_socket() {
        let cli = Cli::try_parse_from(["xdp-filter", "list-rules"]).expect("parse");
        assert_eq!(cli.api_server, ApiEndpoint::Unix("/run/swift-guard/api.sock".into()));
        assert_eq!(cli.api_server.to_string(), DEFAULT_API_ENDPOINT);
    }

    #[test]
    fn api_server_accepts_unix_and_loopback_tcp() {
        let cli = Cli::try_parse_from(["xdp-filter", "--api-server", "tcp:127.0.0.1:7654", "list-rules"])
            .expect("parse");
        assert_eq!(cli.api_server, ApiEndpoint::Tcp("127.0.0.1:7654".parse().unwrap()));
        let cli = Cli::try_parse_from(["xdp-filter", "--api-server", "/tmp/x.sock", "list-rules"])
            .expect("parse");
        assert_eq!(cli.api_server, ApiEndpoint::Unix("/tmp/x.sock".into()));
    }

    #[test]
    fn api_server_rejects_schemeless_and_non_loopback() {
        let e = Cli::try_parse_from(["xdp-filter", "--api-server", "127.0.0.1:7654", "list-rules"])
            .unwrap_err()
            .to_string();
        assert!(e.contains("add a scheme: tcp:127.0.0.1:7654"), "{}", e);
        let e = Cli::try_parse_from(["xdp-filter", "--api-server", "tcp:0.0.0.0:7654", "list-rules"])
            .unwrap_err()
            .to_string();
        assert!(e.contains("refusing non-loopback TCP API address"), "{}", e);
    }
}
