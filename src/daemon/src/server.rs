//! API 서버 모듈
//! CLI 도구와 통신하기 위한 API 서버 구현
//!
//! 프레이밍: [u32 BE 길이][JSON]. 요청 하나에 응답 하나를 항상 돌려준다
//! (역직렬화 실패나 처리 에러도 `ApiResponse::Error` 로 응답).
//! 구조 (R2-1): 연결마다 Send 태스크를 spawn 한다. BPF 요청은 mpsc 로 accept 루프(main 태스크)에
//! 보내 동기 처리하고 oneshot 으로 응답을 돌려받는다 — MapManager / XdpAttachManager(!Send)는
//! main 태스크를 떠나지 않는다. WASM 요청은 연결 태스크에서 처리하고, 로드는 spawn_blocking 으로 돈다.
//! 자원 상한 (R3): 프레임 최대 MAX_FRAME, 연결별 read/write timeout, 동시 연결 MAX_CONNECTIONS,
//! 동시 WASM 로드 MAX_CONCURRENT_LOADS. 상한 초과는 기다리지 않고 즉시 Error 로 거절한다.

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};

use crate::bpf::{self, XdpAttachManager};
use crate::maps::{FilterRule, MapManager, ACTION_REDIRECT};
use crate::telemetry::TelemetryCollector;
use crate::wasm::WasmManager;

use swift_guard::api::{ApiRequest, ApiResponse, SystemStats, WasmModuleInfo};
use swift_guard::types::MatchSide;
use swift_guard::utils;

/// API 서버
#[derive(Debug)]
pub struct ApiServer {
    /// 바인드 주소
    addr: String,
    /// 맵 관리자
    map_manager: Arc<Mutex<MapManager>>,
    /// XDP attach 관리자
    attach: Arc<Mutex<XdpAttachManager>>,
    /// 텔레메트리 수집기
    telemetry: Arc<TelemetryCollector>,
    /// WASM 모듈 관리자
    wasm: Arc<WasmManager>,
}

/// 유효한 action 값 (swift_guard.h ACTION_PASS..ACTION_COUNT)
const VALID_ACTIONS: std::ops::RangeInclusive<u8> = 1..=4;
/// 유효한 protocol 값 (ICMP, TCP, UDP, IPPROTO_ANY)
const VALID_PROTOCOLS: [u8; 4] = [1, 6, 17, 255];

/// AddRule 입력 검증 (BPF 없이 테스트 가능한 순수 함수).
/// BPF 쪽에서 무동작(default → PASS)이 되는 값이나 무시될 필드는 Success 대신 Error 로 거부한다.
fn validate_add_rule(action: u8, protocol: u8, redirect_if: Option<&str>) -> Result<()> {
    if !VALID_ACTIONS.contains(&action) {
        return Err(anyhow!(
            "invalid action {} (1=pass, 2=drop, 3=redirect, 4=count)",
            action
        ));
    }
    if !VALID_PROTOCOLS.contains(&protocol) {
        return Err(anyhow!(
            "invalid protocol {} (1=icmp, 6=tcp, 17=udp, 255=any)",
            protocol
        ));
    }
    match (action == ACTION_REDIRECT, redirect_if) {
        (true, None) => Err(anyhow!("redirect action requires redirect_if")),
        (false, Some(ifname)) => Err(anyhow!(
            "redirect_if '{}' is only allowed with the redirect action",
            ifname
        )),
        _ => Ok(()),
    }
}

/// 요청 프레임 최대 길이 (R3-1). 길이 헤더를 읽은 직후, 버퍼 할당 전에 검사한다.
const MAX_FRAME: usize = 1 << 20;
/// 연결별 요청 읽기(길이+본문) / 응답 쓰기 제한 시간 (R3-1)
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// 동시 연결 상한 (R3-1). 초과 연결은 accept 후 즉시 Error 응답을 쓰고 닫는다.
const MAX_CONNECTIONS: usize = 64;
/// accept 실패(EMFILE 등) 후 다시 accept 하기까지의 대기 (R3-2)
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// 동시 LoadWasmModule 상한 (R3-4)
const MAX_CONCURRENT_LOADS: usize = 2;

/// 길이 헤더 검사: 상한을 넘으면 할당하지 않고 거부한다.
fn check_frame_len(len: u32) -> Result<usize> {
    let len = len as usize;
    if len > MAX_FRAME {
        return Err(anyhow!(
            "request frame too large: {} bytes (max {})",
            len,
            MAX_FRAME
        ));
    }
    Ok(len)
}

/// 응답 프레임 인코딩: [u32 BE 길이][JSON]
fn encode_response(response: &ApiResponse) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(response).context("Failed to serialize response")?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// 연결 상한 초과 시: 기다리지 않고 Error 프레임을 한 번 쓰고 닫는다.
/// accept 루프(main 태스크)에서 호출되므로 await 하지 않는다 — std 소켓(이미 non-blocking)으로
/// 직접 write 한다. 새 소켓의 송신 버퍼는 비어 있어 작은 프레임은 한 번에 들어간다.
/// 실패(WouldBlock 등)해도 연결만 닫힌다.
fn reject_busy(stream: TcpStream) {
    let frame = match encode_response(&error_response(anyhow!(
        "server busy: too many concurrent connections (max {})",
        MAX_CONNECTIONS
    ))) {
        Ok(f) => f,
        Err(_) => return,
    };
    if let Ok(mut std_stream) = stream.into_std() {
        let _ = std_stream.write_all(&frame);
    }
}

fn lock<'a, T>(m: &'a Mutex<T>, what: &str) -> Result<std::sync::MutexGuard<'a, T>> {
    m.lock().map_err(|_| anyhow!("Failed to lock {}", what))
}

/// BPF 객체(MapManager/XdpAttachManager, !Send)가 필요한 요청.
/// 연결 태스크가 만들어 accept 루프(= main 태스크)로 보내고, 결과는 oneshot 으로 돌려받는다.
struct BpfJob {
    request: ApiRequest,
    reply: oneshot::Sender<ApiResponse>,
}

/// 요청이 BPF 객체를 필요로 하는지 (와일드카드 없음: 새 변형은 여기서 경로를 정해야 컴파일된다)
fn needs_bpf(request: &ApiRequest) -> bool {
    match request {
        ApiRequest::Attach { .. }
        | ApiRequest::Detach { .. }
        | ApiRequest::AddRule { .. }
        | ApiRequest::DeleteRule { .. }
        | ApiRequest::ListRules { .. }
        | ApiRequest::GetStats {} => true,
        ApiRequest::LoadWasmModule { .. }
        | ApiRequest::UnloadWasmModule { .. }
        | ApiRequest::ListWasmModules {}
        | ApiRequest::WasmModuleStats { .. } => false,
    }
}

fn error_response(e: anyhow::Error) -> ApiResponse {
    ApiResponse::Error {
        message: format!("{:#}", e),
    }
}

/// accept 루프 (R2-1).
///
/// - 연결마다 `tokio::spawn` 한 태스크가 프레임 읽기/쓰기와 WASM 요청을 처리한다.
///   WASM 로드(컴파일 + init)는 그 태스크 안에서 `spawn_blocking` 으로 돌기 때문에
///   이 루프도, 이 루프를 폴링하는 main 의 `select!`(시그널 처리)도 막지 않는다.
/// - BPF 요청만 채널로 이 루프에 돌아와 `handle_bpf` 로 동기 처리된다(!Send 객체가 main 태스크를 떠나지 않음).
/// - 이 future 가 drop 되면(시그널로 종료) 채널 수신자가 사라지고, 남은 연결 태스크의 BPF 요청은
///   "daemon is shutting down" 에러로 끝난다.
async fn serve<F>(listener: TcpListener, wasm: Arc<WasmManager>, mut handle_bpf: F) -> Result<()>
where
    F: FnMut(ApiRequest) -> ApiResponse,
{
    let (bpf_tx, mut bpf_rx) = mpsc::channel::<BpfJob>(64);
    let conn_permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let load_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_LOADS));
    // R3-2: accept 실패 후 백오프. 루프 안에서 sleep 을 await 하지 않고 select! 분기로 두어
    // 백오프 중에도 BPF 요청 처리와(바깥 select! 의) 시그널 처리가 계속된다.
    let backoff = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(backoff);
    let mut backing_off = false;
    loop {
        tokio::select! {
            accepted = listener.accept(), if !backing_off => match accepted {
                Ok((stream, peer)) => {
                    let permit = match conn_permits.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            debug!("Rejecting connection from {}: connection limit reached", peer);
                            reject_busy(stream);
                            continue;
                        }
                    };
                    debug!("Accepted connection from {}", peer);
                    let wasm = wasm.clone();
                    let bpf_tx = bpf_tx.clone();
                    let load_permits = load_permits.clone();
                    tokio::spawn(async move {
                        // permit 은 연결이 끝날 때까지 쥔다
                        let _permit = permit;
                        if let Err(e) = handle_connection(stream, wasm, bpf_tx, load_permits).await {
                            error!("Connection error ({}): {:#}", peer, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {} (retrying in {:?})", e, ACCEPT_BACKOFF);
                    backoff.as_mut().reset(Instant::now() + ACCEPT_BACKOFF);
                    backing_off = true;
                }
            },
            _ = &mut backoff, if backing_off => backing_off = false,
            // bpf_tx 를 이 루프가 쥐고 있으므로 None 은 오지 않는다
            Some(job) = bpf_rx.recv() => {
                let response = handle_bpf(job.request);
                // 클라이언트가 먼저 끊었으면 수신자가 없다 — 무시
                let _ = job.reply.send(response);
            }
        }
    }
}

/// 요청 프레임 읽기. 길이 헤더 검사(MAX_FRAME)가 본문 버퍼 할당보다 먼저다.
async fn read_request(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .context("Failed to read request length")?;
    let len = check_frame_len(u32::from_be_bytes(len_bytes))?;

    let mut request_bytes = vec![0u8; len];
    stream
        .read_exact(&mut request_bytes)
        .await
        .context("Failed to read request")?;
    Ok(request_bytes)
}

/// 클라이언트 연결 처리 (Send 태스크). 요청을 읽은 뒤에는 항상 응답 프레임을 보낸다.
/// 프레임 초과 / read timeout 도 가능하면 Error 응답을 보낸 뒤 연결을 닫는다(Err 로 로그).
async fn handle_connection(
    mut stream: TcpStream,
    wasm: Arc<WasmManager>,
    bpf_tx: mpsc::Sender<BpfJob>,
    load_permits: Arc<Semaphore>,
) -> Result<()> {
    let read = match timeout(IO_TIMEOUT, read_request(&mut stream)).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("request read timed out after {:?}", IO_TIMEOUT)),
    };

    let (response, read_err) = match read {
        Ok(request_bytes) => {
            let response = match serde_json::from_slice::<ApiRequest>(&request_bytes)
                .context("Failed to deserialize request")
            {
                Ok(request) => {
                    debug!("Processing request: {:?}", request);
                    dispatch(request, &wasm, &bpf_tx, &load_permits).await
                }
                Err(e) => error_response(e),
            };
            (response, None)
        }
        Err(e) => (error_response(anyhow!("{:#}", e)), Some(e)),
    };

    let frame = encode_response(&response)?;
    let written = timeout(IO_TIMEOUT, stream.write_all(&frame)).await;
    // 읽기 실패가 원인이면 그것을 먼저 보고한다 (응답 쓰기 실패는 흔하다: 클라이언트가 이미 끊음)
    if let Some(e) = read_err {
        return Err(e);
    }
    written
        .map_err(|_| anyhow!("response write timed out after {:?}", IO_TIMEOUT))?
        .context("Failed to write response")?;
    Ok(())
}

/// 요청을 경로별로 처리: BPF → main 태스크로 전달, WASM → 이 태스크(로드는 blocking 풀).
async fn dispatch(
    request: ApiRequest,
    wasm: &Arc<WasmManager>,
    bpf_tx: &mpsc::Sender<BpfJob>,
    load_permits: &Arc<Semaphore>,
) -> ApiResponse {
    if needs_bpf(&request) {
        let (reply, rx) = oneshot::channel();
        if bpf_tx.send(BpfJob { request, reply }).await.is_err() {
            return error_response(anyhow!("daemon is shutting down"));
        }
        return rx
            .await
            .unwrap_or_else(|_| error_response(anyhow!("daemon is shutting down")));
    }
    process_wasm_request(wasm, load_permits, request)
        .await
        .unwrap_or_else(error_response)
}

/// WASM 관리 요청. BPF 객체를 쓰지 않으므로 main 태스크 밖에서 처리한다.
async fn process_wasm_request(
    wasm: &Arc<WasmManager>,
    load_permits: &Arc<Semaphore>,
    request: ApiRequest,
) -> Result<ApiResponse> {
    match request {
        ApiRequest::LoadWasmModule { name, file_path } => {
            // R3-4: 동시 로드 상한. 기다리지 않고 즉시 거절한다.
            let permit: OwnedSemaphorePermit = load_permits
                .clone()
                .try_acquire_owned()
                .map_err(|_| anyhow!("too many concurrent module loads (max {})", MAX_CONCURRENT_LOADS))?;
            // 컴파일(Cranelift)은 시간 제한이 없고 init 은 최대 INIT_TIMEOUT 이므로 blocking 풀에서 돈다.
            // permit 은 blocking 작업 안으로 옮겨, 연결이 끊겨도 컴파일이 끝날 때까지 상한에 포함된다.
            let wasm = wasm.clone();
            let msg_name = name.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                wasm.load_module(&name, Path::new(&file_path))
                    .with_context(|| {
                        format!("Failed to load WASM module '{}' from {}", name, file_path)
                    })
            })
            .await
            .context("WASM load task failed")??;
            Ok(ApiResponse::Success {
                message: format!("WASM module '{}' loaded", msg_name),
            })
        }

        ApiRequest::UnloadWasmModule { name } => {
            if wasm.unload_module(&name)? {
                Ok(ApiResponse::Success {
                    message: format!("WASM module '{}' unloaded", name),
                })
            } else {
                Ok(ApiResponse::Error {
                    message: format!("module not found: {}", name),
                })
            }
        }

        ApiRequest::ListWasmModules {} => {
            let modules = wasm
                .list_modules()?
                .into_iter()
                .map(|s| WasmModuleInfo {
                    name: s.name,
                    state: s.state.as_str().to_string(),
                    loaded_at: s.loaded_at,
                })
                .collect();
            Ok(ApiResponse::WasmModules { modules })
        }

        ApiRequest::WasmModuleStats { name } => match wasm.module_stats(&name)? {
            Some(s) => Ok(ApiResponse::WasmModuleStats {
                name: s.name,
                processed_packets: s.processed_packets,
                blocked_packets: s.blocked_packets,
                avg_processing_time_us: s.avg_processing_time_us,
            }),
            None => Ok(ApiResponse::Error {
                message: format!("module not found: {}", name),
            }),
        },

        other => Err(anyhow!("internal: {:?} is not a WASM request", other)),
    }
}

impl ApiServer {
    /// 새로운 API 서버 생성
    pub fn new(
        addr: &str,
        map_manager: Arc<Mutex<MapManager>>,
        attach: Arc<Mutex<XdpAttachManager>>,
        telemetry: Arc<TelemetryCollector>,
        wasm: Arc<WasmManager>,
    ) -> Self {
        Self {
            addr: addr.to_string(),
            map_manager,
            attach,
            telemetry,
            wasm,
        }
    }

    /// 서버 실행 (bind 실패 시 Err, 이후 무한 루프). main 태스크에서 폴링된다.
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr)
            .await
            .with_context(|| format!("Failed to bind to {}", self.addr))?;

        info!("API server listening on {}", self.addr);

        // MutexGuard 를 쥔 채 await 하지 않도록 BPF 요청은 동기 처리
        serve(listener, self.wasm.clone(), |request| {
            self.process_request(request).unwrap_or_else(error_response)
        })
        .await
    }

    /// BPF 요청 처리 (동기, main 태스크)
    fn process_request(&self, request: ApiRequest) -> Result<ApiResponse> {
        match request {
            ApiRequest::Attach {
                interface,
                mode,
                force,
            } => {
                let prog_fd = lock(&self.map_manager, "map_manager")?.xdp_prog_fd()?;
                lock(&self.attach, "attach manager")?.attach(prog_fd, &interface, Some(mode), force)?;
                Ok(ApiResponse::Success {
                    message: format!("XDP program attached to {} in mode {}", interface, mode),
                })
            }

            ApiRequest::Detach { interface } => {
                lock(&self.attach, "attach manager")?.detach(&interface)?;
                Ok(ApiResponse::Success {
                    message: format!("XDP program detached from {}", interface),
                })
            }

            ApiRequest::AddRule {
                src_ip,
                dst_ip,
                src_port_min,
                src_port_max,
                dst_port_min,
                dst_port_max,
                protocol,
                tcp_flags,
                action,
                redirect_if,
                priority,
                rate_limit,
                expire,
                label,
            } => {
                // 룰 하나는 src_ip(filter_rules) 또는 dst_ip(dst_rules) 중 정확히 하나로 매칭한다
                let (side, ip) = utils::select_match_ip(src_ip.as_deref(), dst_ip.as_deref())?;

                // N-5/N-6: action/protocol 범위, redirect_if 와 action 의 짝
                validate_add_rule(action, protocol, redirect_if.as_deref())?;

                let field = match side {
                    MatchSide::Src => "src_ip",
                    MatchSide::Dst => "dst_ip",
                };
                let ip_parsed = utils::parse_ip_prefix(ip)
                    .with_context(|| format!("Invalid {} '{}'", field, ip))?;

                // P-M5: redirect_if 는 실제 인터페이스 이름 (검증 후 redirect 일 때만 Some)
                let (redirect_ifindex, redirect_ifname) = match redirect_if {
                    Some(ifname) => (bpf::ifindex_of(&ifname)?, Some(ifname)),
                    None => (0, None),
                };

                let rule = FilterRule {
                    src_ip: (side == MatchSide::Src).then_some(ip_parsed),
                    dst_ip: (side == MatchSide::Dst).then_some(ip_parsed),
                    src_port_min,
                    src_port_max,
                    dst_port_min,
                    dst_port_max,
                    protocol,
                    tcp_flags,
                    action,
                    redirect_ifindex,
                    redirect_ifname,
                    priority,
                    rate_limit,
                    expire,
                    label: label.clone(),
                    creation_time: utils::current_time_secs(),
                };

                lock(&self.map_manager, "map_manager")?.add_rule(rule)?;

                Ok(ApiResponse::Success {
                    message: format!("Rule '{}' added successfully", label),
                })
            }

            ApiRequest::DeleteRule { label } => {
                let deleted = lock(&self.map_manager, "map_manager")?.delete_rule(&label)?;
                if deleted {
                    Ok(ApiResponse::Success {
                        message: format!("Rule '{}' deleted successfully", label),
                    })
                } else {
                    Ok(ApiResponse::Error {
                        message: format!("Rule '{}' not found", label),
                    })
                }
            }

            ApiRequest::ListRules { include_stats } => {
                let rules = lock(&self.map_manager, "map_manager")?.list_rules(include_stats)?;
                Ok(ApiResponse::Rules { rules })
            }

            ApiRequest::GetStats {} => {
                // 총계는 요청 시점에 맵에서, 비율은 텔레메트리 마지막 계산값
                let (total_packets, total_bytes) =
                    lock(&self.map_manager, "map_manager")?.get_stats()?;
                let (packets_per_sec, mbps) = self.telemetry.rates()?;
                Ok(ApiResponse::Stats {
                    stats: SystemStats {
                        total_packets,
                        total_bytes,
                        packets_per_sec,
                        mbps,
                    },
                })
            }

            // WASM 요청은 dispatch 에서 main 태스크 밖으로 라우팅된다 (needs_bpf)
            other @ (ApiRequest::LoadWasmModule { .. }
            | ApiRequest::UnloadWasmModule { .. }
            | ApiRequest::ListWasmModules {}
            | ApiRequest::WasmModuleStats { .. }) => {
                Err(anyhow!("internal: {:?} is not a BPF request", other))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_actions_and_protocols() {
        for action in [1u8, 2, 4] {
            for proto in VALID_PROTOCOLS {
                assert!(validate_add_rule(action, proto, None).is_ok());
            }
        }
        assert!(validate_add_rule(ACTION_REDIRECT, 6, Some("eth1")).is_ok());
    }

    #[test]
    fn rejects_invalid_action() {
        for action in [0u8, 5, 255] {
            let e = validate_add_rule(action, 255, None).unwrap_err();
            assert!(format!("{:#}", e).contains("invalid action"));
        }
    }

    #[test]
    fn rejects_invalid_protocol() {
        for proto in [0u8, 2, 7, 18, 254] {
            let e = validate_add_rule(2, proto, None).unwrap_err();
            assert!(format!("{:#}", e).contains("invalid protocol"));
        }
    }

    #[test]
    fn redirect_requires_ifname() {
        let e = validate_add_rule(ACTION_REDIRECT, 255, None).unwrap_err();
        assert!(format!("{:#}", e).contains("requires redirect_if"));
    }

    #[test]
    fn rejects_redirect_if_without_redirect_action() {
        for action in [1u8, 2, 4] {
            let e = validate_add_rule(action, 255, Some("eth1")).unwrap_err();
            assert!(format!("{:#}", e).contains("only allowed with the redirect action"));
        }
    }

    // ---- R2-1: WASM 로드가 accept 루프 / main select! 를 막지 않는지 (BPF 불필요) ----

    use std::time::{Duration, Instant};

    /// init 이 무한 루프 → epoch deadline(INIT_TIMEOUT=1s)까지 load_module 이 돌아오지 않는다
    const LOOP_INIT_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "init") (loop $l (br $l)))
          (func (export "allocate") (param i32) (result i32) (i32.const 1024))
          (func (export "deallocate") (param i32 i32))
          (func (export "inspect_packet") (param i32 i32) (result i32) (i32.const 0)))
    "#;

    fn write_loop_wat(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sg_server_test_{}_{}.wat",
            tag,
            std::process::id()
        ));
        std::fs::write(&p, LOOP_INIT_WAT).unwrap();
        p
    }

    async fn call(addr: std::net::SocketAddr, req: &ApiRequest) -> ApiResponse {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let body = serde_json::to_vec(req).unwrap();
        s.write_all(&(body.len() as u32).to_be_bytes()).await.unwrap();
        s.write_all(&body).await.unwrap();
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await.unwrap();
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await.unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    /// 가짜 BPF 처리기: main 태스크에서 동기 실행되는 process_request 자리
    fn fake_bpf(req: ApiRequest) -> ApiResponse {
        ApiResponse::Success {
            message: format!("bpf:{}", needs_bpf(&req)),
        }
    }

    fn load_req(path: &std::path::Path) -> ApiRequest {
        ApiRequest::LoadWasmModule {
            name: "slow".into(),
            file_path: path.to_string_lossy().into_owned(),
        }
    }

    // current_thread 런타임: load 가 이 스레드를 막으면 다른 요청/시그널 분기는 전혀 진행되지 않는다
    #[tokio::test(flavor = "current_thread")]
    async fn slow_wasm_load_does_not_block_bpf_requests() {
        let wasm_path = write_loop_wat("bpf");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wasm = Arc::new(WasmManager::new());
        tokio::spawn(serve(listener, wasm.clone(), fake_bpf));

        let started = Instant::now();
        let load = tokio::spawn({
            let req = load_req(&wasm_path);
            async move { call(addr, &req).await }
        });
        // 로드가 blocking 풀에서 init 루프를 도는 동안
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!load.is_finished(), "load should still be running");

        let t = Instant::now();
        let r = call(addr, &ApiRequest::ListRules { include_stats: false }).await;
        assert!(matches!(r, ApiResponse::Success { ref message } if message == "bpf:true"), "{:?}", r);
        let r = call(addr, &ApiRequest::ListWasmModules {}).await;
        assert!(matches!(r, ApiResponse::WasmModules { ref modules } if modules.is_empty()), "{:?}", r);
        assert!(t.elapsed() < Duration::from_millis(300), "took {:?}", t.elapsed());
        assert!(!load.is_finished(), "other requests must complete while load is still running");

        // 로드는 init timeout 으로 Error 응답을 받는다
        match load.await.unwrap() {
            ApiResponse::Error { message } => assert!(message.contains("timeout"), "{}", message),
            other => panic!("unexpected {:?}", other),
        }
        assert!(started.elapsed() >= Duration::from_millis(500));
        let _ = std::fs::remove_file(wasm_path);
    }

    /// main 의 select!(server.run() vs 시그널) 구조를 흉내: 로드 중 종료 신호가 즉시 처리되는지
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_signal_handled_during_slow_wasm_load() {
        let wasm_path = write_loop_wat("sig");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let wasm = Arc::new(WasmManager::new());
        let (sig_tx, sig_rx) = oneshot::channel::<()>();

        let client = tokio::spawn({
            let req = load_req(&wasm_path);
            async move { call(addr, &req).await }
        });
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = sig_tx.send(());
        });

        let started = Instant::now();
        let outcome = tokio::select! {
            r = serve(listener, wasm.clone(), fake_bpf) => format!("server stopped: {:?}", r),
            _ = sig_rx => "signal".to_string(),
        };
        let elapsed = started.elapsed();
        assert_eq!(outcome, "signal");
        assert!(elapsed < Duration::from_millis(600), "signal handled after {:?}", elapsed);
        assert!(!client.is_finished(), "signal must be handled before the load finishes");
        // 연결 태스크는 독립적으로 끝난다 (init timeout → Error)
        assert!(matches!(client.await.unwrap(), ApiResponse::Error { .. }));
        let _ = std::fs::remove_file(wasm_path);
    }

    // ---- R3: 자원 상한 (BPF 불필요) ----

    #[test]
    fn frame_len_limit() {
        assert_eq!(check_frame_len(0).unwrap(), 0);
        assert_eq!(check_frame_len(MAX_FRAME as u32).unwrap(), MAX_FRAME);
        for len in [MAX_FRAME as u32 + 1, u32::MAX] {
            let e = check_frame_len(len).unwrap_err();
            assert!(format!("{:#}", e).contains("too large"));
        }
    }

    async fn read_response(s: &mut TcpStream) -> ApiResponse {
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await.unwrap();
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await.unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    /// 길이 헤더만 보내고 본문은 보내지 않는다: 할당 + read_exact 로 진행했다면 응답이 오지 않고
    /// (u32::MAX 면 4GiB 할당 시도) 타임아웃된다. 즉시 Error 응답이 오면 할당 전에 거부된 것이다.
    #[tokio::test(flavor = "current_thread")]
    async fn oversized_frame_rejected_without_reading_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::new(WasmManager::new()), fake_bpf));

        for len in [MAX_FRAME as u32 + 1, u32::MAX] {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&len.to_be_bytes()).await.unwrap();
            let r = timeout(Duration::from_secs(2), read_response(&mut s))
                .await
                .expect("oversized frame must be rejected immediately");
            assert!(
                matches!(r, ApiResponse::Error { ref message } if message.contains("too large")),
                "{:?}",
                r
            );
            // 이후 연결은 닫힌다
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b).await.unwrap(), 0);
        }
        // 서버는 계속 동작한다
        let r = call(addr, &ApiRequest::GetStats {}).await;
        assert!(matches!(r, ApiResponse::Success { .. }), "{:?}", r);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_load_limit_rejects_immediately() {
        let wasm_path = write_loop_wat("limit");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::new(WasmManager::new()), fake_bpf));

        let slow: Vec<_> = (0..MAX_CONCURRENT_LOADS)
            .map(|i| {
                let req = ApiRequest::LoadWasmModule {
                    name: format!("slow{}", i),
                    file_path: wasm_path.to_string_lossy().into_owned(),
                };
                tokio::spawn(async move { call(addr, &req).await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(slow.iter().all(|h| !h.is_finished()), "slow loads should be running");

        let t = Instant::now();
        let r = call(addr, &load_req(&wasm_path)).await;
        assert!(t.elapsed() < Duration::from_millis(300), "took {:?}", t.elapsed());
        assert!(
            matches!(r, ApiResponse::Error { ref message } if message.contains("too many concurrent module loads")),
            "{:?}",
            r
        );

        // 진행 중이던 로드는 init timeout 으로 끝나고 permit 이 반환된다
        for h in slow {
            match h.await.unwrap() {
                ApiResponse::Error { message } => assert!(message.contains("timeout"), "{}", message),
                other => panic!("unexpected {:?}", other),
            }
        }
        match call(addr, &load_req(&wasm_path)).await {
            ApiResponse::Error { message } => {
                assert!(!message.contains("too many"), "permit not released: {}", message)
            }
            other => panic!("unexpected {:?}", other),
        }
        let _ = std::fs::remove_file(wasm_path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connection_limit_rejects_without_waiting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::new(WasmManager::new()), fake_bpf));

        // 아무것도 보내지 않는 idle 연결로 상한을 채운다
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            idle.push(TcpStream::connect(addr).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut s = TcpStream::connect(addr).await.unwrap();
        let r = timeout(Duration::from_secs(2), read_response(&mut s))
            .await
            .expect("over-limit connection must be answered immediately");
        assert!(
            matches!(r, ApiResponse::Error { ref message } if message.contains("server busy")),
            "{:?}",
            r
        );

        // idle 연결이 끊기면 permit 이 반환된다
        drop(idle);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r = call(addr, &ApiRequest::GetStats {}).await;
        assert!(matches!(r, ApiResponse::Success { .. }), "{:?}", r);
    }

    #[test]
    fn routing_is_exhaustive_and_correct() {
        assert!(needs_bpf(&ApiRequest::GetStats {}));
        assert!(needs_bpf(&ApiRequest::Detach { interface: "x".into() }));
        assert!(!needs_bpf(&ApiRequest::ListWasmModules {}));
        assert!(!needs_bpf(&ApiRequest::UnloadWasmModule { name: "x".into() }));
    }
}
