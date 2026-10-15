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
//! 전송 (계획 C-4): 기본은 Unix 소켓(`root:swift-guard 0660`, 그룹이 없으면 `0600` root 전용).
//! 접근 제어는 소켓 파일 권한이 한다. SO_PEERCRED 는 감사 로그(변경 요청의 uid/gid/pid)에만 쓴다.
//! TCP 는 `tcp:` 루프백 옵트인(파서가 비루프백을 거부한다, common::endpoint).

use anyhow::{anyhow, Context, Result};
use log::{debug, error, info, warn};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};

use crate::bpf::{self, XdpAttachManager};
use crate::maps::{FilterRule, MapManager, ACTION_REDIRECT};
use crate::telemetry::TelemetryCollector;
use crate::wasm::WasmManager;

use swift_guard::api::{ApiRequest, ApiResponse, SystemStats, WasmModuleInfo};
use swift_guard::endpoint::ApiEndpoint;
use swift_guard::types::MatchSide;
use swift_guard::utils;

/// API 서버
#[derive(Debug)]
pub struct ApiServer {
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
/// 순서: priority → rate_limit → expire (미구현, 0만 허용) → action → protocol → redirect_if.
/// 여러 필드가 걸리면 첫 번째만 보고한다. (src/dst 검사는 호출 전에 select_match_ip 가 한다)
fn validate_add_rule(
    action: u8,
    protocol: u8,
    redirect_if: Option<&str>,
    priority: u32,
    rate_limit: u32,
    expire: u32,
) -> Result<()> {
    for (name, v) in [("priority", priority), ("rate_limit", rate_limit), ("expire", expire)] {
        if v != 0 {
            return Err(anyhow!(
                "{} is not implemented yet: only 0 is accepted (got {})",
                name,
                v
            ));
        }
    }
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
fn reject_busy(conn: ApiConn) {
    let frame = match encode_response(&error_response(anyhow!(
        "server busy: too many concurrent connections (max {})",
        MAX_CONNECTIONS
    ))) {
        Ok(f) => f,
        Err(_) => return,
    };
    match conn {
        ApiConn::Unix(stream) => {
            if let Ok(mut std_stream) = stream.into_std() {
                let _ = std_stream.write_all(&frame);
            }
        }
        ApiConn::Tcp(stream) => {
            if let Ok(mut std_stream) = stream.into_std() {
                let _ = std_stream.write_all(&frame);
            }
        }
    }
}

// ---- 전송 계층 (C-4) ----

/// Unix 소켓 정리 guard: 자기가 만든 소켓(dev/ino 일치)만 Drop 시 삭제한다 (D11).
/// 다른 daemon 이 같은 경로에 새로 만든 소켓은 지우지 않는다.
#[derive(Debug)]
pub struct SocketCleanup {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        match std::fs::symlink_metadata(&self.path) {
            Ok(m) if m.dev() == self.dev && m.ino() == self.ino => {
                match std::fs::remove_file(&self.path) {
                    Ok(()) => debug!("removed API socket {}", self.path.display()),
                    Err(e) => warn!("failed to remove API socket {}: {}", self.path.display(), e),
                }
            }
            Ok(_) => debug!(
                "API socket {} was replaced by another process; not removing it",
                self.path.display()
            ),
            Err(_) => {}
        }
    }
}

/// bind 된 API 리스너. Unix 는 정리 guard 를 소유한다(리스너와 함께 drop → 소켓 삭제).
#[derive(Debug)]
pub enum ApiListener {
    Unix {
        listener: UnixListener,
        _cleanup: SocketCleanup,
    },
    Tcp(TcpListener),
}

/// 수락된 연결
#[derive(Debug)]
enum ApiConn {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl ApiListener {
    /// 연결 하나를 수락하고 감사용 peer 라벨을 만든다.
    /// (tokio accept 는 cancel-safe 이고 이후 처리는 동기라 select! 분기로 써도 안전하다)
    async fn accept(&self) -> std::io::Result<(ApiConn, String)> {
        match self {
            ApiListener::Unix { listener, .. } => {
                let (stream, _) = listener.accept().await?;
                let label = unix_peer_label(&stream);
                Ok((ApiConn::Unix(stream), label))
            }
            ApiListener::Tcp(listener) => {
                let (stream, addr) = listener.accept().await?;
                Ok((ApiConn::Tcp(stream), addr.to_string()))
            }
        }
    }
}

/// SO_PEERCRED 라벨: `uid=U gid=G pid=P` (pid 를 모르면 `?`, 조회 실패 시 `unix peer`)
fn unix_peer_label(stream: &UnixStream) -> String {
    match stream.peer_cred() {
        Ok(c) => format!(
            "uid={} gid={} pid={}",
            c.uid(),
            c.gid(),
            c.pid().map(|p| p.to_string()).unwrap_or_else(|| "?".into())
        ),
        Err(_) => "unix peer".to_string(),
    }
}

/// 감사 로그용 요청 이름과 변경 요청 여부 (D14). 와일드카드 없음: 새 변형은 여기서 분류해야 컴파일된다.
fn audit_kind(request: &ApiRequest) -> (&'static str, bool) {
    match request {
        ApiRequest::Attach { .. } => ("Attach", true),
        ApiRequest::Detach { .. } => ("Detach", true),
        ApiRequest::AddRule { .. } => ("AddRule", true),
        ApiRequest::DeleteRule { .. } => ("DeleteRule", true),
        ApiRequest::LoadWasmModule { .. } => ("LoadWasmModule", true),
        ApiRequest::UnloadWasmModule { .. } => ("UnloadWasmModule", true),
        ApiRequest::ListRules { .. } => ("ListRules", false),
        ApiRequest::GetStats {} => ("GetStats", false),
        ApiRequest::ListWasmModules {} => ("ListWasmModules", false),
        ApiRequest::WasmModuleStats { .. } => ("WasmModuleStats", false),
    }
}

/// umask 를 잠깐 바꿨다가 Drop 시 복원한다 (에러 경로 포함, D12)
struct UmaskGuard(nix::sys::stat::Mode);

impl UmaskGuard {
    fn set(bits: u32) -> Self {
        use nix::sys::stat::{umask, Mode};
        UmaskGuard(umask(Mode::from_bits_truncate(bits as _)))
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        nix::sys::stat::umask(self.0);
    }
}

/// 부모 디렉토리 준비: 없으면 0755 로 하나만 만든다(비재귀, D8). 있는데 디렉토리가 아니면 에러.
fn ensure_parent_dir(path: &Path) -> Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Ok(()),
    };
    match std::fs::metadata(parent) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(anyhow!("{} exists and is not a directory", parent.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o755)
                .create(parent)
                .with_context(|| format!("Failed to create API socket directory {}", parent.display()))?;
            // umask 와 무관하게 0755 로 고정한다
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
                .with_context(|| format!("Failed to set mode on {}", parent.display()))?;
            Ok(())
        }
        Err(e) => Err(anyhow!(e).context(format!("Failed to inspect {}", parent.display()))),
    }
}

/// 경로에 이미 무언가 있으면 처리한다 (D11): 살아 있는 소켓 → 에러, stale 소켓 → 삭제, 소켓 아님 → 에러(보존).
fn clear_stale_socket(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow!(e).context(format!("Failed to inspect {}", path.display()))),
    };
    if !meta.file_type().is_socket() {
        return Err(anyhow!(
            "{} exists and is not a socket; refusing to remove it",
            path.display()
        ));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(anyhow!(
            "API socket {} is already in use by another swift-guard-daemon \
             (stop it first, e.g. sudo systemctl stop swift-guard)",
            path.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path)
                .with_context(|| format!("Failed to remove stale API socket {}", path.display()))?;
            info!("removed stale API socket {}", path.display());
            Ok(())
        }
        Err(e) => Err(anyhow!(e).context(format!("Failed to probe existing API socket {}", path.display()))),
    }
}

/// 소켓 그룹·권한 설정 (D7): 그룹이 있고 chown 이 성공해야 0660, 아니면 0600(root 전용) 유지 + 경고.
/// 반환값: 실제 적용된 모드
fn apply_socket_group(path: &Path, group: &str) -> u32 {
    use nix::unistd::{chown, Group};
    let root_only = |path: &Path| {
        info!("API server listening on unix:{} (mode 0600, root only)", path.display());
        0o600
    };
    match Group::from_name(group) {
        Ok(Some(g)) => match chown(path, None, Some(g.gid)) {
            Ok(()) => match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)) {
                Ok(()) => {
                    info!(
                        "API server listening on unix:{} (mode 0660, group {})",
                        path.display(),
                        group
                    );
                    0o660
                }
                Err(e) => {
                    warn!("cannot set group '{}' on {}: {}; API socket is root-only", group, path.display(), e);
                    root_only(path)
                }
            },
            Err(e) => {
                warn!("cannot set group '{}' on {}: {}; API socket is root-only", group, path.display(), e);
                root_only(path)
            }
        },
        Ok(None) => {
            warn!(
                "group '{}' not found: API socket {} is root-only (create it with: sudo groupadd --system {})",
                group,
                path.display(),
                group
            );
            root_only(path)
        }
        Err(e) => {
            warn!("cannot set group '{}' on {}: {}; API socket is root-only", group, path.display(), e);
            root_only(path)
        }
    }
}

/// API endpoint 에 bind 한다 (C-4). main 은 BPF 로드 전에 호출해 중복 기동을 먼저 거부한다 (D13).
pub async fn bind_api(endpoint: &ApiEndpoint, group: &str) -> Result<ApiListener> {
    match endpoint {
        ApiEndpoint::Unix(path) => {
            ensure_parent_dir(path)?;
            clear_stale_socket(path)?;
            let std_listener = {
                // 0600 으로 생성 → chown → chmod 0660. 권한 설정 전 틈에도 root 외 접속 불가 (D12)
                let _umask = UmaskGuard::set(0o177);
                std::os::unix::net::UnixListener::bind(path)
                    .with_context(|| format!("Failed to bind API socket {}", path.display()))?
            };
            let meta = std::fs::symlink_metadata(path)
                .with_context(|| format!("Failed to stat API socket {}", path.display()))?;
            let cleanup = SocketCleanup {
                path: path.clone(),
                dev: meta.dev(),
                ino: meta.ino(),
            };
            std_listener
                .set_nonblocking(true)
                .context("Failed to set API socket non-blocking")?;
            let listener = UnixListener::from_std(std_listener).context("Failed to register API socket")?;
            apply_socket_group(path, group);
            Ok(ApiListener::Unix {
                listener,
                _cleanup: cleanup,
            })
        }
        ApiEndpoint::Tcp(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("Failed to bind to tcp:{}", addr))?;
            warn!(
                "TCP API enabled on tcp:{}: no authentication, any local user can change rules",
                addr
            );
            info!("API server listening on tcp:{}", addr);
            Ok(ApiListener::Tcp(listener))
        }
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
async fn serve<F>(listener: ApiListener, wasm: Arc<WasmManager>, mut handle_bpf: F) -> Result<()>
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
                Ok((conn, peer)) => {
                    let permit = match conn_permits.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            debug!("Rejecting connection from {}: connection limit reached", peer);
                            reject_busy(conn);
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
                        let r = match conn {
                            ApiConn::Unix(s) => handle_connection(s, &peer, wasm, bpf_tx, load_permits).await,
                            ApiConn::Tcp(s) => handle_connection(s, &peer, wasm, bpf_tx, load_permits).await,
                        };
                        if let Err(e) = r {
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
async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
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
async fn handle_connection<S>(
    mut stream: S,
    peer: &str,
    wasm: Arc<WasmManager>,
    bpf_tx: mpsc::Sender<BpfJob>,
    load_permits: Arc<Semaphore>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
                    // D14 감사: 변경 요청은 info 한 줄(페이로드 제외), 조회는 debug
                    match audit_kind(&request) {
                        (kind, true) => info!("API {} from {}", kind, peer),
                        (kind, false) => debug!("API {} from {}", kind, peer),
                    }
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
        map_manager: Arc<Mutex<MapManager>>,
        attach: Arc<Mutex<XdpAttachManager>>,
        telemetry: Arc<TelemetryCollector>,
        wasm: Arc<WasmManager>,
    ) -> Self {
        Self {
            map_manager,
            attach,
            telemetry,
            wasm,
        }
    }

    /// bind 된 리스너(`bind_api`)로 서버 실행 (무한 루프). main 태스크에서 폴링된다.
    /// 이 future 가 drop 되면 리스너도 drop 되어 Unix 소켓이 삭제된다.
    pub async fn run(&self, listener: ApiListener) -> Result<()> {
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

                // 미구현 필드(priority/rate_limit/expire)는 0만 허용,
                // N-5/N-6: action/protocol 범위, redirect_if 와 action 의 짝
                validate_add_rule(
                    action,
                    protocol,
                    redirect_if.as_deref(),
                    priority,
                    rate_limit,
                    expire,
                )?;

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
                // 총계는 요청 시점에 맵에서(룰 매치 stats_map + XDP 전체 xdp_stats_map, 같은 잠금 안),
                // 비율은 텔레메트리 마지막 계산값. 맵 읽기 실패는 GetStats 전체 Error.
                let ((total_packets, total_bytes), xdp) = {
                    let mm = lock(&self.map_manager, "map_manager")?;
                    (mm.get_stats()?, mm.get_xdp_counters()?)
                };
                let (packets_per_sec, mbps) = self.telemetry.rates()?;
                Ok(ApiResponse::Stats {
                    stats: SystemStats {
                        total_packets,
                        total_bytes,
                        packets_per_sec,
                        mbps,
                        xdp: Some(xdp),
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
                assert!(validate_add_rule(action, proto, None, 0, 0, 0).is_ok());
            }
        }
        assert!(validate_add_rule(ACTION_REDIRECT, 6, Some("eth1"), 0, 0, 0).is_ok());
    }

    #[test]
    fn rejects_invalid_action() {
        for action in [0u8, 5, 255] {
            let e = validate_add_rule(action, 255, None, 0, 0, 0).unwrap_err();
            assert!(format!("{:#}", e).contains("invalid action"));
        }
    }

    #[test]
    fn rejects_invalid_protocol() {
        for proto in [0u8, 2, 7, 18, 254] {
            let e = validate_add_rule(2, proto, None, 0, 0, 0).unwrap_err();
            assert!(format!("{:#}", e).contains("invalid protocol"));
        }
    }

    #[test]
    fn redirect_requires_ifname() {
        let e = validate_add_rule(ACTION_REDIRECT, 255, None, 0, 0, 0).unwrap_err();
        assert!(format!("{:#}", e).contains("requires redirect_if"));
    }

    #[test]
    fn rejects_redirect_if_without_redirect_action() {
        for action in [1u8, 2, 4] {
            let e = validate_add_rule(action, 255, Some("eth1"), 0, 0, 0).unwrap_err();
            assert!(format!("{:#}", e).contains("only allowed with the redirect action"));
        }
    }

    #[test]
    fn rejects_unimplemented_fields_with_exact_message() {
        let msg = |p, r, e| format!("{:#}", validate_add_rule(2, 255, None, p, r, e).unwrap_err());
        assert_eq!(msg(5, 0, 0), "priority is not implemented yet: only 0 is accepted (got 5)");
        assert_eq!(msg(0, 100, 0), "rate_limit is not implemented yet: only 0 is accepted (got 100)");
        assert_eq!(msg(0, 0, 60), "expire is not implemented yet: only 0 is accepted (got 60)");
    }

    #[test]
    fn unimplemented_fields_zero_accepted() {
        assert!(validate_add_rule(2, 6, None, 0, 0, 0).is_ok());
        assert!(validate_add_rule(ACTION_REDIRECT, 17, Some("eth1"), 0, 0, 0).is_ok());
    }

    #[test]
    fn validation_order_reports_first_failure_only() {
        let msg = |a, pr, ri: Option<&str>, p, r, e| {
            format!("{:#}", validate_add_rule(a, pr, ri, p, r, e).unwrap_err())
        };
        // priority > rate_limit > expire
        assert!(msg(2, 255, None, 1, 2, 3).starts_with("priority is not implemented"));
        assert!(msg(2, 255, None, 0, 2, 3).starts_with("rate_limit is not implemented"));
        // 미구현 필드가 action/protocol/redirect 보다 먼저
        assert!(msg(9, 0, None, 0, 0, 3).starts_with("expire is not implemented"));
        assert!(msg(ACTION_REDIRECT, 255, None, 7, 0, 0).starts_with("priority is not implemented"));
        assert!(msg(9, 255, None, 0, 0, 0).contains("invalid action"));
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
        tokio::spawn(serve(ApiListener::Tcp(listener), wasm.clone(), fake_bpf));

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
            r = serve(ApiListener::Tcp(listener), wasm.clone(), fake_bpf) => format!("server stopped: {:?}", r),
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
        tokio::spawn(serve(ApiListener::Tcp(listener), Arc::new(WasmManager::new()), fake_bpf));

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
        tokio::spawn(serve(ApiListener::Tcp(listener), Arc::new(WasmManager::new()), fake_bpf));

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
        tokio::spawn(serve(ApiListener::Tcp(listener), Arc::new(WasmManager::new()), fake_bpf));

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

    // ---- C-4: Unix 소켓 전송·수명·권한 (BPF 불필요) ----

    fn unix_test_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sg_srv_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const NO_GROUP: &str = "sg-no-such-group-for-test";

    async fn call_unix(path: &Path, req: &ApiRequest) -> ApiResponse {
        let mut s = UnixStream::connect(path).await.unwrap();
        let body = serde_json::to_vec(req).unwrap();
        s.write_all(&(body.len() as u32).to_be_bytes()).await.unwrap();
        s.write_all(&body).await.unwrap();
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await.unwrap();
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await.unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unix_round_trip_and_cleanup_on_drop() {
        let d = unix_test_dir("rt");
        let sock = d.join("api.sock");
        let listener = bind_api(&ApiEndpoint::Unix(sock.clone()), NO_GROUP).await.unwrap();
        let server = tokio::spawn(serve(listener, Arc::new(WasmManager::new()), fake_bpf));
        let r = call_unix(&sock, &ApiRequest::ListRules { include_stats: false }).await;
        assert!(matches!(r, ApiResponse::Success { ref message } if message == "bpf:true"), "{:?}", r);
        let r = call_unix(&sock, &ApiRequest::ListWasmModules {}).await;
        assert!(matches!(r, ApiResponse::WasmModules { .. }), "{:?}", r);
        // serve future 를 버리면 리스너와 guard 가 drop 되어 소켓이 지워진다
        server.abort();
        let _ = server.await;
        assert!(!sock.exists(), "socket must be removed on shutdown");
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn creates_missing_parent_dir_0755() {
        let d = unix_test_dir("mkdir");
        let sock = d.join("sub").join("api.sock");
        let l = bind_api(&ApiEndpoint::Unix(sock.clone()), NO_GROUP).await.unwrap();
        assert_eq!(mode_of(&d.join("sub")), 0o755);
        assert!(sock.exists());
        drop(l);
        // 조부모가 없으면 에러 (비재귀)
        let deep = d.join("a").join("b").join("api.sock");
        assert!(bind_api(&ApiEndpoint::Unix(deep), NO_GROUP).await.is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stale_socket_is_replaced() {
        let d = unix_test_dir("stale");
        let sock = d.join("api.sock");
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap()); // 리스너 없는 소켓 파일
        assert!(sock.exists());
        let l = bind_api(&ApiEndpoint::Unix(sock.clone()), NO_GROUP).await.unwrap();
        tokio::spawn(serve(l, Arc::new(WasmManager::new()), fake_bpf));
        let r = call_unix(&sock, &ApiRequest::GetStats {}).await;
        assert!(matches!(r, ApiResponse::Success { .. }), "{:?}", r);
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_socket_is_in_use() {
        let d = unix_test_dir("inuse");
        let sock = d.join("api.sock");
        let first = bind_api(&ApiEndpoint::Unix(sock.clone()), NO_GROUP).await.unwrap();
        let e = format!("{:#}", bind_api(&ApiEndpoint::Unix(sock.clone()), NO_GROUP).await.unwrap_err());
        assert_eq!(
            e,
            format!(
                "API socket {} is already in use by another swift-guard-daemon \
                 (stop it first, e.g. sudo systemctl stop swift-guard)",
                sock.display()
            )
        );
        // 실패한 두 번째 시도가 첫 번째 소켓을 지우지 않는다
        assert!(sock.exists());
        drop(first);
        assert!(!sock.exists());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn regular_file_is_refused_and_preserved() {
        let d = unix_test_dir("file");
        let sock = d.join("api.sock");
        std::fs::write(&sock, b"keep me").unwrap();
        let e = format!("{:#}", bind_api(&ApiEndpoint::Unix(sock.clone()), NO_GROUP).await.unwrap_err());
        assert_eq!(e, format!("{} exists and is not a socket; refusing to remove it", sock.display()));
        assert_eq!(std::fs::read(&sock).unwrap(), b"keep me");
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_group_leaves_socket_root_only() {
        let d = unix_test_dir("nogrp");
        let sock = d.join("api.sock");
        // 사용자 umask 가 느슨해도 0600 이어야 한다
        let old = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o000));
        let l = bind_api(&ApiEndpoint::Unix(sock.clone()), NO_GROUP).await;
        nix::sys::stat::umask(old);
        let _l = l.unwrap();
        assert_eq!(mode_of(&sock), 0o600);
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn existing_group_sets_0660_and_gid() {
        let gid = nix::unistd::getegid();
        let group = match nix::unistd::Group::from_gid(gid) {
            Ok(Some(g)) => g.name,
            _ => {
                eprintln!("skip: no group name for egid {}", gid);
                return;
            }
        };
        let d = unix_test_dir("grp");
        let sock = d.join("api.sock");
        let _l = bind_api(&ApiEndpoint::Unix(sock.clone()), &group).await.unwrap();
        assert_eq!(mode_of(&sock), 0o660);
        assert_eq!(std::fs::symlink_metadata(&sock).unwrap().gid(), gid.as_raw());
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn guard_does_not_remove_replaced_socket() {
        let d = unix_test_dir("replaced");
        let sock = d.join("api.sock");
        let l = bind_api(&ApiEndpoint::Unix(sock.clone()), NO_GROUP).await.unwrap();
        std::fs::remove_file(&sock).unwrap();
        let _other = std::os::unix::net::UnixListener::bind(&sock).unwrap(); // 다른 프로세스의 소켓
        drop(l);
        assert!(sock.exists(), "must not remove a socket it did not create");
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unix_peer_label_has_uid() {
        let (a, _b) = UnixStream::pair().unwrap();
        let label = unix_peer_label(&a);
        assert!(label.starts_with(&format!("uid={} gid=", nix::unistd::geteuid())), "{}", label);
        assert!(label.contains(&format!("pid={}", std::process::id())), "{}", label);
    }

    #[test]
    fn audit_kind_classifies_mutations() {
        assert_eq!(audit_kind(&ApiRequest::Detach { interface: "x".into() }), ("Detach", true));
        assert_eq!(audit_kind(&ApiRequest::DeleteRule { label: "x".into() }), ("DeleteRule", true));
        assert_eq!(audit_kind(&ApiRequest::UnloadWasmModule { name: "x".into() }), ("UnloadWasmModule", true));
        assert_eq!(audit_kind(&ApiRequest::GetStats {}), ("GetStats", false));
        assert_eq!(audit_kind(&ApiRequest::ListRules { include_stats: true }), ("ListRules", false));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unix_connection_limit_rejects_without_waiting() {
        let d = unix_test_dir("busy");
        let sock = d.join("api.sock");
        let l = bind_api(&ApiEndpoint::Unix(sock.clone()), NO_GROUP).await.unwrap();
        tokio::spawn(serve(l, Arc::new(WasmManager::new()), fake_bpf));
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            idle.push(UnixStream::connect(&sock).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut s = UnixStream::connect(&sock).await.unwrap();
        let r = timeout(Duration::from_secs(2), async {
            let mut len = [0u8; 4];
            s.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).await.unwrap();
            serde_json::from_slice::<ApiResponse>(&buf).unwrap()
        })
        .await
        .expect("over-limit connection must be answered immediately");
        assert!(matches!(r, ApiResponse::Error { ref message } if message.contains("server busy")), "{:?}", r);
        drop(idle);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r = call_unix(&sock, &ApiRequest::GetStats {}).await;
        assert!(matches!(r, ApiResponse::Success { .. }), "{:?}", r);
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_endpoint_binds_loopback() {
        // 포트 0(임시 포트)은 파서가 거부하므로 테스트에서는 ApiEndpoint::Tcp 를 직접 만든다
        let l = bind_api(&ApiEndpoint::Tcp("127.0.0.1:0".parse().unwrap()), "ignored").await.unwrap();
        let addr = match &l {
            ApiListener::Tcp(t) => t.local_addr().unwrap(),
            _ => panic!("expected tcp"),
        };
        tokio::spawn(serve(l, Arc::new(WasmManager::new()), fake_bpf));
        let r = call(addr, &ApiRequest::GetStats {}).await;
        assert!(matches!(r, ApiResponse::Success { .. }), "{:?}", r);
    }
}
