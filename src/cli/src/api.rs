//! API 클라이언트 모듈
//! 데몬과 통신하기 위한 API 클라이언트 구현
//! 요청/응답 타입은 swift_guard_common::api 가 원천이다(복제 없음).
//! 주소 문법·기본값은 swift_guard_common::endpoint 가 원천이다.
//! 전송: 기본 Unix 소켓(/run/swift-guard/api.sock), `tcp:` 루프백 옵트인. 프레이밍은 [u32 BE 길이][JSON].

use anyhow::{anyhow, Result};
use std::io::ErrorKind;
use swift_guard_common::api::{ApiRequest, ApiResponse};
use swift_guard_common::endpoint::{ApiEndpoint, DEFAULT_API_GROUP};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// 연결 실패 안내에 쓰는 daemon 기동 명령
const DAEMON_START_HINT: &str =
    "Start it with: sudo swift-guard-daemon --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o";

/// 연결 실패 문구 (고정 계약 C-5: 테스트·문서가 부분 문자열을 grep 한다)
pub fn connect_error_message(endpoint: &ApiEndpoint, err: &std::io::Error) -> String {
    let detail = match (err.kind(), endpoint) {
        (ErrorKind::PermissionDenied, _) => format!(
            "permission denied. Run the command with sudo, or join the '{g}' group: \
             sudo usermod -aG {g} $USER (then log out and back in)",
            g = DEFAULT_API_GROUP
        ),
        (ErrorKind::NotFound, ApiEndpoint::Unix(path)) => format!(
            "daemon is not running (no socket at {}). {}",
            path.display(),
            DAEMON_START_HINT
        ),
        (ErrorKind::ConnectionRefused, _) => {
            format!("daemon is not running (connection refused). {}", DAEMON_START_HINT)
        }
        _ => err.to_string(),
    };
    format!("Failed to connect to API server at {}: {}", endpoint, detail)
}

/// API 클라이언트
#[derive(Debug)]
pub struct ApiClient {
    endpoint: ApiEndpoint,
}

impl ApiClient {
    /// 새로운 API 클라이언트 생성
    pub fn new(endpoint: ApiEndpoint) -> Self {
        Self { endpoint }
    }

    /// 요청 전송 및 응답 수신
    pub async fn send_request(&self, request: &ApiRequest) -> Result<ApiResponse> {
        let map_err = |e: std::io::Error| anyhow!(connect_error_message(&self.endpoint, &e));
        match &self.endpoint {
            ApiEndpoint::Unix(path) => {
                let stream = UnixStream::connect(path).await.map_err(map_err)?;
                exchange(stream, request).await
            }
            ApiEndpoint::Tcp(addr) => {
                let stream = TcpStream::connect(addr).await.map_err(map_err)?;
                exchange(stream, request).await
            }
        }
    }
}

/// 요청 하나를 보내고 응답 하나를 받는다: [u32 BE 길이][JSON]
async fn exchange<S>(mut stream: S, request: &ApiRequest) -> Result<ApiResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_bytes = serde_json::to_vec(request)
        .map_err(|e| anyhow!("Failed to serialize request: {}", e))?;

    let len = request_bytes.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| anyhow!("Failed to send request length: {}", e))?;
    stream
        .write_all(&request_bytes)
        .await
        .map_err(|e| anyhow!("Failed to send request: {}", e))?;

    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .map_err(|e| anyhow!("Failed to receive response length: {}", e))?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    let mut response_bytes = vec![0u8; len];
    stream
        .read_exact(&mut response_bytes)
        .await
        .map_err(|e| anyhow!("Failed to receive response: {}", e))?;

    serde_json::from_slice(&response_bytes)
        .map_err(|e| anyhow!("Failed to deserialize response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;

    fn unix(p: &str) -> ApiEndpoint {
        ApiEndpoint::Unix(p.into())
    }

    #[test]
    fn permission_denied_message() {
        let m = connect_error_message(
            &unix("/run/swift-guard/api.sock"),
            &Error::from(ErrorKind::PermissionDenied),
        );
        assert_eq!(
            m,
            "Failed to connect to API server at unix:/run/swift-guard/api.sock: permission denied. \
             Run the command with sudo, or join the 'swift-guard' group: \
             sudo usermod -aG swift-guard $USER (then log out and back in)"
        );
        for needle in ["permission denied", "sudo", "usermod -aG swift-guard"] {
            assert!(m.contains(needle), "{}", needle);
        }
    }

    #[test]
    fn not_found_message() {
        let m = connect_error_message(&unix("/run/x/api.sock"), &Error::from(ErrorKind::NotFound));
        assert_eq!(
            m,
            "Failed to connect to API server at unix:/run/x/api.sock: daemon is not running \
             (no socket at /run/x/api.sock). Start it with: sudo swift-guard-daemon \
             --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o"
        );
    }

    #[test]
    fn connection_refused_message() {
        let tcp: ApiEndpoint = "tcp:127.0.0.1:7654".parse().unwrap();
        let m = connect_error_message(&tcp, &Error::from(ErrorKind::ConnectionRefused));
        assert_eq!(
            m,
            "Failed to connect to API server at tcp:127.0.0.1:7654: daemon is not running \
             (connection refused). Start it with: sudo swift-guard-daemon \
             --bpf-obj /usr/local/lib/swift-guard/xdp_filter.o"
        );
        // stale 소켓(리스너 없음)도 ConnectionRefused 다
        let m = connect_error_message(&unix("/tmp/s"), &Error::from(ErrorKind::ConnectionRefused));
        assert!(m.contains("daemon is not running (connection refused)"));
    }

    #[test]
    fn other_error_message() {
        let e = Error::new(ErrorKind::Other, "boom");
        assert_eq!(
            connect_error_message(&unix("/tmp/s"), &e),
            "Failed to connect to API server at unix:/tmp/s: boom"
        );
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sg_cli_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn missing_socket_reports_daemon_not_running() {
        let d = temp_dir("missing");
        let sock = d.join("none.sock");
        let client = ApiClient::new(ApiEndpoint::Unix(sock.clone()));
        let e = client.send_request(&ApiRequest::GetStats {}).await.unwrap_err();
        let m = format!("{:#}", e);
        assert!(m.contains("daemon is not running"), "{}", m);
        assert!(m.contains(&sock.display().to_string()), "{}", m);
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn stale_socket_reports_connection_refused() {
        let d = temp_dir("stale");
        let sock = d.join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap()); // 파일만 남는다
        let client = ApiClient::new(ApiEndpoint::Unix(sock));
        let m = format!("{:#}", client.send_request(&ApiRequest::GetStats {}).await.unwrap_err());
        assert!(m.contains("daemon is not running (connection refused)"), "{}", m);
        let _ = std::fs::remove_dir_all(d);
    }

    /// 쓰기 권한 없는 소켓 → PermissionDenied 문구. root 는 권한 검사를 우회하므로 건너뛴다.
    #[tokio::test]
    async fn unwritable_socket_reports_permission_denied() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = temp_dir("perm");
        // 방금 만든 디렉토리의 소유자 = 실효 uid
        if std::fs::metadata(&d).unwrap().uid() == 0 {
            eprintln!("skip: running as root");
            let _ = std::fs::remove_dir_all(d);
            return;
        }
        let sock = d.join("locked.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o000)).unwrap();
        let client = ApiClient::new(ApiEndpoint::Unix(sock));
        let m = format!("{:#}", client.send_request(&ApiRequest::GetStats {}).await.unwrap_err());
        assert!(m.contains("permission denied"), "{}", m);
        assert!(m.contains("sudo"), "{}", m);
        let _ = std::fs::remove_dir_all(d);
    }

    /// Unix 소켓 왕복: 프레이밍이 TCP 와 같은지
    #[tokio::test]
    async fn unix_round_trip() {
        let d = temp_dir("rt");
        let sock = d.join("rt.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut len = [0u8; 4];
            s.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).await.unwrap();
            let req: ApiRequest = serde_json::from_slice(&buf).unwrap();
            let body = serde_json::to_vec(&ApiResponse::Success {
                message: format!("{:?}", req),
            })
            .unwrap();
            s.write_all(&(body.len() as u32).to_be_bytes()).await.unwrap();
            s.write_all(&body).await.unwrap();
        });
        let client = ApiClient::new(ApiEndpoint::Unix(sock));
        match client.send_request(&ApiRequest::GetStats {}).await.unwrap() {
            ApiResponse::Success { message } => assert!(message.contains("GetStats"), "{}", message),
            other => panic!("unexpected {:?}", other),
        }
        let _ = std::fs::remove_dir_all(d);
    }
}
