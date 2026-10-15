//! daemon API 주소(endpoint) 문법 — CLI(`--api-server`)와 daemon(`--api-addr`)이 공유하는 SSOT.
//!
//! - `unix:/절대/경로` 또는 `/절대/경로`(unix: 생략형): Unix 도메인 소켓 (기본값)
//! - `tcp:<루프백 IP>:<포트>`: 옵트인 TCP. API 에 인증이 없으므로 루프백(127.0.0.0/8, ::1)만 허용한다.
//! - 접두사 없는 `host:port` 는 옛 형식이다. 조용히 무인증 TCP 로 돌지 않도록 거부하고 `tcp:` 를 안내한다.
//!
//! 에러 문구는 테스트·문서가 의존하는 고정 계약이다(계획 C-1).

use anyhow::{anyhow, Result};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

/// 기본 API 소켓 경로
pub const DEFAULT_API_SOCKET: &str = "/run/swift-guard/api.sock";
/// 기본 API endpoint (CLI·daemon 기본값)
pub const DEFAULT_API_ENDPOINT: &str = "unix:/run/swift-guard/api.sock";
/// 기본 API 소켓 그룹 (Makefile install-group 과 같은 이름)
pub const DEFAULT_API_GROUP: &str = "swift-guard";
/// Unix 소켓 경로 최대 바이트 (sun_path 108 - NUL)
pub const MAX_UNIX_PATH_BYTES: usize = 107;

/// daemon API 주소
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiEndpoint {
    Unix(PathBuf),
    Tcp(SocketAddr),
}

impl ApiEndpoint {
    /// 기본 endpoint (`unix:/run/swift-guard/api.sock`)
    pub fn default_unix() -> Self {
        ApiEndpoint::Unix(PathBuf::from(DEFAULT_API_SOCKET))
    }
}

fn parse_unix(s: &str, path: &str) -> Result<ApiEndpoint> {
    if !path.starts_with('/') {
        return Err(anyhow!(
            "invalid API address '{}': Unix socket path must be absolute",
            s
        ));
    }
    if path.len() > MAX_UNIX_PATH_BYTES {
        return Err(anyhow!(
            "invalid API address '{}': Unix socket path is too long (max {} bytes)",
            s,
            MAX_UNIX_PATH_BYTES
        ));
    }
    Ok(ApiEndpoint::Unix(PathBuf::from(path)))
}

fn parse_tcp(s: &str, addr: &str) -> Result<ApiEndpoint> {
    let addr: SocketAddr = addr.parse().map_err(|_| {
        anyhow!(
            "invalid API address '{}': expected tcp:<loopback-ip>:<port>, e.g. tcp:127.0.0.1:7654",
            s
        )
    })?;
    if addr.port() == 0 {
        return Err(anyhow!("invalid API address '{}': port must be 1-65535", s));
    }
    if !addr.ip().is_loopback() {
        return Err(anyhow!(
            "refusing non-loopback TCP API address '{}': the API has no authentication; \
             use 127.0.0.1 or ::1, or the default Unix socket",
            s
        ));
    }
    Ok(ApiEndpoint::Tcp(addr))
}

impl FromStr for ApiEndpoint {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Some(path) = s.strip_prefix("unix:") {
            return parse_unix(s, path);
        }
        if s.starts_with('/') {
            return parse_unix(s, s);
        }
        if let Some(addr) = s.strip_prefix("tcp:") {
            return parse_tcp(s, addr);
        }
        if s.parse::<SocketAddr>().is_ok() {
            return Err(anyhow!(
                "invalid API address '{s}': add a scheme: tcp:{s} (loopback only, no access control) \
                 or unix:{DEFAULT_API_SOCKET}"
            ));
        }
        Err(anyhow!(
            "invalid API address '{}': expected unix:/path/to/socket or tcp:<loopback-ip>:<port>",
            s
        ))
    }
}

impl fmt::Display for ApiEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiEndpoint::Unix(p) => write!(f, "unix:{}", p.display()),
            // SocketAddr 의 Display 는 IPv6 를 [::1]:port 로 쓴다
            ApiEndpoint::Tcp(a) => write!(f, "tcp:{}", a),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(s: &str) -> String {
        format!("{:#}", s.parse::<ApiEndpoint>().unwrap_err())
    }

    #[test]
    fn default_constants_agree() {
        assert_eq!(DEFAULT_API_ENDPOINT, format!("unix:{}", DEFAULT_API_SOCKET));
        assert_eq!(
            DEFAULT_API_ENDPOINT.parse::<ApiEndpoint>().unwrap(),
            ApiEndpoint::default_unix()
        );
    }

    #[test]
    fn accepts_valid_addresses() {
        let ok = |s: &str| s.parse::<ApiEndpoint>().unwrap();
        assert_eq!(ok("unix:/run/x.sock"), ApiEndpoint::Unix("/run/x.sock".into()));
        assert_eq!(ok("/tmp/a.sock"), ApiEndpoint::Unix("/tmp/a.sock".into()));
        assert_eq!(ok("tcp:127.0.0.1:7654"), ApiEndpoint::Tcp("127.0.0.1:7654".parse().unwrap()));
        assert_eq!(ok("tcp:127.1.2.3:1"), ApiEndpoint::Tcp("127.1.2.3:1".parse().unwrap()));
        assert_eq!(ok("tcp:[::1]:7654"), ApiEndpoint::Tcp("[::1]:7654".parse().unwrap()));
        // 경계: 107바이트 경로는 허용
        let p = format!("/{}", "a".repeat(MAX_UNIX_PATH_BYTES - 1));
        assert_eq!(ok(&p), ApiEndpoint::Unix(p.clone().into()));
    }

    #[test]
    fn rejects_relative_unix_path() {
        assert_eq!(
            err("unix:rel.sock"),
            "invalid API address 'unix:rel.sock': Unix socket path must be absolute"
        );
    }

    #[test]
    fn rejects_too_long_unix_path() {
        let p = format!("unix:/{}", "a".repeat(MAX_UNIX_PATH_BYTES)); // 108 바이트 경로
        assert_eq!(
            err(&p),
            format!("invalid API address '{}': Unix socket path is too long (max 107 bytes)", p)
        );
        let bare = format!("/{}", "b".repeat(MAX_UNIX_PATH_BYTES));
        assert!(err(&bare).contains("too long"));
    }

    #[test]
    fn rejects_non_loopback_tcp() {
        for s in ["tcp:0.0.0.0:7654", "tcp:192.0.2.1:7654", "tcp:[::]:7654"] {
            assert_eq!(
                err(s),
                format!(
                    "refusing non-loopback TCP API address '{}': the API has no authentication; \
                     use 127.0.0.1 or ::1, or the default Unix socket",
                    s
                )
            );
        }
    }

    #[test]
    fn rejects_tcp_hostname_and_port_zero() {
        assert_eq!(
            err("tcp:localhost:7654"),
            "invalid API address 'tcp:localhost:7654': expected tcp:<loopback-ip>:<port>, e.g. tcp:127.0.0.1:7654"
        );
        assert_eq!(
            err("tcp:127.0.0.1:0"),
            "invalid API address 'tcp:127.0.0.1:0': port must be 1-65535"
        );
    }

    #[test]
    fn rejects_schemeless_host_port_with_hint() {
        assert_eq!(
            err("127.0.0.1:7654"),
            "invalid API address '127.0.0.1:7654': add a scheme: tcp:127.0.0.1:7654 \
             (loopback only, no access control) or unix:/run/swift-guard/api.sock"
        );
    }

    #[test]
    fn rejects_garbage() {
        for s in ["foo", "", "http://127.0.0.1:7654"] {
            assert_eq!(
                err(s),
                format!(
                    "invalid API address '{}': expected unix:/path/to/socket or tcp:<loopback-ip>:<port>",
                    s
                )
            );
        }
    }

    #[test]
    fn display_round_trip() {
        for (input, shown) in [
            ("unix:/run/swift-guard/api.sock", "unix:/run/swift-guard/api.sock"),
            ("/tmp/a.sock", "unix:/tmp/a.sock"),
            ("tcp:127.0.0.1:7654", "tcp:127.0.0.1:7654"),
            ("tcp:[::1]:7654", "tcp:[::1]:7654"),
        ] {
            let e: ApiEndpoint = input.parse().unwrap();
            assert_eq!(e.to_string(), shown);
            assert_eq!(shown.parse::<ApiEndpoint>().unwrap(), e);
        }
    }
}
