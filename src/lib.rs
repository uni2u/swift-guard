//! Swift-Guard: 적응형 네트워크 보안 프레임워크
//!
//! 본 라이브러리는 eBPF/XDP 기반 패킷 처리와 WebAssembly 기반 심층 검사를 
//! 통합하여 클라우드 네이티브 환경에 최적화된 보안 솔루션을 제공합니다.

pub mod common;
pub mod xdp;
pub mod wasm;

/// Swift-Guard 라이브러리 버전
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// 초기화 및 로깅 설정
pub fn init() {
    env_logger::init();
    log::info!("Swift-Guard v{} initialized", VERSION);
}
