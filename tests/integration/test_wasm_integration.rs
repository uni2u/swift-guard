// Swift-Guard WASM 통합 테스트

use std::process::Command;
use std::thread;
use std::time::Duration;
use std::path::Path;
use std::fs;

#[test]
#[ignore]  // 실제 실행시 --ignored 플래그로 실행
fn test_wasm_module_lifecycle() {
    // 이 테스트는 로컬 시스템에 루트 권한이 필요하므로 CI 환경에서는 스킵됩니다.
    if !has_root_privileges() {
        println!("Skipping test_wasm_module_lifecycle: root privileges required");
        return;
    }

    // 테스트 WASM 모듈이 있는지 확인
    let wasm_module_path = "wasm/modules/http_inspector.wasm";
    if !Path::new(wasm_module_path).exists() {
        // 테스트 전에 WASM 모듈 빌드
        let build_output = Command::new("sh")
            .args(&["-c", "cd wasm && ./build.sh"])
            .output()
            .expect("Failed to build WASM module");

        assert!(build_output.status.success(), "WASM build failed: {}",
                String::from_utf8_lossy(&build_output.stderr));
    }

    // 대몬 시작
    let daemon_handle = start_daemon();
    thread::sleep(Duration::from_secs(2)); // 대몬 시작 대기

    // WASM 모듈 로드
    let load_output = Command::new("sudo")
        .args(&[
            "target/debug/xdp-filter", "wasm", "load",
            "--name", "http-inspector",
            "--file", wasm_module_path
        ])
        .output()
        .expect("Failed to execute wasm load command");

    assert!(load_output.status.success(), "WASM load command failed: {}",
            String::from_utf8_lossy(&load_output.stderr));

    // WASM 모듈 목록 확인
    let list_output = Command::new("sudo")
        .args(&["target/debug/xdp-filter", "wasm", "list"])
        .output()
        .expect("Failed to execute wasm list command");

    let output_str = String::from_utf8_lossy(&list_output.stdout);
    assert!(output_str.contains("http-inspector"), "Loaded WASM module not found in list");

    // WASM 모듈 통계 확인
    let stats_output = Command::new("sudo")
        .args(&[
            "target/debug/xdp-filter", "wasm", "stats",
            "--name", "http-inspector"
        ])
        .output()
        .expect("Failed to execute wasm stats command");

    assert!(stats_output.status.success(), "WASM stats command failed: {}",
            String::from_utf8_lossy(&stats_output.stderr));

    // WASM 모듈 언로드
    let unload_output = Command::new("sudo")
        .args(&[
            "target/debug/xdp-filter", "wasm", "unload",
            "--name", "http-inspector"
        ])
        .output()
        .expect("Failed to execute wasm unload command");

    assert!(unload_output.status.success(), "WASM unload command failed: {}",
            String::from_utf8_lossy(&unload_output.stderr));

    // 모듈이 언로드되었는지 확인
    let list_output = Command::new("sudo")
        .args(&["target/debug/xdp-filter", "wasm", "list"])
        .output()
        .expect("Failed to execute wasm list command");

    let output_str = String::from_utf8_lossy(&list_output.stdout);
    assert!(!output_str.contains("http-inspector"), "WASM module was not unloaded properly");

    // 대몬 종료
    stop_daemon(daemon_handle);
}

// 헬퍼 함수들

// 루트 권한 확인
fn has_root_privileges() -> bool {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .expect("Failed to execute id command");

    let uid = String::from_utf8_lossy(&output.stdout).trim().parse::<u32>().unwrap_or(1000);
    uid == 0
}

// 대몬 시작
fn start_daemon() -> std::process::Child {
    Command::new("sudo")
        .args(&["target/debug/swift-guard-daemon"])
        .spawn()
        .expect("Failed to start daemon")
}

// 대몬 종료
fn stop_daemon(mut daemon_handle: std::process::Child) {
    daemon_handle.kill().expect("Failed to kill daemon");
    daemon_handle.wait().expect("Failed to wait for daemon to exit");
}
