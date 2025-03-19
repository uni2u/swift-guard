// Swift-Guard 기본 필터링 통합 테스트

use std::process::Command;
use std::thread;
use std::time::Duration;

#[test]
#[ignore]  // 실제 실행시 --ignored 플래그로 실행
fn test_attach_detach() {
    // 이 테스트는 로컬 시스템에 루트 권한이 필요하므로 CI 환경에서는 스킵됩니다.
    if !has_root_privileges() {
        println!("Skipping test_attach_detach: root privileges required");
        return;
    }

    // 테스트용 인터페이스가 있는지 확인
    let test_if = "lo";  // 루프백 인터페이스 사용
    if !interface_exists(test_if) {
        panic!("Test interface {} does not exist", test_if);
    }

    // 대몬 시작
    let daemon_handle = start_daemon();
    thread::sleep(Duration::from_secs(2)); // 대몬 시작 대기

    // XDP 프로그램 연결
    let attach_output = Command::new("sudo")
        .args(&["target/debug/xdp-filter", "attach", test_if, "--mode", "generic"])
        .output()
        .expect("Failed to execute attach command");

    assert!(attach_output.status.success(), "Attach command failed: {}", 
            String::from_utf8_lossy(&attach_output.stderr));

    // 연결 확인
    let check_output = Command::new("ip")
        .args(&["link", "show", "dev", test_if])
        .output()
        .expect("Failed to execute ip link command");

    let output_str = String::from_utf8_lossy(&check_output.stdout);
    assert!(output_str.contains("xdp"), "XDP program not attached to interface");

    // XDP 프로그램 분리
    let detach_output = Command::new("sudo")
        .args(&["target/debug/xdp-filter", "detach", test_if])
        .output()
        .expect("Failed to execute detach command");

    assert!(detach_output.status.success(), "Detach command failed: {}",
            String::from_utf8_lossy(&detach_output.stderr));

    // 대몬 종료
    stop_daemon(daemon_handle);
}

#[test]
#[ignore]
fn test_rule_management() {
    // 이 테스트는 로컬 시스템에 루트 권한이 필요하므로 CI 환경에서는 스킵됩니다.
    if !has_root_privileges() {
        println!("Skipping test_rule_management: root privileges required");
        return;
    }

    // 테스트용 인터페이스가 있는지 확인
    let test_if = "lo";  // 루프백 인터페이스 사용
    if !interface_exists(test_if) {
        panic!("Test interface {} does not exist", test_if);
    }

    // 대몬 시작
    let daemon_handle = start_daemon();
    thread::sleep(Duration::from_secs(2)); // 대몬 시작 대기

    // XDP 프로그램 연결
    let _ = Command::new("sudo")
        .args(&["target/debug/xdp-filter", "attach", test_if, "--mode", "generic"])
        .output()
        .expect("Failed to execute attach command");

    // 규칙 추가
    let add_rule_output = Command::new("sudo")
        .args(&[
            "target/debug/xdp-filter", "add-rule",
            "--src-ip", "192.168.1.100",
            "--dst-port", "80",
            "--protocol", "tcp",
            "--action", "drop",
            "--label", "test-rule"
        ])
        .output()
        .expect("Failed to execute add-rule command");

    assert!(add_rule_output.status.success(), "Add rule command failed: {}",
            String::from_utf8_lossy(&add_rule_output.stderr));

    // 규칙 목록 조회
    let list_rules_output = Command::new("sudo")
        .args(&["target/debug/xdp-filter", "list-rules"])
        .output()
        .expect("Failed to execute list-rules command");

    let output_str = String::from_utf8_lossy(&list_rules_output.stdout);
    assert!(output_str.contains("test-rule"), "Added rule not found in rules list");

    // 규칙 삭제
    let delete_rule_output = Command::new("sudo")
        .args(&["target/debug/xdp-filter", "delete-rule", "--label", "test-rule"])
        .output()
        .expect("Failed to execute delete-rule command");

    assert!(delete_rule_output.status.success(), "Delete rule command failed: {}",
            String::from_utf8_lossy(&delete_rule_output.stderr));

    // 규칙이 삭제되었는지 확인
    let list_rules_output = Command::new("sudo")
        .args(&["target/debug/xdp-filter", "list-rules"])
        .output()
        .expect("Failed to execute list-rules command");

    let output_str = String::from_utf8_lossy(&list_rules_output.stdout);
    assert!(!output_str.contains("test-rule"), "Rule was not deleted properly");

    // XDP 프로그램 분리
    let _ = Command::new("sudo")
        .args(&["target/debug/xdp-filter", "detach", test_if])
        .output()
        .expect("Failed to execute detach command");

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

// 인터페이스 존재 확인
fn interface_exists(interface: &str) -> bool {
    let output = Command::new("ip")
        .args(&["link", "show", "dev", interface])
        .output()
        .expect("Failed to execute ip link command");

    output.status.success()
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
