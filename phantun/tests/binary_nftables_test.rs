use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn send_sigterm(pid: u32) {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
}

#[test]
fn test_binary_server_nftables_lifecycle() {
    let _lock = TEST_LOCK.lock().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_server"))
        .args(["--local", "4567", "--remote", "127.0.0.1:1234"])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start server binary");

    thread::sleep(Duration::from_millis(800));

    // Verify rules were added to table inet phantun
    let output = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    assert!(output.status.success(), "table inet phantun should exist");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("chain prerouting"), "chain prerouting should exist in table");
    assert!(text.contains("tcp dport 4567"), "tcp dport 4567 rule should exist");
    assert!(text.contains("dnat ip to 192.168.201.2"), "DNAT to 192.168.201.2 rule should exist");

    // Terminate server with SIGTERM
    send_sigterm(child.id());
    let status = child.wait().expect("Failed to wait on child");
    assert!(status.success(), "Server should exit cleanly on SIGTERM");

    // Verify table is removed or does not contain port 4567
    let output_after = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    if output_after.status.success() {
        let text_after = String::from_utf8_lossy(&output_after.stdout);
        assert!(!text_after.contains("4567"), "Rules for 4567 should be removed");
    }
}

#[test]
fn test_binary_client_nftables_lifecycle() {
    let _lock = TEST_LOCK.lock().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_client"))
        .args([
            "--local", "127.0.0.1:1234",
            "--remote", "127.0.0.1:4567",
            "--tun", "tun_t_bin",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start client binary");

    thread::sleep(Duration::from_millis(800));

    // Verify rules were added
    let output = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    assert!(output.status.success(), "table inet phantun should exist");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("chain postrouting"), "chain postrouting should exist");
    assert!(text.contains("tun_t_bin"), "tun_t_bin should be in rule");
    assert!(text.contains("masquerade"), "masquerade should be in rule");

    // Terminate client with SIGTERM
    send_sigterm(child.id());
    let status = child.wait().expect("Failed to wait on child");
    assert!(status.success(), "Client should exit cleanly on SIGTERM");

    // Verify rule removed
    let output_after = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    if output_after.status.success() {
        let text_after = String::from_utf8_lossy(&output_after.stdout);
        assert!(!text_after.contains("tun_t_bin"), "Rule for tun_t_bin should be removed");
    }
}

#[test]
fn test_binary_disable_nftables_flag() {
    let _lock = TEST_LOCK.lock().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_server"))
        .args([
            "--no-nftables",
            "--local", "4569",
            "--remote", "127.0.0.1:1234",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start server binary");

    thread::sleep(Duration::from_millis(800));

    // Check table inet phantun: rule 4569 should NOT exist
    let output = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(!text.contains("4569"), "Rule 4569 must not exist when --no-nftables is passed");
    }

    // Terminate server
    send_sigterm(child.id());
    let _ = child.wait();
}

#[test]
fn test_binary_client_fwmark() {
    let _lock = TEST_LOCK.lock().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_client"))
        .args([
            "--local", "127.0.0.1:1235",
            "--remote", "127.0.0.1:4568",
            "--tun", "tun_t_cfwm",
            "--fwmark", "0x100",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start client binary with fwmark");

    thread::sleep(Duration::from_millis(800));

    // Verify rules were added
    let output = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    assert!(output.status.success(), "table inet phantun should exist");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("chain prerouting_mangle"), "chain prerouting_mangle should exist");
    assert!(text.contains("tun_t_cfwm"), "tun_t_cfwm should be in rule");
    assert!(text.contains("0x00000100"), "0x00000100 should be in rule");

    // Terminate client with SIGTERM
    send_sigterm(child.id());
    let status = child.wait().expect("Failed to wait on child");
    assert!(status.success(), "Client should exit cleanly on SIGTERM");

    // Verify rule removed
    let output_after = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    if output_after.status.success() {
        let text_after = String::from_utf8_lossy(&output_after.stdout);
        assert!(!text_after.contains("tun_t_cfwm"), "Rule for tun_t_cfwm should be removed");
    }
}

#[test]
fn test_binary_server_fwmark() {
    let _lock = TEST_LOCK.lock().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_server"))
        .args([
            "--local", "4570",
            "--remote", "127.0.0.1:1236",
            "--tun", "tun_t_sfwm",
            "--fwmark", "256",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start server binary with fwmark");

    thread::sleep(Duration::from_millis(800));

    // Verify rules were added
    let output = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    assert!(output.status.success(), "table inet phantun should exist");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("chain prerouting_mangle"), "chain prerouting_mangle should exist");
    assert!(text.contains("tun_t_sfwm"), "tun_t_sfwm should be in rule");
    assert!(text.contains("0x00000100"), "0x00000100 should be in rule");

    // Terminate server with SIGTERM
    send_sigterm(child.id());
    let status = child.wait().expect("Failed to wait on child");
    assert!(status.success(), "Server should exit cleanly on SIGTERM");

    // Verify rule removed
    let output_after = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    if output_after.status.success() {
        let text_after = String::from_utf8_lossy(&output_after.stdout);
        assert!(!text_after.contains("tun_t_sfwm"), "Rule for tun_t_sfwm should be removed");
    }
}

#[test]
fn test_binary_server_nft_interface_wildcard() {
    let _lock = TEST_LOCK.lock().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_server"))
        .args([
            "--local", "4573",
            "--remote", "127.0.0.1:1237",
            "--tun", "tun_t_swild",
            "-i", "-",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start server binary with wildcard interface");

    thread::sleep(Duration::from_millis(800));

    // Verify rules were added to table inet phantun without iif
    let output = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    assert!(output.status.success(), "table inet phantun should exist");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("chain prerouting"), "chain prerouting should exist");
    assert!(text.contains("tcp dport 4573"), "tcp dport 4573 rule should exist");

    // Look at the line with 4573 and verify it does NOT contain iif
    for line in text.lines() {
        if line.contains("4573") {
            assert!(!line.contains("iif"), "Rule with port 4573 must not have iif clause: {}", line);
        }
    }

    // Terminate server with SIGTERM
    send_sigterm(child.id());
    let status = child.wait().expect("Failed to wait on child");
    assert!(status.success(), "Server should exit cleanly on SIGTERM");

    // Verify rule removed
    let output_after = Command::new("nft")
        .args(["list", "table", "inet", "phantun"])
        .output()
        .expect("Failed to run nft list");

    if output_after.status.success() {
        let text_after = String::from_utf8_lossy(&output_after.stdout);
        assert!(!text_after.contains("4573"), "Rule for 4573 should be removed");
    }
}
