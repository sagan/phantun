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
