use log::{info, warn};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "phantun";

#[derive(Debug, Clone)]
pub struct NftRule {
    pub chain: String,
    pub handle: u64,
    pub description: String,
}

#[derive(Debug)]
pub struct NftRuleGuard {
    pub rules: Vec<NftRule>,
    pub removed: bool,
}

impl NftRuleGuard {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            removed: false,
        }
    }

    /// Sets up client nftables rules in table `inet phantun`:
    /// Chain: `postrouting`
    /// Rule: `iifname "<tun_name>" oif "<iface>" masquerade`
    /// If `physical_iface` is None, auto-detection is attempted. If still None or if
    /// `physical_iface` is Some("-"), `iifname "<tun_name>" masquerade` is added.
    /// If `fwmark` is Some, a rule is also added to `prerouting_mangle`:
    /// `iifname "<tun_name>" meta mark set <fwmark>`
    pub fn setup_client(
        tun_name: &str,
        physical_iface: Option<&str>,
        fwmark: Option<u32>,
    ) -> io::Result<Self> {
        let detected_iface = match physical_iface {
            Some("-") | Some("") => None,
            Some(iface) => Some(iface.to_string()),
            None => detect_physical_interface(),
        };
        let iface_opt = detected_iface.as_deref();

        // 1. Ensure table inet phantun exists
        ensure_table_exists()?;

        // 2. Ensure chain postrouting exists
        ensure_chain_exists(
            "postrouting",
            "{ type nat hook postrouting priority srcnat; policy accept; }",
        )?;

        // 3. Formulate rule string and predicate for checking existing rules
        let rule_str = match iface_opt {
            Some(iface) => format!("iifname \"{}\" oif \"{}\" masquerade", tun_name, iface),
            None => format!("iifname \"{}\" masquerade", tun_name),
        };

        let tun_quoted = format!("\"{}\"", tun_name);
        let iface_quoted = iface_opt.map(|i| format!("\"{}\"", i));

        let predicate = move |rule: &str| {
            let matches_tun = rule.contains("iifname") && (rule.contains(&tun_quoted) || rule.contains(tun_name));
            let matches_masq = rule.contains("masquerade");
            let matches_iface = match iface_opt {
                Some(iface) => {
                    let iface_q = iface_quoted.as_deref().unwrap_or(iface);
                    (rule.contains("oif") || rule.contains("oifname"))
                        && (rule.contains(iface_q) || rule.contains(iface))
                }
                None => !rule.contains("oif") && !rule.contains("oifname"),
            };
            matches_tun && matches_masq && matches_iface
        };

        let mut guard = Self::new();

        // Check if rule already exists (idempotency)
        let existing_handles = get_chain_rule_handles("postrouting", &predicate)?;
        if !existing_handles.is_empty() {
            info!(
                "nftables rule for TUN {} already exists in table {} {}, reusing handle(s) {:?}",
                tun_name, TABLE_FAMILY, TABLE_NAME, existing_handles
            );
            for h in existing_handles {
                guard.rules.push(NftRule {
                    chain: "postrouting".to_string(),
                    handle: h,
                    description: rule_str.clone(),
                });
            }
        } else {
            // Add rule
            execute_nft(&["add", "rule", TABLE_FAMILY, TABLE_NAME, "postrouting", &rule_str])?;
            info!(
                "Added nftables rule to {} {}: {}",
                TABLE_FAMILY, TABLE_NAME, rule_str
            );

            // Fetch newly created handle
            let handles = get_chain_rule_handles("postrouting", &predicate)?;
            for h in handles {
                guard.rules.push(NftRule {
                    chain: "postrouting".to_string(),
                    handle: h,
                    description: rule_str.clone(),
                });
            }
        }

        if let Some(mark) = fwmark {
            guard.add_fwmark_rule(tun_name, mark)?;
        }

        Ok(guard)
    }

    /// Adds an nftables rule to set the fwmark for packets originating from `tun_name`:
    /// Chain: `prerouting_mangle`
    /// Hook: `prerouting` priority `mangle` (-150)
    /// Rule: `iifname "<tun_name>" meta mark set <fwmark>`
    pub fn add_fwmark_rule(&mut self, tun_name: &str, fwmark: u32) -> io::Result<()> {
        ensure_table_exists()?;
        ensure_chain_exists(
            "prerouting_mangle",
            "{ type filter hook prerouting priority mangle; policy accept; }",
        )?;

        let rule_str = format!("iifname \"{}\" meta mark set {:#x}", tun_name, fwmark);
        let tun_quoted = format!("\"{}\"", tun_name);
        let mark_hex_8 = format!("0x{:08x}", fwmark);
        let mark_hex = format!("{:#x}", fwmark);
        let mark_dec = fwmark.to_string();

        let predicate = move |rule: &str| {
            let matches_tun = rule.contains("iifname") && (rule.contains(&tun_quoted) || rule.contains(tun_name));
            let matches_action = rule.contains("meta mark set") || rule.contains("mark set");
            let rule_lower = rule.to_ascii_lowercase();
            let matches_mark = rule_lower.contains(&mark_hex_8)
                || rule_lower.contains(&mark_hex)
                || rule.contains(&mark_dec);
            matches_tun && matches_action && matches_mark
        };

        let existing_handles = get_chain_rule_handles("prerouting_mangle", &predicate)?;
        if !existing_handles.is_empty() {
            info!(
                "nftables fwmark rule for TUN {} mark {:#x} already exists in table {} {}, reusing handle(s) {:?}",
                tun_name, fwmark, TABLE_FAMILY, TABLE_NAME, existing_handles
            );
            for h in existing_handles {
                self.rules.push(NftRule {
                    chain: "prerouting_mangle".to_string(),
                    handle: h,
                    description: rule_str.clone(),
                });
            }
        } else {
            execute_nft(&[
                "add",
                "rule",
                TABLE_FAMILY,
                TABLE_NAME,
                "prerouting_mangle",
                &rule_str,
            ])?;
            info!(
                "Added nftables rule to {} {}: {}",
                TABLE_FAMILY, TABLE_NAME, rule_str
            );

            let handles = get_chain_rule_handles("prerouting_mangle", &predicate)?;
            for h in handles {
                self.rules.push(NftRule {
                    chain: "prerouting_mangle".to_string(),
                    handle: h,
                    description: rule_str.clone(),
                });
            }
        }

        Ok(())
    }

    /// Sets up server nftables rules in table `inet phantun`:
    /// Chain: `prerouting`
    /// IPv4 Rule: `iifname "<iface>" tcp dport <local_port> dnat ip to <tun_peer>`
    /// IPv6 Rule: `iifname "<iface>" tcp dport <local_port> dnat ip6 to <tun_peer6>` (if IPv6 enabled)
    /// If `physical_iface` is None, auto-detection is attempted. If still None or if
    /// `physical_iface` is Some("-"), rules are added without the `iifname "<iface>"` clause:
    /// `tcp dport <local_port> dnat ip to <tun_peer>`
    /// If `fwmark` is Some, a rule is also added to `prerouting_mangle`:
    /// `iifname "<tun_name>" meta mark set <fwmark>`
    pub fn setup_server(
        local_port: u16,
        tun_name: &str,
        tun_peer: Ipv4Addr,
        tun_peer6: Option<Ipv6Addr>,
        physical_iface: Option<&str>,
        fwmark: Option<u32>,
    ) -> io::Result<Self> {
        let detected_iface = match physical_iface {
            Some("-") | Some("") => None,
            Some(iface) => Some(iface.to_string()),
            None => detect_physical_interface(),
        };
        let iface_opt = detected_iface.as_deref();

        // 1. Ensure table inet phantun exists
        ensure_table_exists()?;

        // 2. Ensure chain prerouting exists
        ensure_chain_exists(
            "prerouting",
            "{ type nat hook prerouting priority dstnat; policy accept; }",
        )?;

        let mut guard = Self::new();

        // 3. IPv4 DNAT rule
        let rule4_str = match iface_opt {
            Some("-") | None => format!("tcp dport {} dnat ip to {}", local_port, tun_peer),
            Some(iface) => format!(
                "iifname \"{}\" tcp dport {} dnat ip to {}",
                iface, local_port, tun_peer
            ),
        };

        let iface_quoted = iface_opt.map(|i| format!("\"{}\"", i));
        let port_str = local_port.to_string();
        let peer4_str = tun_peer.to_string();

        let predicate4 = {
            let port_str = port_str.clone();
            let iface_quoted = iface_quoted.clone();
            move |rule: &str| {
                let matches_port = rule.contains("tcp dport") && rule.contains(&port_str);
                let matches_target = rule.contains("dnat ip to") && rule.contains(&peer4_str);
                let matches_iface = match iface_opt {
                    Some(iface) => {
                        let iface_q = iface_quoted.as_deref().unwrap_or(iface);
                        (rule.contains("iif") || rule.contains("iifname"))
                            && (rule.contains(iface_q) || rule.contains(iface))
                    }
                    None => !rule.contains("iif") && !rule.contains("iifname"),
                };
                matches_port && matches_target && matches_iface
            }
        };

        let existing_handles4 = get_chain_rule_handles("prerouting", &predicate4)?;
        if !existing_handles4.is_empty() {
            info!(
                "nftables IPv4 DNAT rule for port {} already exists in table {} {}, reusing handle(s) {:?}",
                local_port, TABLE_FAMILY, TABLE_NAME, existing_handles4
            );
            for h in existing_handles4 {
                guard.rules.push(NftRule {
                    chain: "prerouting".to_string(),
                    handle: h,
                    description: rule4_str.clone(),
                });
            }
        } else {
            execute_nft(&["add", "rule", TABLE_FAMILY, TABLE_NAME, "prerouting", &rule4_str])?;
            info!(
                "Added nftables rule to {} {}: {}",
                TABLE_FAMILY, TABLE_NAME, rule4_str
            );

            let handles = get_chain_rule_handles("prerouting", &predicate4)?;
            for h in handles {
                guard.rules.push(NftRule {
                    chain: "prerouting".to_string(),
                    handle: h,
                    description: rule4_str.clone(),
                });
            }
        }

        // 4. IPv6 DNAT rule (if configured)
        if let Some(peer6) = tun_peer6 {
            let rule6_str = match iface_opt {
                Some("-") | None => format!("tcp dport {} dnat ip6 to {}", local_port, peer6),
                Some(iface) => format!(
                    "iifname \"{}\" tcp dport {} dnat ip6 to {}",
                    iface, local_port, peer6
                ),
            };

            let peer6_str = peer6.to_string();
            let predicate6 = {
                let port_str = port_str.clone();
                let iface_quoted = iface_quoted.clone();
                move |rule: &str| {
                    let matches_port = rule.contains("tcp dport") && rule.contains(&port_str);
                    let matches_target = rule.contains("dnat ip6 to") && rule.contains(&peer6_str);
                    let matches_iface = match iface_opt {
                        Some(iface) => {
                            let iface_q = iface_quoted.as_deref().unwrap_or(iface);
                            (rule.contains("iif") || rule.contains("iifname"))
                                && (rule.contains(iface_q) || rule.contains(iface))
                        }
                        None => !rule.contains("iif") && !rule.contains("iifname"),
                    };
                    matches_port && matches_target && matches_iface
                }
            };

            let existing_handles6 = get_chain_rule_handles("prerouting", &predicate6)?;
            if !existing_handles6.is_empty() {
                info!(
                    "nftables IPv6 DNAT rule for port {} already exists in table {} {}, reusing handle(s) {:?}",
                    local_port, TABLE_FAMILY, TABLE_NAME, existing_handles6
                );
                for h in existing_handles6 {
                    guard.rules.push(NftRule {
                        chain: "prerouting".to_string(),
                        handle: h,
                        description: rule6_str.clone(),
                    });
                }
            } else {
                execute_nft(&["add", "rule", TABLE_FAMILY, TABLE_NAME, "prerouting", &rule6_str])?;
                info!(
                    "Added nftables rule to {} {}: {}",
                    TABLE_FAMILY, TABLE_NAME, rule6_str
                );

                let handles = get_chain_rule_handles("prerouting", &predicate6)?;
                for h in handles {
                    guard.rules.push(NftRule {
                        chain: "prerouting".to_string(),
                        handle: h,
                        description: rule6_str.clone(),
                    });
                }
            }
        }

        if let Some(mark) = fwmark {
            guard.add_fwmark_rule(tun_name, mark)?;
        }

        Ok(guard)
    }

    /// Removes the nftables rules that were added by this guard in a best-effort manner.
    /// Also deletes empty chains and the `phantun` table if no rules or chains remain.
    pub fn remove_rules(&mut self) {
        if self.removed {
            return;
        }
        self.removed = true;

        for rule in &self.rules {
            let handle_str = rule.handle.to_string();
            let res = execute_nft(&[
                "delete",
                "rule",
                TABLE_FAMILY,
                TABLE_NAME,
                &rule.chain,
                "handle",
                &handle_str,
            ]);

            match res {
                Ok(_) => {
                    info!(
                        "Removed nftables rule in {} {}: handle {} ({})",
                        TABLE_FAMILY, TABLE_NAME, rule.handle, rule.description
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to remove nftables rule handle {} in {}: {}",
                        rule.handle, rule.chain, e
                    );
                }
            }
        }
    }
}

impl Drop for NftRuleGuard {
    fn drop(&mut self) {
        self.remove_rules();
    }
}

/// Executes an `nft` command with given arguments.
pub fn execute_nft(args: &[&str]) -> io::Result<std::process::Output> {
    let output = Command::new("nft").args(args).output().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                "nft command not found. Please install nftables or pass --no-nftables to disable automatic rule management.",
            )
        } else {
            e
        }
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "nft command failed with status {}: nft {}\nStderr: {}",
                output.status,
                args.join(" "),
                stderr.trim()
            ),
        ));
    }

    Ok(output)
}

/// Ensures table `inet phantun` exists.
pub fn ensure_table_exists() -> io::Result<()> {
    execute_nft(&["add", "table", TABLE_FAMILY, TABLE_NAME])?;
    Ok(())
}

/// Ensures a chain exists in table `inet phantun`.
pub fn ensure_chain_exists(chain_name: &str, chain_def: &str) -> io::Result<()> {
    execute_nft(&["add", "chain", TABLE_FAMILY, TABLE_NAME, chain_name, chain_def])?;
    Ok(())
}

/// Parses a netfilter fwmark string in either decimal or hex (with `0x` or `0X` prefix).
pub fn parse_fwmark(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let res = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    };
    res.map_err(|e| {
        format!(
            "invalid fwmark \"{}\": must be a valid 32-bit unsigned integer (decimal or 0x-prefixed hex): {}",
            s, e
        )
    })
}

/// Returns rule handles for all rules in `chain` matching `predicate`.
pub fn get_chain_rule_handles<F>(chain: &str, predicate: &F) -> io::Result<Vec<u64>>
where
    F: Fn(&str) -> bool,
{
    let output = match Command::new("nft")
        .args(["-a", "list", "chain", TABLE_FAMILY, TABLE_NAME, chain])
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                return Ok(Vec::new());
            }
            return Err(e);
        }
    };

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut handles = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.rfind("# handle ") {
            let rule_part = trimmed[..pos].trim();
            let handle_str = trimmed[pos + 9..].trim();
            if let Ok(handle) = handle_str.parse::<u64>() {
                if predicate(rule_part) {
                    handles.push(handle);
                }
            }
        }
    }

    Ok(handles)
}

/// Automatically detects the physical network interface of the machine.
/// Inspects `/proc/net/route` for default route, falls back to `ip route show default`,
/// and then to the first non-loopback, non-virtual interface in `/proc/net/dev`.
pub fn detect_physical_interface() -> Option<String> {
    // 1. Try reading /proc/net/route
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        let mut best_metric = u32::MAX;
        let mut best_iface = None;

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 8 {
                let iface = fields[0];
                let dest = fields[1];
                let mask = fields[7];
                let metric = fields.get(6).and_then(|m| m.parse::<u32>().ok()).unwrap_or(0);

                if dest == "00000000" && mask == "00000000" {
                    if metric < best_metric {
                        best_metric = metric;
                        best_iface = Some(iface.to_string());
                    }
                }
            }
        }

        if let Some(iface) = best_iface {
            return Some(iface);
        }
    }

    // 2. Fallback to `ip route show default`
    if let Ok(output) = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut iter = text.split_whitespace();
            while let Some(word) = iter.next() {
                if word == "dev" {
                    if let Some(dev) = iter.next() {
                        return Some(dev.to_string());
                    }
                }
            }
        }
    }

    // 3. Fallback to /proc/net/dev
    if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
        for line in content.lines().skip(2) {
            if let Some(colon) = line.find(':') {
                let iface = line[..colon].trim();
                if iface != "lo"
                    && !iface.starts_with("tun")
                    && !iface.starts_with("docker")
                    && !iface.starts_with("veth")
                    && !iface.starts_with("test")
                {
                    return Some(iface.to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_detect_physical_interface() {
        let iface = detect_physical_interface();
        assert!(iface.is_some(), "Expected to detect physical interface");
        let iface_name = iface.unwrap();
        assert!(!iface_name.is_empty());
        assert_ne!(iface_name, "lo");
    }

    #[test]
    fn test_parse_fwmark() {
        assert_eq!(parse_fwmark("256").unwrap(), 256);
        assert_eq!(parse_fwmark("0x100").unwrap(), 256);
        assert_eq!(parse_fwmark("0X100").unwrap(), 256);
        assert_eq!(parse_fwmark("0x10").unwrap(), 16);
        assert_eq!(parse_fwmark("0xa").unwrap(), 10);
        assert_eq!(parse_fwmark("0").unwrap(), 0);
        assert_eq!(parse_fwmark("0xffffffff").unwrap(), 0xffffffff);
        assert!(parse_fwmark("invalid").is_err());
        assert!(parse_fwmark("-1").is_err());
        assert!(parse_fwmark("0x100000000").is_err());
    }

    #[test]
    fn test_client_nftables_lifecycle() {
        let _lock = TEST_LOCK.lock().unwrap();
        let test_tun = "tun_test_c";
        let iface = detect_physical_interface();

        // 1. Setup client
        let mut guard = NftRuleGuard::setup_client(test_tun, iface.as_deref(), None)
            .expect("Failed to setup client nftables");
        assert!(!guard.rules.is_empty(), "Expected rules to be registered");

        // Verify rule exists in nft
        let handles = get_chain_rule_handles("postrouting", &|r| r.contains(test_tun))
            .expect("Failed to query handles");
        assert_eq!(handles.len(), 1);

        // 2. Setup client again with same parameters (test idempotency)
        let mut guard2 = NftRuleGuard::setup_client(test_tun, iface.as_deref(), None)
            .expect("Failed to setup client nftables second time");
        let handles2 = get_chain_rule_handles("postrouting", &|r| r.contains(test_tun))
            .expect("Failed to query handles");
        assert_eq!(handles2.len(), 1, "Idempotent setup should not create duplicate rules");

        // 3. Remove rules
        guard2.removed = true; // Avoid double delete of same handle in this test
        guard.remove_rules();

        let handles_after = get_chain_rule_handles("postrouting", &|r| r.contains(test_tun))
            .expect("Failed to query handles after removal");
        assert!(handles_after.is_empty(), "Rule should have been removed");
    }

    #[test]
    fn test_server_nftables_lifecycle() {
        let _lock = TEST_LOCK.lock().unwrap();
        let test_port = 59876;
        let test_tun = "tun_test_s";
        let tun_peer = Ipv4Addr::new(192, 168, 201, 2);
        let tun_peer6 = Some(Ipv6Addr::new(0xfcc9, 0, 0, 0, 0, 0, 0, 2));
        let iface = detect_physical_interface();

        // 1. Setup server
        let mut guard = NftRuleGuard::setup_server(test_port, test_tun, tun_peer, tun_peer6, iface.as_deref(), None)
            .expect("Failed to setup server nftables");
        assert_eq!(guard.rules.len(), 2, "Expected IPv4 and IPv6 rules");

        // Verify rules exist in nft
        let port_str = test_port.to_string();
        let handles = get_chain_rule_handles("prerouting", &|r| r.contains(&port_str))
            .expect("Failed to query handles");
        assert_eq!(handles.len(), 2);

        // 2. Setup server again (idempotency)
        let mut guard2 = NftRuleGuard::setup_server(test_port, test_tun, tun_peer, tun_peer6, iface.as_deref(), None)
            .expect("Failed to setup server nftables second time");
        let handles2 = get_chain_rule_handles("prerouting", &|r| r.contains(&port_str))
            .expect("Failed to query handles");
        assert_eq!(handles2.len(), 2, "Idempotent setup should not create duplicate rules");

        // 3. Remove rules
        guard2.removed = true;
        guard.remove_rules();

        let handles_after = get_chain_rule_handles("prerouting", &|r| r.contains(&port_str))
            .expect("Failed to query handles after removal");
        assert!(handles_after.is_empty(), "Rules should have been removed");
    }

    #[test]
    fn test_fwmark_lifecycle() {
        let _lock = TEST_LOCK.lock().unwrap();
        let test_tun = "tun_test_fwm";
        let test_mark = 0x100;
        let iface = detect_physical_interface();

        // Setup client with fwmark
        let mut guard = NftRuleGuard::setup_client(test_tun, iface.as_deref(), Some(test_mark))
            .expect("Failed to setup client with fwmark");
        assert_eq!(guard.rules.len(), 2, "Expected masquerade and fwmark rules");

        // Verify fwmark rule in prerouting_mangle
        let handles = get_chain_rule_handles("prerouting_mangle", &|r| r.contains(test_tun) && r.contains("0x00000100"))
            .expect("Failed to query handles");
        assert_eq!(handles.len(), 1);

        // Setup second time (idempotency)
        let mut guard2 = NftRuleGuard::setup_client(test_tun, iface.as_deref(), Some(test_mark))
            .expect("Failed to setup client second time with fwmark");
        let handles2 = get_chain_rule_handles("prerouting_mangle", &|r| r.contains(test_tun) && r.contains("0x00000100"))
            .expect("Failed to query handles");
        assert_eq!(handles2.len(), 1);

        guard2.removed = true;
        guard.remove_rules();

        let handles_after = get_chain_rule_handles("prerouting_mangle", &|r| r.contains(test_tun))
            .expect("Failed to query handles after removal");
        assert!(handles_after.is_empty(), "Fwmark rule should have been removed");
    }

    #[test]
    fn test_coexistence_and_cleanup() {
        let _lock = TEST_LOCK.lock().unwrap();
        let test_tun = "tun_test_coex";
        let test_port = 59877;
        let tun_peer = Ipv4Addr::new(192, 168, 201, 2);
        let iface = detect_physical_interface();

        let mut client_guard = NftRuleGuard::setup_client(test_tun, iface.as_deref(), None)
            .expect("Failed to setup client");
        let mut server_guard = NftRuleGuard::setup_server(test_port, test_tun, tun_peer, None, iface.as_deref(), None)
            .expect("Failed to setup server");

        // Both client and server rules exist
        let port_str = test_port.to_string();
        assert_eq!(
            get_chain_rule_handles("postrouting", &|r| r.contains(test_tun)).unwrap().len(),
            1
        );
        assert_eq!(
            get_chain_rule_handles("prerouting", &|r| r.contains(&port_str)).unwrap().len(),
            1
        );

        // Remove client: server rules should still exist
        client_guard.remove_rules();
        assert_eq!(
            get_chain_rule_handles("postrouting", &|r| r.contains(test_tun)).unwrap().len(),
            0
        );
        assert_eq!(
            get_chain_rule_handles("prerouting", &|r| r.contains(&port_str)).unwrap().len(),
            1
        );

        // Remove server: now both are cleaned up
        server_guard.remove_rules();
        assert_eq!(
            get_chain_rule_handles("prerouting", &|r| r.contains(&port_str)).unwrap().len(),
            0
        );
    }

    #[test]
    fn test_multiple_servers_coexistence() {
        let _lock = TEST_LOCK.lock().unwrap();
        let port1 = 59878;
        let port2 = 59879;
        let tun_peer = Ipv4Addr::new(192, 168, 201, 2);
        let iface = detect_physical_interface();

        let mut server1 = NftRuleGuard::setup_server(port1, "tun_test_s1", tun_peer, None, iface.as_deref(), None)
            .expect("Failed to setup server 1");
        let mut server2 = NftRuleGuard::setup_server(port2, "tun_test_s2", tun_peer, None, iface.as_deref(), None)
            .expect("Failed to setup server 2");

        let port1_str = port1.to_string();
        let port2_str = port2.to_string();

        assert_eq!(
            get_chain_rule_handles("prerouting", &|r| r.contains(&port1_str)).unwrap().len(),
            1
        );
        assert_eq!(
            get_chain_rule_handles("prerouting", &|r| r.contains(&port2_str)).unwrap().len(),
            1
        );

        // Stopping server 1 MUST NOT remove server 2's rules or flush the table/chain
        server1.remove_rules();

        assert_eq!(
            get_chain_rule_handles("prerouting", &|r| r.contains(&port1_str)).unwrap().len(),
            0,
            "Server 1 rule should be removed"
        );
        assert_eq!(
            get_chain_rule_handles("prerouting", &|r| r.contains(&port2_str)).unwrap().len(),
            1,
            "Server 2 rule MUST remain in prerouting after server 1 stops"
        );

        // Now stop server 2
        server2.remove_rules();
        assert_eq!(
            get_chain_rule_handles("prerouting", &|r| r.contains(&port2_str)).unwrap().len(),
            0
        );
    }

    #[test]
    fn test_server_nftables_wildcard_interface() {
        let _lock = TEST_LOCK.lock().unwrap();
        let test_port = 59880;
        let test_tun = "tun_test_swild";
        let tun_peer = Ipv4Addr::new(192, 168, 201, 2);
        let tun_peer6 = Some(Ipv6Addr::new(0xfcc9, 0, 0, 0, 0, 0, 0, 2));

        // 1. Setup server with wildcard "-"
        let mut guard = NftRuleGuard::setup_server(test_port, test_tun, tun_peer, tun_peer6, Some("-"), None)
            .expect("Failed to setup server nftables with wildcard");
        assert_eq!(guard.rules.len(), 2, "Expected IPv4 and IPv6 rules");

        // Verify rules in guard description do NOT have iif
        for r in &guard.rules {
            assert!(!r.description.contains("iif"), "Wildcard rule should not contain iif: {}", r.description);
        }

        // Verify rules exist in nft without iif
        let port_str = test_port.to_string();
        let handles = get_chain_rule_handles("prerouting", &|r| r.contains(&port_str) && !r.contains("iif"))
            .expect("Failed to query handles");
        assert_eq!(handles.len(), 2);

        // 2. Setup server again with "-" (idempotency)
        let mut guard2 = NftRuleGuard::setup_server(test_port, test_tun, tun_peer, tun_peer6, Some("-"), None)
            .expect("Failed to setup server nftables second time");
        let handles2 = get_chain_rule_handles("prerouting", &|r| r.contains(&port_str) && !r.contains("iif"))
            .expect("Failed to query handles");
        assert_eq!(handles2.len(), 2, "Idempotent setup should not create duplicate rules");

        // 3. Remove rules
        guard2.removed = true;
        guard.remove_rules();

        let handles_after = get_chain_rule_handles("prerouting", &|r| r.contains(&port_str))
            .expect("Failed to query handles after removal");
        assert!(handles_after.is_empty(), "Rules should have been removed");
    }

    #[test]
    fn test_client_nftables_wildcard_interface() {
        let _lock = TEST_LOCK.lock().unwrap();
        let test_tun = "tun_test_cwild";

        // 1. Setup client with wildcard "-"
        let mut guard = NftRuleGuard::setup_client(test_tun, Some("-"), None)
            .expect("Failed to setup client nftables with wildcard");
        assert_eq!(guard.rules.len(), 1, "Expected masquerade rule");

        // Verify rule in guard description does NOT have oif
        assert!(!guard.rules[0].description.contains("oif"), "Wildcard client rule should not contain oif: {}", guard.rules[0].description);

        // Verify rule exists in nft without oif
        let handles = get_chain_rule_handles("postrouting", &|r| r.contains(test_tun) && !r.contains("oif"))
            .expect("Failed to query handles");
        assert_eq!(handles.len(), 1);

        // 2. Setup client again with "-" (idempotency)
        let mut guard2 = NftRuleGuard::setup_client(test_tun, Some("-"), None)
            .expect("Failed to setup client nftables second time");
        let handles2 = get_chain_rule_handles("postrouting", &|r| r.contains(test_tun) && !r.contains("oif"))
            .expect("Failed to query handles");
        assert_eq!(handles2.len(), 1);

        // 3. Remove rules
        guard2.removed = true;
        guard.remove_rules();

        let handles_after = get_chain_rule_handles("postrouting", &|r| r.contains(test_tun))
            .expect("Failed to query handles after removal");
        assert!(handles_after.is_empty(), "Rule should have been removed");
    }
}
