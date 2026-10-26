//! Reconstruct data-VPN handshakes on promotion using shared long-term identity
//! and authenticated public roaming endpoints. Private configuration never leaves
//! a root-only recovery file or a pipe to the pinned WireGuard utility.
use crate::{read_private, write_private, Authority, Config, Role};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    interface: [u8; 16],
    public_key: [u8; 32],
    ip: [u8; 16],
    port: u16,
    family: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    cluster: String,
    node: u8,
    policy: String,
    authority: Authority,
    endpoints: Vec<Endpoint>,
}
impl Cache {
    fn validate(&self, config: &Config, role: &Role) -> Result<()> {
        // Roaming metadata belongs to the desired VPN identity. Unrelated
        // firewall changes advance the HA policy without invalidating it.
        ensure!(
            self.cluster == config.cluster
                && self.node == config.node
                && self.policy == config.wireguard_policy
                && self.authority.term <= role.authority.term
                && self.endpoints.len() <= 4096,
            "incompatible WireGuard HA snapshot"
        );
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    policy: String,
    interface: String,
    config: String,
}

async fn command(args: &[&str], input: Option<&str>) -> Result<String> {
    let bin = std::env::var("WREN_WG_BIN").unwrap_or_else(|_| "wg".into());
    let mut child = Command::new(bin)
        .args(args)
        .kill_on_drop(true)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("starting WireGuard promotion operation")?;
    if let Some(input) = input {
        let mut stdin = child.stdin.take().context("WireGuard pipe")?;
        stdin.write_all(input.as_bytes()).await?;
    }
    let result = timeout(Duration::from_millis(500), child.wait_with_output()).await??;
    ensure!(
        result.status.success() && result.stdout.len() <= 1_048_576,
        "WireGuard promotion operation failed"
    );
    String::from_utf8(result.stdout).context("invalid WireGuard output")
}

fn endpoint(cache: &Cache, interface: &str, key: &str) -> Result<Option<String>> {
    let public: [u8; 32] = STANDARD
        .decode(key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid configured WireGuard peer key"))?;
    for e in &cache.endpoints {
        let end = e
            .interface
            .iter()
            .position(|b| *b == 0)
            .context("invalid replicated WireGuard interface")?;
        let name = std::str::from_utf8(&e.interface[..end])?;
        ensure!(
            e.interface[end..].iter().all(|b| *b == 0),
            "invalid replicated WireGuard padding"
        );
        if name == interface && e.public_key == public {
            ensure!(e.port > 0, "invalid replicated WireGuard port");
            let ip = match e.family {
                4 => {
                    ensure!(e.ip[4..] == [0; 12], "invalid replicated IPv4 padding");
                    IpAddr::from(<[u8; 4]>::try_from(&e.ip[..4])?)
                }
                6 => IpAddr::from(e.ip),
                _ => anyhow::bail!("invalid replicated endpoint family"),
            };
            ensure!(
                !ip.is_unspecified() && !ip.is_multicast(),
                "invalid replicated endpoint IP"
            );
            return Ok(Some(SocketAddr::new(ip, e.port).to_string()));
        }
    }
    Ok(None)
}

fn promotion_config(original: &str, interface: &str, cache: Option<&Cache>) -> Result<String> {
    let mut parts = original.split("[Peer]");
    let mut output = parts
        .next()
        .context("missing WireGuard interface")?
        .to_string();
    ensure!(
        output.contains("[Interface]"),
        "invalid WireGuard interface configuration"
    );
    for peer in parts {
        let key = peer
            .lines()
            .find_map(|l| l.trim().strip_prefix("PublicKey = "))
            .context("WireGuard peer has no public key")?;
        let learned = cache
            .map(|c| endpoint(c, interface, key))
            .transpose()?
            .flatten();
        output.push_str("[Peer]\n");
        for line in peer.lines().filter(|l| !l.trim().is_empty()) {
            if line.trim().starts_with("PersistentKeepalive = ")
                || learned.is_some() && line.trim().starts_with("Endpoint = ")
            {
                continue;
            }
            output.push_str(line);
            output.push('\n');
        }
        if let Some(endpoint) = learned {
            output.push_str(&format!("Endpoint = {endpoint}\n"));
        }
        output.push_str("PersistentKeepalive = 1\n");
    }
    Ok(output)
}

pub async fn promote(config: Config, role: Role) -> Result<()> {
    if config.wireguard.is_empty() {
        return Ok(());
    }
    let cache = match read_private::<Cache>(Path::new("/run/velstra/ha/wireguard.json")) {
        Ok(cache) => {
            cache.validate(&config, &role)?;
            Some(cache)
        }
        Err(error) => {
            if role.claimed_ready_term > 0 {
                return Err(error).context("complete WireGuard endpoint snapshot is required");
            }
            None
        }
    };
    for interface in &config.wireguard {
        ensure!(
            !interface.is_empty()
                && interface.len() < 16
                && interface
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')),
            "invalid HA WireGuard interface"
        );
        let recovery_path = Path::new("/run/velstra/ha").join(format!("wg-{interface}.json"));
        let original = match read_private::<Recovery>(&recovery_path) {
            Ok(saved)
                if saved.policy == config.wireguard_policy && saved.interface == *interface =>
            {
                saved.config
            }
            _ => command(&["showconf", interface], None)
                .await
                .context("reading current WireGuard configuration")?,
        };
        let promoted = promotion_config(&original, interface, cache.as_ref())?;
        // Store the endpoint-adjusted policy with its original keepalive intent.
        // syncconf after re-creation preserves the newly initiated session.
        let restored = restore_keepalive(&original, &promoted)?;
        write_private(
            &recovery_path,
            &Recovery {
                policy: config.wireguard_policy.clone(),
                interface: interface.clone(),
                config: restored.clone(),
            },
            false,
        )?;
        let interface_only = original
            .split("[Peer]")
            .next()
            .context("missing WireGuard interface")?;
        command(&["setconf", interface, "/dev/stdin"], Some(interface_only))
            .await
            .context("clearing prior WireGuard sessions")?;
        command(&["setconf", interface, "/dev/stdin"], Some(&promoted))
            .await
            .context("installing promotion WireGuard configuration")?;
        command(&["syncconf", interface, "/dev/stdin"], Some(&restored))
            .await
            .context("restoring WireGuard keepalive intent")?;
        std::fs::remove_file(recovery_path)?;
    }
    Ok(())
}
fn restore_keepalive(original: &str, promoted: &str) -> Result<String> {
    let originals: Vec<_> = original.split("[Peer]").skip(1).collect();
    let mut sections = promoted.split("[Peer]");
    let mut result = sections.next().unwrap_or_default().to_string();
    for (index, peer) in sections.enumerate() {
        let old = originals
            .get(index)
            .context("WireGuard peer count changed")?;
        result.push_str("[Peer]\n");
        for line in peer
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("PersistentKeepalive = "))
        {
            result.push_str(line);
            result.push('\n');
        }
        if let Some(line) = old
            .lines()
            .find(|l| l.trim().starts_with("PersistentKeepalive = "))
        {
            result.push_str(line);
            result.push('\n');
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roaming_cache_survives_filter_change_but_cannot_cross_vpn_identity() {
        let mut config = Config {
            cluster: "cluster".into(),
            node: 1,
            witness: "127.0.0.1:5440".parse().unwrap(),
            secret: "unused".into(),
            priority: 200,
            preempt: true,
            wireguard: vec!["wg0".into()],
            wireguard_policy: "vpn-digest".into(),
            lease_ms: crate::TTL_MS,
            io_ms: crate::IO_MS,
        };
        let role = Role {
            authority: Authority {
                term: 5,
                policy: [9; 32],
                ..Authority::default()
            },
            ..Role::default()
        };
        let mut cache = Cache {
            cluster: config.cluster.clone(),
            node: 1,
            policy: config.wireguard_policy.clone(),
            authority: Authority {
                term: 4,
                policy: [8; 32],
                ..Authority::default()
            },
            endpoints: vec![],
        };
        cache.validate(&config, &role).unwrap();
        config.wireguard_policy = "changed-identity".into();
        assert!(cache.validate(&config, &role).is_err());
        config.wireguard_policy = cache.policy.clone();
        cache.authority.term = 6;
        assert!(cache.validate(&config, &role).is_err());
        cache.authority.term = 4;
        cache.node = 2;
        assert!(cache.validate(&config, &role).is_err());
        cache.node = 1;
        cache.cluster = "another-cluster".into();
        assert!(cache.validate(&config, &role).is_err());
    }
    #[test]
    fn promotion_reuses_identity_updates_only_known_peer_and_restores_keepalive() {
        let key = STANDARD.encode([1; 32]);
        let original=format!("[Interface]\nPrivateKey = private\nListenPort = 51820\n[Peer]\nPublicKey = {key}\nPresharedKey = psk\nEndpoint = 192.0.2.1:1\nAllowedIPs = 10.0.0.0/24\nPersistentKeepalive = 25\n");
        let mut iface = [0; 16];
        iface[..3].copy_from_slice(b"wg0");
        let mut ip = [0; 16];
        ip[..4].copy_from_slice(&[198, 51, 100, 2]);
        let cache = Cache {
            cluster: "cluster".into(),
            node: 2,
            policy: "policy".into(),
            authority: Authority::default(),
            endpoints: vec![
                Endpoint {
                    interface: iface,
                    public_key: [1; 32],
                    ip,
                    port: 443,
                    family: 4,
                },
                Endpoint {
                    interface: iface,
                    public_key: [2; 32],
                    ip,
                    port: 444,
                    family: 4,
                },
            ],
        };
        let promoted = promotion_config(&original, "wg0", Some(&cache)).unwrap();
        assert!(promoted.contains("PrivateKey = private"));
        assert!(promoted.contains("PresharedKey = psk"));
        assert!(promoted.contains("Endpoint = 198.51.100.2:443"));
        assert!(!promoted.contains(":444"));
        assert!(promoted.contains("PersistentKeepalive = 1\n"));
        let restored = restore_keepalive(&original, &promoted).unwrap();
        assert!(restored.contains("PersistentKeepalive = 25\n"));
        assert!(!restored.contains("PersistentKeepalive = 1\n"));
        assert!(restored.contains("Endpoint = 198.51.100.2:443"));
    }
}
