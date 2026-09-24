use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;

const DEFAULT_L1_URL: &str = "https://iplists.firehol.org/files/firehol_level1.netset";
const DEFAULT_L2_URL: &str = "https://iplists.firehol.org/files/firehol_level2.netset";
const DEFAULT_BOGONS_IPV4_URL: &str = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt";
const DEFAULT_BOGONS_IPV6_URL: &str = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt";

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct Config {
    #[serde(default = "default_interval", with = "humantime_serde")]
    pub interval: Duration,
    #[serde(default)]
    pub path: PathBuf,
    #[serde(default)]
    pub l1_url: String,
    #[serde(default)]
    pub l2_url: String,
    #[serde(default = "default_bogons_ipv4_url")]
    pub bogons_ipv4_url: String,
    #[serde(default = "default_bogons_ipv6_url")]
    pub bogons_ipv6_url: String,
    #[serde(skip)]
    pub whitelist: Vec<String>,
    #[serde(default = "default_log_blocked")]
    pub log_blocked: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interval: default_interval(),
            path: PathBuf::from("."),
            l1_url: DEFAULT_L1_URL.to_owned(),
            l2_url: DEFAULT_L2_URL.to_owned(),
            bogons_ipv4_url: default_bogons_ipv4_url(),
            bogons_ipv6_url: default_bogons_ipv6_url(),
            whitelist: Vec::new(),
            log_blocked: default_log_blocked(),
        }
    }
}

fn default_interval() -> Duration {
    Duration::from_secs(60 * 60)
}

fn default_bogons_ipv4_url() -> String {
    DEFAULT_BOGONS_IPV4_URL.to_owned()
}

fn default_bogons_ipv6_url() -> String {
    DEFAULT_BOGONS_IPV6_URL.to_owned()
}

fn default_log_blocked() -> bool {
    false
}

pub async fn load_config(data_dir: &Path) -> Result<Config> {
    let path = data_dir.join("config.toml");
    let config = match fs::read_to_string(&path).await {
        Ok(config) => config,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
            "Configuration file {} does not exist",
            path.display()
        ),
        Err(error) => return Err(error).with_context(|| format!("Failed to read {}", path.display())),
    };
    let mut config: Config = toml::from_str(&config)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    anyhow::ensure!(!config.interval.is_zero(), "interval must be greater than zero");
    for (filename, ipv4) in [("whitelist-ipv4.txt", true), ("whitelist-ipv6.txt", false)] {
        let list_path = data_dir.join(filename);
        let list = match fs::read_to_string(&list_path).await {
            Ok(list) => list,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
                "Whitelist file {} does not exist",
                list_path.display()
            ),
            Err(error) => return Err(error).with_context(|| format!("Failed to read {}", list_path.display())),
        };
        for (line_number, line) in list.lines().enumerate() {
            let network = line.split('#').next().unwrap_or_default().trim();
            if network.is_empty() {
                continue;
            }
            let parsed = network.parse::<ipnet::IpNet>()
                .with_context(|| format!("Invalid network in {} at line {}", list_path.display(), line_number + 1))?;
            anyhow::ensure!(parsed.addr().is_ipv4() == ipv4,
                "Wrong address family in {} at line {}",
                list_path.display(), line_number + 1);
            config.whitelist.push(network.to_owned());
        }
    }
    Ok(config)
}
