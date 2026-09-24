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
    #[serde(default = "default_whitelist")]
    pub whitelist: Vec<String>,
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
            whitelist: default_whitelist(),
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

fn default_whitelist() -> Vec<String> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
        .into_iter()
        .map(str::to_owned)
        .collect()
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
    let config: Config = toml::from_str(&config)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    anyhow::ensure!(!config.interval.is_zero(), "interval must be greater than zero");
    for network in &config.whitelist {
        network.parse::<ipnet::IpNet>()
            .with_context(|| format!("Invalid whitelist network: {network}"))?;
    }
    Ok(config)
}
