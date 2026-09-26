mod config;
mod etags;
mod ipset;
#[cfg(target_os = "linux")]
#[path = "nftables.rs"]
mod nftables_sync;

pub use config::{load_config, Config};
use anyhow::{Context, Result, ensure};
use etags::Etags;
use ipset::Ipset;
use log::{error, info};
use serde::{Deserializer, de::{DeserializeSeed, MapAccess, SeqAccess, Visitor}};
use std::{collections::HashSet, path::{Path, PathBuf}};
use std::time::Instant;
use tokio::fs;
use tokio_util::sync::CancellationToken;

const GITHUB_META_URL: &str = "https://api.github.com/meta";

pub async fn run_scheduler(data_dir: PathBuf, config: Config, cancellation: CancellationToken) -> Result<()> {
    let client = reqwest::Client::builder().user_agent("firehol-differ-nftables").build()?;
    let mut ticker = tokio::time::interval(config.interval);
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            _ = ticker.tick() => {
                if let Err(error) = run_once_with_client(&data_dir, &config, &client, false).await {
                    error!("Scheduled download/update failed; will retry: {error:#}");
                }
            }
        }
    }
}

pub async fn run_once(data_dir: &Path, config: &Config) -> Result<()> {
    let client = reqwest::Client::builder().user_agent("firehol-differ-nftables").build()?;
    run_once_with_client(data_dir, config, &client, true).await
}

async fn run_once_with_client(
    data_dir: &Path,
    config: &Config,
    client: &reqwest::Client,
    _restore_if_unchanged: bool,
) -> Result<()> {
    fs::create_dir_all(data_dir).await?;
    let start = Instant::now();
    let mut etags = Etags::load(data_dir).await.unwrap_or_default();
    let (l1_etag, l2_etag, bogons_ipv4_etag, bogons_ipv6_etag, github_meta_etag) = tokio::try_join!(
        remote_etag(client, &config.l1_url),
        remote_etag(client, &config.l2_url),
        remote_etag(client, &config.bogons_ipv4_url),
        remote_etag(client, &config.bogons_ipv6_url),
        remote_etag(client, GITHUB_META_URL),
    )?;

    let (has_l1, has_l2, has_bogons_ipv4, has_bogons_ipv6, has_github_meta) = tokio::try_join!(
        cache_file_exists(data_dir, "firehol_level1.netset"),
        cache_file_exists(data_dir, "firehol_level2.netset"),
        cache_file_exists(data_dir, "fullbogons-ipv4.txt"),
        cache_file_exists(data_dir, "fullbogons-ipv6.txt"),
        cache_file_exists(data_dir, "github-meta.json"),
    )?;
    let (l1_remote, l2_remote, bogons_ipv4_remote, bogons_ipv6_remote, github_meta_remote) = tokio::try_join!(
        download_if_changed(client, "FireHOL Level 1", &config.l1_url, has_l1, l1_etag.as_deref(), etags.l1.as_deref()),
        download_if_changed(client, "FireHOL Level 2", &config.l2_url, has_l2, l2_etag.as_deref(), etags.l2.as_deref()),
        download_if_changed(client, "Team Cymru IPv4 bogons", &config.bogons_ipv4_url, has_bogons_ipv4, bogons_ipv4_etag.as_deref(), etags.bogons_ipv4.as_deref()),
        download_if_changed(client, "Team Cymru IPv6 bogons", &config.bogons_ipv6_url, has_bogons_ipv6, bogons_ipv6_etag.as_deref(), etags.bogons_ipv6.as_deref()),
        download_if_changed(client, "GitHub IP metadata", GITHUB_META_URL, has_github_meta, github_meta_etag.as_deref(), etags.github_meta.as_deref()),
    )?;

    if l1_remote.is_none()
        && l2_remote.is_none()
        && bogons_ipv4_remote.is_none()
        && bogons_ipv6_remote.is_none()
        && github_meta_remote.is_none()
    {
        info!("ETags have not changed and all feed files are cached.");
        #[cfg(target_os = "linux")]
        if _restore_if_unchanged {
            restore_cached(data_dir, config).await?;
        }
        return Ok(());
    }

    let github_networks = match github_meta_remote.as_deref() {
        Some(meta) => Some(parse_github_ranges(meta)?),
        None => None,
    };
    #[cfg(target_os = "linux")]
    let updated_lists = [&l1_remote, &l2_remote, &bogons_ipv4_remote, &bogons_ipv6_remote];
    #[cfg(target_os = "linux")]
    let mut new_sets = Vec::with_capacity(updated_lists.len());
    #[cfg(target_os = "linux")]
    for list in updated_lists {
        let networks = list.as_deref().map(|text| {
            let mut set = Ipset::new().from(text);
            set.consolidate();
            let mut networks: Vec<_> = set.ips.into_iter().collect();
            networks.sort();
            networks
        });
        new_sets.push(networks);
    }

    #[cfg(target_os = "linux")]
    let nftables_result = async {
        let (whitelist_ipv4, whitelist_ipv6) = if github_networks.is_some() {
            let (ipv4, ipv6) = load_whitelist(data_dir).await?;
            (Some(ipv4), Some(ipv6))
        } else {
            (None, None)
        };
        nftables_sync::replace_lists(
            &new_sets,
            whitelist_ipv4.as_deref(),
            whitelist_ipv6.as_deref(),
            github_networks.as_deref(),
            config.log_blocked,
        )
    }.await;
    #[cfg(target_os = "linux")]
    nftables_result?;

    persist_changed_downloads(data_dir, &l1_remote, &l2_remote, &bogons_ipv4_remote, &bogons_ipv6_remote, &github_meta_remote).await?;
    etags.l1 = l1_etag;
    etags.l2 = l2_etag;
    etags.bogons_ipv4 = bogons_ipv4_etag;
    etags.bogons_ipv6 = bogons_ipv6_etag;
    etags.github_meta = github_meta_etag;
    etags.save(data_dir).await?;
    info!("Elapsed time: {:.3} seconds", start.elapsed().as_secs_f64());
    Ok(())
}

/// Rebuild the nftables sets from the last successfully downloaded lists.
/// This is used after a reboot or an nftables ruleset reload.
#[cfg(target_os = "linux")]
pub async fn restore_cached(data_dir: &Path, config: &Config) -> Result<()> {
    let client = reqwest::Client::builder().user_agent("firehol-differ-nftables").build()?;
    let (l1, missing_l1) = read_cached_or_missing(data_dir, "firehol_level1.netset").await?;
    let (l2, missing_l2) = read_cached_or_missing(data_dir, "firehol_level2.netset").await?;
    let (bogons_ipv4, missing_bogons_ipv4) = read_cached_or_missing(data_dir, "fullbogons-ipv4.txt").await?;
    let (bogons_ipv6, missing_bogons_ipv6) = read_cached_or_missing(data_dir, "fullbogons-ipv6.txt").await?;
    let l1 = if missing_l1 { download(&client, &config.l1_url).await? } else { l1 };
    let l2 = if missing_l2 { download(&client, &config.l2_url).await? } else { l2 };
    let bogons_ipv4 = if missing_bogons_ipv4 { download(&client, &config.bogons_ipv4_url).await? } else { bogons_ipv4 };
    let bogons_ipv6 = if missing_bogons_ipv6 { download(&client, &config.bogons_ipv6_url).await? } else { bogons_ipv6 };
    let cached_github_meta = read_or_empty(&data_dir.join("github-meta.json")).await?;
    let github_meta = github_metadata(&client, &cached_github_meta, true).await?;

    let processing_result = async {
        let github_networks = parse_github_ranges(&github_meta)?;
        let lists = [&l1, &l2, &bogons_ipv4, &bogons_ipv6];
        let mut networks = Vec::new();
        for list in lists {
            let mut set = Ipset::new().from(list);
            set.consolidate();
            let mut entries: Vec<_> = set.ips.into_iter().collect();
            entries.sort();
            networks.push(entries);
        }
        let (whitelist_ipv4, whitelist_ipv6) = load_whitelist(data_dir).await?;
        let updates: Vec<_> = networks.into_iter().map(Some).collect();
        nftables_sync::replace_lists(
            &updates,
            Some(&whitelist_ipv4),
            Some(&whitelist_ipv6),
            Some(&github_networks),
            config.log_blocked,
        )
    }.await;
    let persist_result = persist_downloads(data_dir, &l1, &l2, &bogons_ipv4, &bogons_ipv6, &github_meta).await;
    processing_result?;
    persist_result?;
    Ok(())
}

async fn persist_downloads(
    data_dir: &Path,
    l1: &str,
    l2: &str,
    bogons_ipv4: &str,
    bogons_ipv6: &str,
    github_meta: &str,
) -> Result<()> {
    tokio::try_join!(
        fs::write(data_dir.join("firehol_level1.netset"), l1),
        fs::write(data_dir.join("firehol_level2.netset"), l2),
        fs::write(data_dir.join("fullbogons-ipv4.txt"), bogons_ipv4),
        fs::write(data_dir.join("fullbogons-ipv6.txt"), bogons_ipv6),
        fs::write(data_dir.join("github-meta.json"), github_meta),
    )?;
    Ok(())
}

async fn persist_changed_downloads(
    data_dir: &Path,
    l1: &Option<String>,
    l2: &Option<String>,
    bogons_ipv4: &Option<String>,
    bogons_ipv6: &Option<String>,
    github_meta: &Option<String>,
) -> Result<()> {
    for (filename, contents) in [
        ("firehol_level1.netset", l1),
        ("firehol_level2.netset", l2),
        ("fullbogons-ipv4.txt", bogons_ipv4),
        ("fullbogons-ipv6.txt", bogons_ipv6),
        ("github-meta.json", github_meta),
    ] {
        if let Some(contents) = contents {
            fs::write(data_dir.join(filename), contents).await
                .with_context(|| format!("Failed to persist updated feed {filename}"))?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn read_cached_or_missing(data_dir: &Path, filename: &str) -> Result<(String, bool)> {
    let path = data_dir.join(filename);
    match fs::read_to_string(&path).await {
        Ok(value) => Ok((value, false)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((String::new(), true)),
        Err(error) => Err(error).with_context(|| format!("Failed to read cached feed {}", path.display())),
    }
}

#[cfg(target_os = "linux")]
async fn load_whitelist(data_dir: &Path) -> Result<(Vec<String>, Vec<String>)> {
    let ipv4_path = data_dir.join("whitelist-ipv4.txt");
    let ipv6_path = data_dir.join("whitelist-ipv6.txt");
    let (ipv4_text, ipv6_text) = tokio::try_join!(
        async { fs::read_to_string(&ipv4_path).await.with_context(|| format!("Failed to read {}", ipv4_path.display())) },
        async { fs::read_to_string(&ipv6_path).await.with_context(|| format!("Failed to read {}", ipv6_path.display())) },
    )?;

    let mut ipv4 = Ipset::new().from(&ipv4_text);
    ipv4.consolidate();
    let mut ipv6 = Ipset::new().from(&ipv6_text);
    ipv6.consolidate();
    let mut ipv4_networks: Vec<_> = ipv4.ips.into_iter().map(|network| network.to_string()).collect();
    let mut ipv6_networks: Vec<_> = ipv6.ips.into_iter().map(|network| network.to_string()).collect();
    ipv4_networks.sort();
    ipv6_networks.sort();
    Ok((ipv4_networks, ipv6_networks))
}

async fn github_metadata(client: &reqwest::Client, cached: &str, use_cache: bool) -> Result<String> {
    if use_cache && !cached.is_empty() {
        if parse_github_ranges(cached).is_ok() {
            return Ok(cached.to_owned());
        }
    }

    download(client, GITHUB_META_URL).await
}

fn parse_github_ranges(body: &str) -> Result<Vec<ipnet::IpNet>> {
    let mut deserializer = serde_json::Deserializer::from_str(body);
    let mut ranges = HashSet::new();
    let mut required = [false; 4];
    deserializer.deserialize_map(GithubMetadataVisitor { ranges: &mut ranges, required: &mut required })
        .context("Could not parse GitHub IP metadata")?;
    deserializer.end().context("Could not parse GitHub IP metadata")?;
    for (index, field) in ["hooks", "web", "api", "git"].into_iter().enumerate() {
        ensure!(required[index], "GitHub IP metadata is missing the {field} ranges");
    }
    ensure!(ranges.iter().any(|network| matches!(network, ipnet::IpNet::V4(_))), "GitHub metadata contains no IPv4 ranges");
    ensure!(ranges.iter().any(|network| matches!(network, ipnet::IpNet::V6(_))), "GitHub metadata contains no IPv6 ranges");
    let mut ranges: Vec<_> = ranges.into_iter().collect();
    ranges.sort();
    Ok(ranges)
}

struct GithubMetadataVisitor<'a> {
    ranges: &'a mut HashSet<ipnet::IpNet>,
    required: &'a mut [bool; 4],
}

impl<'de> Visitor<'de> for GithubMetadataVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a GitHub IP metadata object")
    }

    fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<&str>()? {
            let required_index = match key {
                "hooks" => Some(0),
                "web" => Some(1),
                "api" => Some(2),
                "git" => Some(3),
                _ => None,
            };
            let mut is_array = false;
            map.next_value_seed(RangeCollector { ranges: &mut *self.ranges, is_array: Some(&mut is_array) })?;
            if let Some(index) = required_index {
                if !is_array {
                    return Err(serde::de::Error::custom(format!("GitHub metadata field {key} must be an array")));
                }
                self.required[index] = true;
            }
        }
        Ok(())
    }
}

struct RangeCollector<'a> {
    ranges: &'a mut HashSet<ipnet::IpNet>,
    is_array: Option<&'a mut bool>,
}

impl<'de> DeserializeSeed<'de> for RangeCollector<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for RangeCollector<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value containing IP range strings")
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if let Ok(network) = value.parse::<ipnet::IpNet>() {
            self.ranges.insert(network.trunc());
        }
        Ok(())
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_seq<A>(mut self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if let Some(is_array) = self.is_array.take() {
            *is_array = true;
        }
        while sequence.next_element_seed(RangeCollector { ranges: &mut *self.ranges, is_array: None })?.is_some() {}
        Ok(())
    }

    fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        while map.next_key::<serde::de::IgnoredAny>()?.is_some() {
            map.next_value_seed(RangeCollector { ranges: &mut *self.ranges, is_array: None })?;
        }
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
}

async fn remote_etag(client: &reqwest::Client, url: &str) -> Result<Option<String>> {
    let response = client.head(url).send().await?.error_for_status()?;
    Ok(response.headers().get(reqwest::header::ETAG).map(|h| h.to_str().map(str::to_owned)).transpose()?)
}

async fn download(client: &reqwest::Client, url: &str) -> Result<String> {
    Ok(client.get(url).send().await?.error_for_status()?.text().await?)
}

async fn read_or_empty(path: &Path) -> Result<String> {
    Ok(match fs::read_to_string(path).await { Ok(value) => value, Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(), Err(error) => return Err(error.into()) })
}

async fn cache_file_exists(data_dir: &Path, filename: &str) -> Result<bool> {
    let path = data_dir.join(filename);
    match fs::metadata(&path).await {
        Ok(metadata) => {
            ensure!(metadata.is_file(), "Feed cache path is not a file: {}", path.display());
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect feed cache {}", path.display())),
    }
}

async fn download_if_changed(
    client: &reqwest::Client,
    name: &str,
    url: &str,
    cached_file_exists: bool,
    remote_etag: Option<&str>,
    cached_etag: Option<&str>,
) -> Result<Option<String>> {
    let etag_changed = remote_etag.is_none() || remote_etag != cached_etag;
    if !cached_file_exists || etag_changed {
        info!("Downloading updated feed: {name}");
        Ok(Some(download(client, url).await?))
    } else {
        Ok(None)
    }
}
