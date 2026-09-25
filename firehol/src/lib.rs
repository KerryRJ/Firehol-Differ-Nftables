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

    if l1_etag.is_some()
        && l2_etag.is_some()
        && bogons_ipv4_etag.is_some()
        && bogons_ipv6_etag.is_some()
        && github_meta_etag.is_some()
        && etags.l1.as_deref() == l1_etag.as_deref()
        && etags.l2.as_deref() == l2_etag.as_deref()
        && etags.bogons_ipv4.as_deref() == bogons_ipv4_etag.as_deref()
        && etags.bogons_ipv6.as_deref() == bogons_ipv6_etag.as_deref()
        && etags.github_meta.as_deref() == github_meta_etag.as_deref()
    {
        info!("ETags have not changed.");
        #[cfg(target_os = "linux")]
        if _restore_if_unchanged {
            restore_cached(data_dir, config).await?;
        }
        return Ok(());
    }

    info!("Downloading FireHOL, Team Cymru, and GitHub IP lists ...");
    let previous_lists = [
        read_or_empty(&data_dir.join("firehol_level1.netset")).await?,
        read_or_empty(&data_dir.join("firehol_level2.netset")).await?,
        read_or_empty(&data_dir.join("fullbogons-ipv4.txt")).await?,
        read_or_empty(&data_dir.join("fullbogons-ipv6.txt")).await?,
    ];
    let l1_remote = download(client, &config.l1_url).await?;
    let l2_remote = download(client, &config.l2_url).await?;
    let bogons_ipv4_remote = download(client, &config.bogons_ipv4_url).await?;
    let bogons_ipv6_remote = download(client, &config.bogons_ipv6_url).await?;
    let cached_github_meta = read_or_empty(&data_dir.join("github-meta.json")).await?;
    let github_meta_unchanged = github_meta_etag.is_some()
        && etags.github_meta.as_deref() == github_meta_etag.as_deref();
    let github_meta = github_metadata(client, &cached_github_meta, github_meta_unchanged).await?;
    #[cfg(target_os = "linux")]
    let mut new_sets = Vec::with_capacity(4);
    let mut total = 0;
    for (old_list, new_list) in previous_lists.iter().zip([
        &l1_remote,
        &l2_remote,
        &bogons_ipv4_remote,
        &bogons_ipv6_remote,
    ]) {
        let mut old = Ipset::new().from(&old_list);
        let mut new = Ipset::new().from(new_list);
        old.consolidate();
        new.consolidate();
        let additions = new.ips.difference(&old.ips).count();
        let deletions = old.ips.difference(&new.ips).count();
        total += additions + deletions;
        #[cfg(target_os = "linux")]
        new_sets.push(new.ips);
    }

    #[cfg(target_os = "linux")]
    let new_sets: Vec<Vec<ipnet::IpNet>> = new_sets.into_iter().map(|set| {
        let mut entries: Vec<_> = set.into_iter().collect();
        entries.sort();
        entries
    }).collect();
    #[cfg(target_os = "linux")]
    let nftables_result = async {
        let _github_networks = parse_github_ranges(&github_meta)?;
        let (whitelist_ipv4, whitelist_ipv6) = load_whitelist(data_dir).await?;
        nftables_sync::replace_lists(&new_sets, &whitelist_ipv4, &whitelist_ipv6, &_github_networks, config.log_blocked)
    }.await;
    #[cfg(target_os = "linux")]
    let persist_result = persist_downloads(data_dir, &l1_remote, &l2_remote, &bogons_ipv4_remote, &bogons_ipv6_remote, &github_meta).await;
    persist_result?;
    #[cfg(target_os = "linux")]
    nftables_result?;

    info!("Remote IPs: L1={} L2={} Bogons4={} Bogons6={} T={}", rows(&l1_remote), rows(&l2_remote), rows(&bogons_ipv4_remote), rows(&bogons_ipv6_remote), rows(&l1_remote) + rows(&l2_remote) + rows(&bogons_ipv4_remote) + rows(&bogons_ipv6_remote));
    info!("Total changes: {total}");
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
        nftables_sync::replace_lists(&networks, &whitelist_ipv4, &whitelist_ipv6, &github_networks, config.log_blocked)
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

fn parse_github_ranges(body: &str) -> Result<Vec<String>> {
    let metadata: serde_json::Value = serde_json::from_str(body).context("Could not parse GitHub IP metadata")?;
    ensure!(metadata.is_object(), "GitHub IP metadata must be a JSON object");
    for field in ["hooks", "web", "api", "git"] {
        ensure!(metadata.get(field).and_then(serde_json::Value::as_array).is_some(), "GitHub IP metadata is missing the {field} ranges");
    }

    let mut ranges = HashSet::new();
    collect_ip_ranges(&metadata, &mut ranges);
    ensure!(ranges.iter().any(|range| range.contains('.')), "GitHub metadata contains no IPv4 ranges");
    ensure!(ranges.iter().any(|range| range.contains(':')), "GitHub metadata contains no IPv6 ranges");
    let mut ranges: Vec<_> = ranges.into_iter().collect();
    ranges.sort();
    Ok(ranges)
}

fn collect_ip_ranges(value: &serde_json::Value, ranges: &mut HashSet<String>) {
    match value {
        serde_json::Value::Array(values) => values.iter().for_each(|value| collect_ip_ranges(value, ranges)),
        serde_json::Value::Object(values) => values.values().for_each(|value| collect_ip_ranges(value, ranges)),
        serde_json::Value::String(value) => {
            if let Ok(network) = value.parse::<ipnet::IpNet>() {
                ranges.insert(network.trunc().to_string());
            }
        }
        _ => {}
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

fn rows(value: &str) -> usize { value.lines().filter(|line| { let line = line.trim(); !line.is_empty() && !line.starts_with('#') }).count() }
