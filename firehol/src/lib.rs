mod config;
mod etags;
mod ipset;
#[cfg(target_os = "linux")]
#[path = "nftables.rs"]
mod nftables_sync;

pub use config::{load_config, Config};
use anyhow::Result;
use etags::Etags;
use ipset::Ipset;
use log::info;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::fs;
use tokio_util::sync::CancellationToken;

pub async fn run_scheduler(data_dir: PathBuf, config: Config, cancellation: CancellationToken) -> Result<()> {
    let mut ticker = tokio::time::interval(config.interval);
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => return Ok(()),
            _ = ticker.tick() => run_once(&data_dir, &config).await?,
        }
    }
}

pub async fn run_once(data_dir: &Path, config: &Config) -> Result<()> {
    fs::create_dir_all(data_dir).await?;
    let start = Instant::now();
    let mut etags = Etags::load(data_dir).await.unwrap_or_default();
    let client = reqwest::Client::new();
    let l1_etag = remote_etag(&client, &config.l1_url).await?;
    let l2_etag = remote_etag(&client, &config.l2_url).await?;
    let bogons_ipv4_etag = remote_etag(&client, &config.bogons_ipv4_url).await?;
    let bogons_ipv6_etag = remote_etag(&client, &config.bogons_ipv6_url).await?;

    if l1_etag.is_some()
        && l2_etag.is_some()
        && bogons_ipv4_etag.is_some()
        && bogons_ipv6_etag.is_some()
        && etags.l1.as_deref() == l1_etag.as_deref()
        && etags.l2.as_deref() == l2_etag.as_deref()
        && etags.bogons_ipv4.as_deref() == bogons_ipv4_etag.as_deref()
        && etags.bogons_ipv6.as_deref() == bogons_ipv6_etag.as_deref()
    {
        info!("ETags have not changed.");
        return Ok(());
    }

    info!("Downloading FireHOL level 1 and 2 and Team Cymru fullbogons IPv4 and IPv6 lists ...");
    let (l1_remote, l2_remote, bogons_ipv4_remote, bogons_ipv6_remote) = tokio::try_join!(
        download(&client, &config.l1_url),
        download(&client, &config.l2_url),
        download(&client, &config.bogons_ipv4_url),
        download(&client, &config.bogons_ipv6_url),
    )?;
    let l1_local = read_or_empty(&data_dir.join("firehol_level1.netset")).await?;
    let l2_local = read_or_empty(&data_dir.join("firehol_level2.netset")).await?;
    let bogons_ipv4_local = read_or_empty(&data_dir.join("fullbogons-ipv4.txt")).await?;
    let bogons_ipv6_local = read_or_empty(&data_dir.join("fullbogons-ipv6.txt")).await?;

    let old_lists = [&l1_local, &l2_local, &bogons_ipv4_local, &bogons_ipv6_local];
    let new_lists = [&l1_remote, &l2_remote, &bogons_ipv4_remote, &bogons_ipv6_remote];
    let mut new_sets = Vec::new();
    let mut total = 0;
    for (old_list, new_list) in old_lists.into_iter().zip(new_lists) {
        let mut old = Ipset::new().from(old_list);
        let mut new = Ipset::new().from(new_list);
        old.consolidate();
        new.consolidate();
        let mut additions: Vec<_> = new.ips.difference(&old.ips).cloned().collect();
        let mut deletions: Vec<_> = old.ips.difference(&new.ips).cloned().collect();
        additions.sort();
        deletions.sort();
        total += additions.len() + deletions.len();
        new_sets.push(new.ips);
    }

    let new_sets: Vec<Vec<String>> = new_sets.into_iter().map(|set| {
        let mut entries: Vec<_> = set.into_iter().collect();
        entries.sort();
        entries
    }).collect();
    #[cfg(target_os = "linux")]
    nftables_sync::replace_lists(&new_sets, &config.whitelist)?;

    tokio::try_join!(
        fs::write(data_dir.join("firehol_level1.netset"), &l1_remote),
        fs::write(data_dir.join("firehol_level2.netset"), &l2_remote),
        fs::write(data_dir.join("fullbogons-ipv4.txt"), &bogons_ipv4_remote),
        fs::write(data_dir.join("fullbogons-ipv6.txt"), &bogons_ipv6_remote)
    )?;
    info!("Remote IPs: L1={} L2={} Bogons4={} Bogons6={} T={}", rows(&l1_remote), rows(&l2_remote), rows(&bogons_ipv4_remote), rows(&bogons_ipv6_remote), rows(&l1_remote) + rows(&l2_remote) + rows(&bogons_ipv4_remote) + rows(&bogons_ipv6_remote));
    info!("Total changes: {total}");
    etags.l1 = l1_etag;
    etags.l2 = l2_etag;
    etags.bogons_ipv4 = bogons_ipv4_etag;
    etags.bogons_ipv6 = bogons_ipv6_etag;
    etags.save(data_dir).await?;
    info!("Elapsed time: {:.3} seconds", start.elapsed().as_secs_f64());
    Ok(())
}

/// Rebuild the nftables sets from the last successfully downloaded lists.
/// This is used after a reboot or an nftables ruleset reload.
#[cfg(target_os = "linux")]
pub async fn restore_cached(data_dir: &Path, config: &Config) -> Result<()> {
    let l1 = read_or_empty(&data_dir.join("firehol_level1.netset")).await?;
    let l2 = read_or_empty(&data_dir.join("firehol_level2.netset")).await?;
    let bogons_ipv4 = read_or_empty(&data_dir.join("fullbogons-ipv4.txt")).await?;
    let bogons_ipv6 = read_or_empty(&data_dir.join("fullbogons-ipv6.txt")).await?;

    let lists = [&l1, &l2, &bogons_ipv4, &bogons_ipv6];
    let mut networks = Vec::new();
    for list in lists {
        let mut set = Ipset::new().from(list);
        set.consolidate();
        let mut entries: Vec<_> = set.ips.into_iter().collect();
        entries.sort();
        networks.push(entries);
    }
    nftables_sync::replace_lists(&networks, &config.whitelist)
}

async fn remote_etag(client: &reqwest::Client, url: &str) -> Result<Option<String>> {
    Ok(client.head(url).send().await?.headers().get(reqwest::header::ETAG).map(|h| h.to_str().map(str::to_owned)).transpose()?)
}

async fn download(client: &reqwest::Client, url: &str) -> Result<String> {
    Ok(client.get(url).send().await?.text().await?)
}

async fn read_or_empty(path: &Path) -> Result<String> {
    Ok(match fs::read_to_string(path).await { Ok(value) => value, Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(), Err(error) => return Err(error.into()) })
}

fn rows(value: &str) -> usize { value.lines().filter(|line| { let line = line.trim(); !line.is_empty() && !line.starts_with('#') }).count() }
