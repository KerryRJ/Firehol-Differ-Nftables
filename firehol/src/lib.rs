mod config;
mod etags;
mod ipset;

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

    if etags.l1.as_deref() == l1_etag.as_deref() && etags.l2.as_deref() == l2_etag.as_deref() {
        info!("ETags have not changed.");
        return Ok(());
    }

    info!("Downloading the FireHOL level 1 and level 2 ipsets ...");
    let (l1_remote, l2_remote) = tokio::try_join!(download(&client, &config.l1_url), download(&client, &config.l2_url))?;
    let l1_local = read_or_empty(&data_dir.join("firehol_level1.netset")).await?;
    let l2_local = read_or_empty(&data_dir.join("firehol_level2.netset")).await?;

    let mut old = Ipset::new().from(&l1_local).from(&l2_local); let mut new = Ipset::new().from(&l1_remote).from(&l2_remote);
    old.consolidate(); new.consolidate();
    let mut additions: Vec<_> = new.ips.difference(&old.ips).cloned().collect();
    let mut deletions: Vec<_> = old.ips.difference(&new.ips).cloned().collect();
    additions.sort(); deletions.sort();
    let total = additions.len() + deletions.len();

    tokio::try_join!(
        fs::write(data_dir.join("firehol_level1.netset"), &l1_remote),
        fs::write(data_dir.join("firehol_level2.netset"), &l2_remote)
    )?;
    info!("Remote IPs: L1={} L2={} T={}", rows(&l1_remote), rows(&l2_remote), rows(&l1_remote) + rows(&l2_remote));
    info!("Total changes: {total}");
    etags.l1 = l1_etag;
    etags.l2 = l2_etag;
    etags.save(data_dir).await?;
    info!("Elapsed time: {:.3} seconds", start.elapsed().as_secs_f64());
    Ok(())
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
