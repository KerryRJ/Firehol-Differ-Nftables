#[cfg(not(unix))]
fn main() {
    eprintln!("The Linux service must be built on a Unix platform.");
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    service::run().await
}

#[cfg(unix)]
mod service {
use anyhow::{Context, Result};
use firehol::{load_config, restore_cached, run_scheduler};
use log::info;
use std::{fs, path::Path};
use tokio_util::sync::CancellationToken;

fn init_logging() -> Result<()> {
    let log_dir = Path::new("/var/log/firehol-differ-nftables");
    fs::create_dir_all(log_dir).context("Failed to create /var/log/firehol-differ-nftables")?;
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("iodrive.log"))
        .context("Failed to open /var/log/firehol-differ-nftables/iodrive.log")?;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();
    Ok(())
}

pub async fn run() -> Result<()> {
    init_logging()?;
    let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("Failed to listen for reload signal")?;
    let mut nftables_reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .context("Failed to listen for nftables reload notification")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("Failed to listen for shutdown signal")?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("Failed to listen for interrupt signal")?;

    let initial_config = load_config(Path::new(".")).await?;
    let mut restore_data_dir = initial_config.path.clone();
    if let Err(error) = restore_cached(&restore_data_dir, &initial_config).await {
        log::warn!("Could not restore cached nftables sets at startup: {error:#}");
    }
    let mut scheduler = start_scheduler(initial_config.clone()).await?;
    loop {
        tokio::select! {
            result = &mut scheduler.task => {
                result.context("Scheduler task failed")??;
                return Ok(());
            }
            _ = reload.recv() => {
                info!("Received reload signal; reloading configuration");
                let new_config = match load_config(Path::new(".")).await {
                    Ok(config) => config,
                    Err(error) => {
                        log::error!("Failed to reload configuration; keeping current scheduler: {error:#}");
                        continue;
                    }
                };
                let new_data_dir = new_config.path.clone();
                if let Err(error) = restore_cached(&new_data_dir, &new_config).await {
                    log::error!("Failed to apply reloaded configuration to cached nftables sets: {error:#}");
                }
                let new_scheduler = start_scheduler(new_config.clone()).await?;
                scheduler.cancellation.cancel();
                scheduler.task.await.context("Scheduler task failed during reload")??;
                scheduler = new_scheduler;
                restore_data_dir = new_data_dir;
            }
            _ = nftables_reload.recv() => {
                info!("Received nftables reload notification; restoring cached sets");
                let config = load_config(Path::new(".")).await?;
                if let Err(error) = restore_cached(&restore_data_dir, &config).await {
                    log::error!("Failed to restore cached nftables sets: {error:#}");
                }
            }
            _ = terminate.recv() => {
                info!("Received termination signal; shutting down");
                break;
            }
            _ = interrupt.recv() => {
                info!("Received interrupt signal; shutting down");
                break;
            }
        }
    }
    scheduler.cancellation.cancel();
    scheduler.task.await.context("Scheduler task failed during shutdown")??;
    Ok(())
}

struct Scheduler {
    cancellation: CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
}

async fn start_scheduler(config: firehol::Config) -> Result<Scheduler> {
    let data_dir = config.path.clone();
    let cancellation = CancellationToken::new();
    let task_cancellation = cancellation.clone();
    let task = tokio::spawn(async move {
        run_scheduler(data_dir, config, task_cancellation).await
    });
    Ok(Scheduler { cancellation, task })
}
}
