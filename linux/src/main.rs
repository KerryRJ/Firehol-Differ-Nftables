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
use firehol::{load_config, run_scheduler};
use log::info;
use std::{fs, path::Path};
use tokio_util::sync::CancellationToken;

fn init_logging() -> Result<()> {
    let log_dir = Path::new("/var/log/firehol-differ-nftables");
    fs::create_dir_all(log_dir).context("Failed to create /var/log/firehol-differ-nftables")?;
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("firehol.log"))
        .context("Failed to open /var/log/firehol-differ-nftables/firehol.log")?;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();
    Ok(())
}

pub async fn run() -> Result<()> {
    init_logging()?;
    let mut reload = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("Failed to listen for reload signal")?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("Failed to listen for shutdown signal")?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("Failed to listen for interrupt signal")?;

    let mut scheduler = start_scheduler().await?;
    loop {
        tokio::select! {
            result = &mut scheduler.task => {
                result.context("Scheduler task failed")??;
                return Ok(());
            }
            _ = reload.recv() => {
                info!("Received reload signal; reloading configuration");
                let new_scheduler = match start_scheduler().await {
                    Ok(scheduler) => scheduler,
                    Err(error) => {
                        log::error!("Failed to reload configuration; keeping current scheduler: {error:#}");
                        continue;
                    }
                };
                scheduler.cancellation.cancel();
                scheduler.task.await.context("Scheduler task failed during reload")??;
                scheduler = new_scheduler;
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

async fn start_scheduler() -> Result<Scheduler> {
    let config = load_config(Path::new(".")).await?;
    let data_dir = config.path.clone();
    let cancellation = CancellationToken::new();
    let task = tokio::spawn(run_scheduler(data_dir, config, cancellation.clone()));
    Ok(Scheduler { cancellation, task })
}
}
