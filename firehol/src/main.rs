use anyhow::Result;
use clap::{Parser, Subcommand};
use firehol::{load_config, run_once, run_scheduler};
use std::{fs, path::PathBuf};
use tokio_util::sync::CancellationToken;

fn init_logging(data_dir: &std::path::Path) -> Result<()> {
    let log_dir = if cfg!(windows) {
        std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.to_path_buf())
            .join("firehol")
            .join("logs")
    } else {
        PathBuf::from("/var/log/firehol")
    };
    fs::create_dir_all(&log_dir)?;
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("firehol.log"))?;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();
    Ok(())
}

#[derive(Debug, Parser)]
#[command(name = "firehol", about = "Download and diff FireHOL IP sets")]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Download the current lists and write a delta immediately.
    RunOnce,
    /// Run continuously using config.toml.
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.data_dir)?;

    match cli.command.unwrap_or(Command::RunOnce) {
        Command::RunOnce => {
            let config = load_config(&cli.data_dir).await?;
            run_once(&cli.data_dir, &config).await
        }
        Command::Run => {
            let config = load_config(&cli.data_dir).await?;
            let cancellation = CancellationToken::new();
            let scheduler = tokio::spawn(run_scheduler(
                config.path.clone(),
                config,
                cancellation.clone(),
            ));

            tokio::select! {
                result = scheduler => result??,
                result = tokio::signal::ctrl_c() => {
                    result?;
                    cancellation.cancel();
                }
            }
            Ok(())
        }
    }
}
