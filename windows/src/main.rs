#[cfg(not(windows))]
fn main() {
    eprintln!("windows service must be built on Windows");
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    service::run()
}

#[cfg(windows)]
mod service {
    use anyhow::{Context, Result};
    use firehol::{load_config, run_scheduler};
    use std::{env, ffi::OsString, path::PathBuf, sync::mpsc, time::Duration};
    use tokio_util::sync::CancellationToken;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_NAME: &str = "firehol-differ-nftables";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    fn install_dir() -> Result<PathBuf> {
        let executable = env::current_exe().context("Failed to locate service executable")?;
        executable
            .parent()
            .map(PathBuf::from)
            .context("Service executable path has no parent directory")
    }

    fn data_dir() -> PathBuf {
        env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("firehol-differ-nftables")
    }

    pub fn run() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    define_windows_service!(ffi_service_main, service_main);

    struct EventLogger {
        source: windows_sys::Win32::Foundation::HANDLE,
    }

    unsafe impl Send for EventLogger {}
    unsafe impl Sync for EventLogger {}

    impl log::Log for EventLogger {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.level() <= log::Level::Info
        }

        fn log(&self, record: &log::Record<'_>) {
            use windows_sys::Win32::System::EventLog::{
                EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, ReportEventW,
            };
            if !self.enabled(record.metadata()) {
                return;
            }
            let event_type = match record.level() {
                log::Level::Error => EVENTLOG_ERROR_TYPE,
                log::Level::Warn => EVENTLOG_WARNING_TYPE,
                _ => EVENTLOG_INFORMATION_TYPE,
            };
            let message = format!("{}", record.args());
            let wide: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
            let strings = [wide.as_ptr()];
            unsafe {
                let _ = ReportEventW(
                    self.source,
                    event_type,
                    0,
                    0x1000,
                    std::ptr::null_mut(),
                    1,
                    0,
                    strings.as_ptr(),
                    std::ptr::null(),
                );
            }
        }

        fn flush(&self) {}
    }

    fn init_logging() -> Result<()> {
        use windows_sys::Win32::System::EventLog::RegisterEventSourceW;
        let source_name: Vec<u16> = "Iodrive\\firehol-differ-nftables"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let source = unsafe { RegisterEventSourceW(std::ptr::null(), source_name.as_ptr()) };
        if source.is_null() {
            anyhow::bail!(
                "Failed to register Event Log source Iodrive\\firehol-differ-nftables (is it installed?)"
            );
        }
        log::set_boxed_logger(Box::new(EventLogger { source }))
            .context("Failed to initialize Windows Event Log logger")?;
        log::set_max_level(log::LevelFilter::Info);
        Ok(())
    }
    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            log::error!("Service stopped with an error: {error:#}");
        }
    }

    fn run_service() -> Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let event_handler = move |event| -> ServiceControlHandlerResult {
            match event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
        if let Err(error) = init_logging() {
            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::ServiceSpecific(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;
            return Err(error);
        }
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })?;

        let runtime = tokio::runtime::Runtime::new().context("Failed to create Tokio runtime")?;
        let executable_dir = install_dir()?;
        let config = match runtime.block_on(load_config(&executable_dir)) {
            Ok(config) => config,
            Err(error) => {
                log::error!("Failed to load configuration: {error:#}");
                status_handle.set_service_status(ServiceStatus {
                    service_type: SERVICE_TYPE,
                    current_state: ServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::ServiceSpecific(1),
                    checkpoint: 0,
                    wait_hint: Duration::default(),
                    process_id: None,
                })?;
                return Err(error);
            }
        };
        let output_dir = if config.path.as_os_str().is_empty() || config.path == PathBuf::from(".")
        {
            data_dir()
        } else if config.path.is_absolute() {
            config.path.clone()
        } else {
            data_dir().join(&config.path)
        };
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let worker = runtime.spawn(run_scheduler(output_dir, config, worker_cancellation));

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let scheduler_result = loop {
            match shutdown_rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                    cancellation.cancel();
                    break runtime
                        .block_on(worker)
                        .context("Scheduler task failed")?
                        .context("Scheduler failed during shutdown");
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if worker.is_finished() {
                break runtime
                    .block_on(worker)
                    .context("Scheduler task failed")?
                    .context("Scheduler stopped unexpectedly");
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        if let Err(error) = scheduler_result {
            log::error!("Scheduler failed: {error:#}");
            status_handle.set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::ServiceSpecific(1),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })?;
            return Err(error);
        }
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }
}
