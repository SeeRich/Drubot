use std::{io, path::PathBuf};

use bytesize::ByteSize;
use file_rotate::{
    compression::Compression,
    suffix::{AppendTimestamp, FileLimit},
    ContentLimit, FileRotate,
};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{filter::FromEnvError, prelude::*, EnvFilter};

/// To set console logging via environment variable use RUST_LOG=none,drubot=debug
pub fn init_logging() -> Result<Vec<WorkerGuard>, FromEnvError> {
    // Vector of guards that guarantee logs are flushed when they are dropped
    let mut guards = Vec::<WorkerGuard>::new();

    // Non-blocking stdio logging
    let (non_blocking_io, _io_guard) = tracing_appender::non_blocking(io::stdout());
    guards.push(_io_guard);
    let layer_stdio = tracing_subscriber::fmt::Layer::default()
        .with_writer(non_blocking_io)
        .with_line_number(true)
        .with_filter(EnvFilter::from_default_env());

    let mut o_log_dir = dirs::data_local_dir();
    // Create application log directory if it doesn't exist
    if let Some(ref mut log_dir) = o_log_dir {
        log_dir.push("PipeWrench");
        log_dir.push("Logs");
        if !log_dir.exists() {
            o_log_dir = if std::fs::create_dir_all(log_dir.clone()).is_ok() {
                Some(log_dir.to_path_buf())
            } else {
                None
            }
        }
    }

    // File we are currently logging to
    let mut logging_file: Option<PathBuf> = None;

    // Non-blocking file logging
    let layer_file = if let Some(ref mut app_log_dir) = o_log_dir {
        let mut log_fp = app_log_dir.clone();
        log_fp.push("log");

        // Copy logging file for debugging log
        logging_file = Some(log_fp.clone());

        let mut file_log = FileRotate::new(
            log_fp,
            AppendTimestamp::default(FileLimit::MaxFiles(10)),
            ContentLimit::Bytes(ByteSize::mb(5).as_u64() as usize),
            Compression::None,
            #[cfg(unix)]
            None,
        );

        // Always rotate on startup
        let _ = file_log.rotate();

        let (non_blocking_file, _file_guard) = tracing_appender::non_blocking(file_log);
        guards.push(_file_guard);

        // For file logging, use a filter that filters out third-party crate logs
        let file_filter = EnvFilter::from_default_env()
            .add_directive("none".parse()?)
            .add_directive("drubot=trace".parse()?);

        Some(
            tracing_subscriber::fmt::Layer::default()
                .with_writer(non_blocking_file)
                .with_ansi(false)
                .with_filter(file_filter),
        )
    } else {
        None
    };

    // Setup tracing subscribers
    tracing_subscriber::registry()
        .with(layer_stdio)
        .with(layer_file)
        .init();

    if let Some(log_file) = logging_file {
        log::info!("Logging to: {}", log_file.display());
    }

    Ok(guards)
}
