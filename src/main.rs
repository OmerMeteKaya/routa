//! `routa` binary entry point: loads a config file, validates it,
//! initializes logging, builds a server, and runs it.
//!
//! Usage: routa [config-file]
//!   config-file defaults to "routa.conf" in the current directory.
//!
//! Deliberately thin and fails loudly on a missing/invalid config
//! file rather than silently falling back to hardcoded defaults -- a
//! production server quietly running with defaults instead of an
//! operator's actual intended config (wrong port, missing TLS,
//! unintended upstreams) is a worse failure mode than refusing to
//! start with a clear error message.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use routa::core::config;
use routa::core::event_loop;
use routa::core::server::RoutaServer;
use routa::util::logger;

fn main() {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "routa.conf".to_string());

    let (cfg, parse_ctx) = match config::load(std::path::Path::new(&config_path)) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("routa: failed to load config file '{config_path}': {e}");
            eprintln!("routa: see examples/routa.conf for the full config reference");
            std::process::exit(1);
        }
    };

    for warning in &parse_ctx.warnings {
        eprintln!("routa: config warning: {warning:?}");
    }

    let validation_errors = config::validate(&cfg);
    if !validation_errors.is_empty() {
        eprintln!("routa: config file '{config_path}' is invalid:");
        for error in &validation_errors {
            eprintln!("  - {error}");
        }
        std::process::exit(1);
    }

    // Logging is initialized as early as possible -- everything from
    // here on (server construction, worker startup, request handling)
    // logs through this. Held for the process's lifetime: dropping it
    // would flush and stop accepting further log lines from the
    // non-blocking file writer (see LoggerGuard's own doc comment).
    let logger_config = logger::config_from_strings(&cfg.log_level, &cfg.log_file);
    let _logger_guard = match logger::init(&logger_config) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("routa: failed to initialize logging: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!(config_path = %config_path, port = cfg.port, "routa starting");

    let port = cfg.port as u16;
    let n_workers = cfg.n_workers as usize;

    let server = match RoutaServer::from_config(cfg) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(error = %e, "failed to build server from config");
            std::process::exit(1);
        }
    };

    let pool = event_loop::run(server, port, n_workers);

    // SIGTERM/SIGINT initiate a graceful shutdown: WorkerPool::shutdown()
    // signals every worker thread to stop accepting new connections
    // and exit its poll loop, then joins each thread.
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        if let Err(e) = signal_hook::flag::register(sig, Arc::clone(&shutdown_requested)) {
            tracing::warn!(signal = sig, error = %e, "failed to register signal handler");
        }
    }

    tracing::info!(port, n_workers, "routa ready");

    while !shutdown_requested.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    tracing::info!("shutdown signal received, draining workers");
    pool.shutdown();
    tracing::info!("routa stopped");
}
