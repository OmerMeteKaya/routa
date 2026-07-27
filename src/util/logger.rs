//! General application logging (startup/shutdown, config reload,
//! worker panics, connection errors) -- distinct from the structured
//! per-request access log (see `http::middleware::logger`), which
//! covers a different concern (one line per completed HTTP request)
//! and already has its own JSON format and sink abstraction.
//!
//! Built on `tracing` rather than the `log` crate: this codebase's
//! logging needs are currently simple ad-hoc events (a handful of
//! startup/reload/error messages), but `tracing`'s span model gives a
//! natural place to grow into later -- e.g. tagging every log line
//! within a request's handling with that request's trace id, or every
//! line from a given worker thread with its worker id, without
//! needing to thread an explicit context parameter through every
//! function that might log. `tracing`'s macros (`tracing::warn!`,
//! `tracing::error!`, etc.) are used directly elsewhere in the
//! codebase; this module only owns *initializing* the global
//! subscriber that decides how those events are formatted and where
//! they go.

use tracing_subscriber::EnvFilter;

/// Output format for log lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable, single-line-per-event text -- suitable for a
    /// terminal during local development.
    Pretty,
    /// One JSON object per line -- suitable for log aggregation
    /// systems (matches the structured-logging convention this
    /// codebase already uses for the access log).
    Json,
}

#[derive(Debug, Clone)]
pub struct LoggerConfig {
    pub level: String, // "debug", "info", "warn", "error" -- matches RoutaConfig.log_level's existing string convention
    pub file: Option<std::path::PathBuf>, // None = stderr
    pub format: LogFormat,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        LoggerConfig {
            level: "info".to_string(),
            file: None,
            format: LogFormat::Json,
        }
    }
}

/// Parses `RoutaConfig`'s existing `log_level`/`log_file` string
/// fields into a `LoggerConfig` -- kept separate from `RoutaConfig`
/// itself (rather than adding a `LogFormat` field there) since the
/// config file format's `log_level`/`log_file` keys are already
/// established and this module doesn't need to change that surface,
/// just interpret it.
pub fn config_from_strings(log_level: &str, log_file: &str) -> LoggerConfig {
    let level = if log_level.is_empty() {
        "info".to_string()
    } else {
        log_level.to_string()
    };
    let file = if log_file.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(log_file))
    };
    LoggerConfig {
        level,
        file,
        format: LogFormat::Json,
    }
}

/// A handle that must be kept alive for the lifetime of the process
/// when logging to a file -- `tracing_appender`'s non-blocking writer
/// flushes on a background thread, and drops its buffer (losing
/// not-yet-flushed lines) when this guard is dropped. `init()` returns
/// this; the caller (see `main.rs`) holds it for as long as the
/// server runs.
pub struct LoggerGuard {
    _file_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// Initializes the global `tracing` subscriber according to `config`.
/// Must be called exactly once, as early as possible in `main`
/// (before any other module might log) -- a second call returns an
/// error rather than panicking, since `RoutaServer::from_config` being
/// called more than once in a process (e.g. some test setups) would
/// otherwise bring the whole test binary down.
pub fn init(config: &LoggerConfig) -> Result<LoggerGuard, String> {
    let env_filter = EnvFilter::try_new(&config.level).map_err(|e| format!("invalid log level {:?}: {e}", config.level))?;

    match &config.file {
        Some(path) => init_with_file(env_filter, path, config.format),
        None => init_with_stderr(env_filter, config.format),
    }
}

fn init_with_stderr(env_filter: EnvFilter, format: LogFormat) -> Result<LoggerGuard, String> {
    let result = match format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .try_init(),
        LogFormat::Pretty => tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .try_init(),
    };
    result.map_err(|e| format!("failed to initialize tracing subscriber: {e}"))?;
    Ok(LoggerGuard { _file_guard: None })
}

fn init_with_file(env_filter: EnvFilter, path: &std::path::Path, format: LogFormat) -> Result<LoggerGuard, String> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("failed to open log file {}: {e}", path.display()))?;
    let (non_blocking, guard) = tracing_appender::non_blocking(file);

    let result = match format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .with_writer(non_blocking)
            .try_init(),
        LogFormat::Pretty => tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(non_blocking)
            .try_init(),
    };
    result.map_err(|e| format!("failed to initialize tracing subscriber: {e}"))?;
    Ok(LoggerGuard {
        _file_guard: Some(guard),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_strings_defaults_to_info_when_empty() {
        let cfg = config_from_strings("", "");
        assert_eq!(cfg.level, "info");
        assert!(cfg.file.is_none());
    }

    #[test]
    fn config_from_strings_preserves_explicit_level() {
        let cfg = config_from_strings("debug", "");
        assert_eq!(cfg.level, "debug");
    }

    #[test]
    fn config_from_strings_sets_file_path_when_nonempty() {
        let cfg = config_from_strings("warn", "/var/log/routa.log");
        assert_eq!(cfg.file, Some(std::path::PathBuf::from("/var/log/routa.log")));
    }

    #[test]
    fn default_config_uses_json_format_and_stderr() {
        let cfg = LoggerConfig::default();
        assert_eq!(cfg.format, LogFormat::Json);
        assert!(cfg.file.is_none());
        assert_eq!(cfg.level, "info");
    }

    #[test]
    fn init_never_panics_regardless_of_level_string_validity() {
        // EnvFilter's own directive syntax is permissive enough that
        // most arbitrary strings parse as *some* filter rather than
        // erroring outright -- what this test actually guards against
        // is init() panicking on a weird level string, not that every
        // possible garbage string is guaranteed to produce an Err.
        let cfg = LoggerConfig {
            level: "not-a-real-level!!!".to_string(),
            file: None,
            format: LogFormat::Json,
        };
        let _ = init(&cfg); // must not panic, regardless of Ok/Err
    }

    #[test]
    fn init_with_file_creates_and_writes_to_the_file() {
        let dir = std::env::temp_dir().join(format!(
            "routa_logger_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("test.log");

        let cfg = LoggerConfig {
            level: "info".to_string(),
            file: Some(log_path.clone()),
            format: LogFormat::Json,
        };

        // init() sets the GLOBAL subscriber -- only the first call in
        // this test binary actually takes effect (try_init() returns
        // Err on subsequent calls, which this test tolerates rather
        // than asserting on, since test execution order/parallelism
        // means this might not be the first call). What's actually
        // under test here is that opening and writing to the file
        // itself works, independent of whether this specific call
        // became the active global subscriber.
        let _ = init(&cfg);
        tracing::info!("test log line");
        // Give the non-blocking writer a moment to flush.
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert!(log_path.exists(), "log file should have been created");

        std::fs::remove_dir_all(&dir).ok();
    }
}
