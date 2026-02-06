//! TunnelCraft Logging
//!
//! Unified logging setup for all TunnelCraft applications.
//!
//! ## Usage
//!
//! ```no_run
//! use tunnelcraft_logging::{init, LogLevel};
//!
//! // Initialize with info level
//! init(LogLevel::Info);
//!
//! // Or with verbose/debug level
//! init(LogLevel::Debug);
//!
//! // Or from a boolean flag (common CLI pattern)
//! let verbose = true;
//! init(LogLevel::from_verbose(verbose));
//! ```

use tracing_subscriber::EnvFilter;

/// Log level for the application
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogLevel {
    /// Error messages only
    Error,
    /// Warnings and errors
    Warn,
    /// Info, warnings, and errors (default)
    #[default]
    Info,
    /// Debug messages and above
    Debug,
    /// All messages including trace
    Trace,
}

impl LogLevel {
    /// Create a log level from a verbose flag
    ///
    /// - `false` → `Info`
    /// - `true` → `Debug`
    pub fn from_verbose(verbose: bool) -> Self {
        if verbose {
            Self::Debug
        } else {
            Self::Info
        }
    }

    /// Create a log level from a verbosity count
    ///
    /// - `0` → `Info`
    /// - `1` → `Debug`
    /// - `2+` → `Trace`
    pub fn from_verbosity(count: u8) -> Self {
        match count {
            0 => Self::Info,
            1 => Self::Debug,
            _ => Self::Trace,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// Initialize logging with the specified level
///
/// This sets up tracing-subscriber with a formatted output.
/// Call this once at the start of your application.
///
/// # Panics
///
/// Panics if called more than once (tracing subscriber already set).
/// Use `try_init` if you need to handle this case.
pub fn init(level: LogLevel) {
    try_init(level).expect("Failed to initialize logging");
}

/// Try to initialize logging, returning an error if already initialized
pub fn try_init(level: LogLevel) -> Result<(), String> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .map_err(|e| e.to_string())
}

/// Initialize logging with the specified level and custom format
pub fn init_with_target(level: LogLevel, show_target: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(show_target)
        .init();
}

/// Initialize logging for tests (captures output for test framework)
#[cfg(test)]
pub fn init_test() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("debug"))
        .with_test_writer()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_verbose() {
        assert_eq!(LogLevel::from_verbose(false), LogLevel::Info);
        assert_eq!(LogLevel::from_verbose(true), LogLevel::Debug);
    }

    #[test]
    fn test_log_level_from_verbosity() {
        assert_eq!(LogLevel::from_verbosity(0), LogLevel::Info);
        assert_eq!(LogLevel::from_verbosity(1), LogLevel::Debug);
        assert_eq!(LogLevel::from_verbosity(2), LogLevel::Trace);
        assert_eq!(LogLevel::from_verbosity(10), LogLevel::Trace);
    }

    #[test]
    fn test_log_level_as_str() {
        assert_eq!(LogLevel::Error.as_str(), "error");
        assert_eq!(LogLevel::Warn.as_str(), "warn");
        assert_eq!(LogLevel::Info.as_str(), "info");
        assert_eq!(LogLevel::Debug.as_str(), "debug");
        assert_eq!(LogLevel::Trace.as_str(), "trace");
    }

    #[test]
    fn test_log_level_default() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }
}
