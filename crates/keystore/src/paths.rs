//! Path utilities for cross-platform support

use std::path::{Path, PathBuf};

/// Expand a path, replacing `~` with the user's home directory
///
/// # Examples
///
/// ```
/// use tunnelcraft_keystore::expand_path;
/// use std::path::PathBuf;
///
/// let path = expand_path(&PathBuf::from("~/keys/node.key"));
/// assert!(!path.starts_with("~"));
/// ```
pub fn expand_path(path: &Path) -> PathBuf {
    if path.starts_with("~") {
        if let Ok(stripped) = path.strip_prefix("~") {
            if let Some(home) = home_dir() {
                return home.join(stripped);
            }
        }
    }
    path.to_path_buf()
}

/// Get the user's home directory
fn home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

/// Get the default keystore directory for the current platform
///
/// - macOS: `~/Library/Application Support/TunnelCraft/keys`
/// - Linux: `~/.local/share/tunnelcraft/keys`
/// - Windows: `%APPDATA%\TunnelCraft\keys`
pub fn default_keystore_dir() -> PathBuf {
    data_dir().join("keys")
}

/// Get the default config directory for the current platform
///
/// - macOS: `~/Library/Application Support/TunnelCraft`
/// - Linux: `~/.config/tunnelcraft`
/// - Windows: `%APPDATA%\TunnelCraft`
pub fn default_config_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .map(|h| h.join("Library/Application Support/TunnelCraft"))
            .unwrap_or_else(|| PathBuf::from(".tunnelcraft"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                home_dir()
                    .map(|h| h.join(".config"))
                    .unwrap_or_else(|| PathBuf::from("."))
            })
            .join("tunnelcraft")
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("TunnelCraft")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        home_dir()
            .map(|h| h.join(".tunnelcraft"))
            .unwrap_or_else(|| PathBuf::from(".tunnelcraft"))
    }
}

/// Get the data directory for the current platform
fn data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .map(|h| h.join("Library/Application Support/TunnelCraft"))
            .unwrap_or_else(|| PathBuf::from(".tunnelcraft"))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                home_dir()
                    .map(|h| h.join(".local/share"))
                    .unwrap_or_else(|| PathBuf::from("."))
            })
            .join("tunnelcraft")
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("TunnelCraft")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        home_dir()
            .map(|h| h.join(".tunnelcraft"))
            .unwrap_or_else(|| PathBuf::from(".tunnelcraft"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_path_no_tilde() {
        let path = PathBuf::from("/absolute/path");
        assert_eq!(expand_path(&path), path);
    }

    #[test]
    fn test_expand_path_with_tilde() {
        let path = PathBuf::from("~/some/path");
        let expanded = expand_path(&path);
        assert!(!expanded.starts_with("~"));
        assert!(expanded.ends_with("some/path"));
    }

    #[test]
    fn test_default_keystore_dir() {
        let dir = default_keystore_dir();
        assert!(dir.ends_with("keys"));
    }

    #[test]
    fn test_default_config_dir() {
        let dir = default_config_dir();
        let dir_str = dir.to_string_lossy().to_lowercase();
        assert!(dir_str.contains("tunnelcraft"));
    }
}
