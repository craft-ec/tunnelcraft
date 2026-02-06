//! Keypair management utilities

use std::path::Path;

use libp2p::identity::Keypair;
use thiserror::Error;
use tracing::info;

use tunnelcraft_crypto::SigningKeypair;

use crate::paths::expand_path;

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("Failed to read keyfile: {0}")]
    ReadError(std::io::Error),

    #[error("Failed to write keyfile: {0}")]
    WriteError(std::io::Error),

    #[error("Invalid keyfile format: {0}")]
    InvalidFormat(String),

    #[error("Failed to create directory: {0}")]
    CreateDirError(std::io::Error),
}

/// Load an existing libp2p keypair from disk, or generate a new one
///
/// The keypair is stored as the 32-byte Ed25519 secret key.
///
/// # Arguments
///
/// * `keyfile` - Path to the keyfile (supports `~` expansion)
///
/// # Returns
///
/// The loaded or newly generated keypair
///
/// # Examples
///
/// ```no_run
/// use tunnelcraft_keystore::load_or_generate_libp2p_keypair;
/// use std::path::PathBuf;
///
/// let keypair = load_or_generate_libp2p_keypair(&PathBuf::from("~/.tunnelcraft/node.key"))?;
/// # Ok::<(), tunnelcraft_keystore::Error>(())
/// ```
pub fn load_or_generate_libp2p_keypair(keyfile: &Path) -> Result<Keypair, KeystoreError> {
    let path = expand_path(keyfile);

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(KeystoreError::CreateDirError)?;
        }
    }

    // Try to load existing keypair
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(KeystoreError::ReadError)?;
        // ed25519_from_bytes expects the 32-byte secret key
        let keypair = Keypair::ed25519_from_bytes(bytes)
            .map_err(|e| KeystoreError::InvalidFormat(e.to_string()))?;
        info!("Loaded existing libp2p keypair from {:?}", path);
        return Ok(keypair);
    }

    // Generate new keypair
    let keypair = Keypair::generate_ed25519();
    let ed25519_keypair = keypair
        .clone()
        .try_into_ed25519()
        .map_err(|_| KeystoreError::InvalidFormat("Failed to extract ed25519 key".to_string()))?;

    // Store only the 32-byte secret key
    let secret = ed25519_keypair.secret();
    let secret_bytes = secret.as_ref();

    std::fs::write(&path, secret_bytes).map_err(KeystoreError::WriteError)?;

    info!("Generated new libp2p keypair, saved to {:?}", path);
    Ok(keypair)
}

/// Load an existing TunnelCraft signing keypair from disk, or generate a new one
///
/// The keypair is stored as the 32-byte secret key.
///
/// # Arguments
///
/// * `keyfile` - Path to the keyfile (supports `~` expansion)
///
/// # Returns
///
/// The loaded or newly generated signing keypair
pub fn load_or_generate_signing_keypair(keyfile: &Path) -> Result<SigningKeypair, KeystoreError> {
    let path = expand_path(keyfile);

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(KeystoreError::CreateDirError)?;
        }
    }

    // Try to load existing keypair
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(KeystoreError::ReadError)?;
        if bytes.len() != 32 {
            return Err(KeystoreError::InvalidFormat(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        let keypair = SigningKeypair::from_secret_bytes(&key_bytes);
        info!("Loaded existing signing keypair from {:?}", path);
        return Ok(keypair);
    }

    // Generate new keypair
    let keypair = SigningKeypair::generate();
    let bytes = keypair.secret_key_bytes();

    std::fs::write(&path, bytes).map_err(KeystoreError::WriteError)?;

    info!("Generated new signing keypair, saved to {:?}", path);
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_libp2p_keypair() {
        let temp_dir = std::env::temp_dir().join("tunnelcraft_test_libp2p");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let keyfile = temp_dir.join("test.key");

        // Generate new keypair
        let keypair1 = load_or_generate_libp2p_keypair(&keyfile).unwrap();
        assert!(keyfile.exists());

        // Load existing keypair
        let keypair2 = load_or_generate_libp2p_keypair(&keyfile).unwrap();

        // Should be the same keypair
        assert_eq!(
            keypair1.public().to_peer_id(),
            keypair2.public().to_peer_id()
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_generate_signing_keypair() {
        let temp_dir = std::env::temp_dir().join("tunnelcraft_test_signing");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let keyfile = temp_dir.join("signing.key");

        // Generate new keypair
        let keypair1 = load_or_generate_signing_keypair(&keyfile).unwrap();
        assert!(keyfile.exists());

        // Load existing keypair
        let keypair2 = load_or_generate_signing_keypair(&keyfile).unwrap();

        // Should be the same keypair
        assert_eq!(
            keypair1.public_key_bytes(),
            keypair2.public_key_bytes()
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_invalid_keyfile_wrong_length() {
        let temp_dir = std::env::temp_dir().join("tunnelcraft_test_invalid");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let keyfile = temp_dir.join("invalid.key");
        fs::write(&keyfile, b"invalid").unwrap(); // 7 bytes, not 32

        let result = load_or_generate_signing_keypair(&keyfile);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
