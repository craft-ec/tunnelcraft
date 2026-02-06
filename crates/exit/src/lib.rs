//! TunnelCraft Exit Node
//!
//! Exit node logic: HTTP fetch and settlement submission.
//!
//! ## Responsibilities
//!
//! 1. Collect request shards from relays
//! 2. Reconstruct HTTP request using erasure coding
//! 3. Execute HTTP request to target
//! 4. Fragment response into shards
//! 5. Submit Phase 1 settlement (stores user_pubkey for verification)
//! 6. Send response shards back through the network

mod handler;
mod request;
mod response;

pub use handler::{ExitHandler, ExitConfig};
pub use request::HttpRequest;
pub use response::HttpResponse;

use thiserror::Error;
use tunnelcraft_erasure::ErasureError;

#[derive(Error, Debug)]
pub enum ExitError {
    #[error("Insufficient shards: have {have}, need {need}")]
    InsufficientShards { have: usize, need: usize },

    #[error("Erasure decode failed: {0}")]
    ErasureDecodeError(String),

    #[error("Erasure error: {0}")]
    Erasure(#[from] ErasureError),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Invalid request format: {0}")]
    InvalidRequest(String),

    #[error("Settlement failed: {0}")]
    SettlementError(String),

    #[error("Request timeout")]
    Timeout,

    #[error("Blocked destination: {0}")]
    BlockedDestination(String),
}

pub type Result<T> = std::result::Result<T, ExitError>;
