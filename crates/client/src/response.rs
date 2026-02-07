//! Tunnel response type
//!
//! HTTP response returned through the VPN tunnel.

use std::collections::HashMap;

use crate::{ClientError, Result};

/// HTTP response from the tunnel
#[derive(Debug, Clone)]
pub struct TunnelResponse {
    /// HTTP status code
    pub status: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: Vec<u8>,
}

impl TunnelResponse {
    /// Parse response from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Parse format: status\nheader_count\nheaders...\nbody_len\nbody
        let mut lines = data.split(|&b| b == b'\n');

        let status = lines
            .next()
            .ok_or_else(|| ClientError::InvalidResponse)?;
        let status: u16 = String::from_utf8_lossy(status)
            .parse()
            .map_err(|_| ClientError::InvalidResponse)?;

        let header_count = lines
            .next()
            .ok_or_else(|| ClientError::InvalidResponse)?;
        let header_count: usize = String::from_utf8_lossy(header_count)
            .parse()
            .map_err(|_| ClientError::InvalidResponse)?;

        let mut headers = HashMap::new();
        for _ in 0..header_count {
            let header_line = lines
                .next()
                .ok_or_else(|| ClientError::InvalidResponse)?;
            let header_str = String::from_utf8_lossy(header_line);
            if let Some((key, value)) = header_str.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        let body_len = lines
            .next()
            .ok_or_else(|| ClientError::InvalidResponse)?;
        let body_len: usize = String::from_utf8_lossy(body_len)
            .parse()
            .map_err(|_| ClientError::InvalidResponse)?;

        let body: Vec<u8> = lines
            .flat_map(|line| line.iter().copied().chain(std::iter::once(b'\n')))
            .take(body_len)
            .collect();

        Ok(Self {
            status,
            headers,
            body,
        })
    }

    /// Get body as string
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_parsing() {
        let data = b"200\n2\nContent-Type: text/plain\nX-Custom: value\n5\nHello";
        let response = TunnelResponse::from_bytes(data).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.headers.len(), 2);
        assert_eq!(response.text(), "Hello");
    }

    #[test]
    fn test_response_empty_body() {
        let data = b"404\n0\n0\n";
        let response = TunnelResponse::from_bytes(data).unwrap();

        assert_eq!(response.status, 404);
        assert!(response.headers.is_empty());
        assert!(response.body.is_empty());
    }
}
