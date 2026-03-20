//! Health check server for kanshi.

use axum::{routing::get, Json, Router};
use serde::Serialize;

/// Health status response.
#[derive(Clone, Debug, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub bpf_loaded: bool,
    pub allow_map_entries: usize,
    pub revocation_map_entries: usize,
}

impl HealthStatus {
    /// Create a healthy status.
    #[must_use]
    pub fn healthy(allow_entries: usize, revocation_entries: usize) -> Self {
        Self {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            bpf_loaded: false, // Will be true when eBPF programs are loaded
            allow_map_entries: allow_entries,
            revocation_map_entries: revocation_entries,
        }
    }
}

/// Create the health check router.
#[must_use]
pub fn health_router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
}

async fn healthz() -> Json<HealthStatus> {
    Json(HealthStatus::healthy(0, 0))
}

async fn readyz() -> Json<HealthStatus> {
    Json(HealthStatus::healthy(0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_status_healthy() {
        let status = HealthStatus::healthy(100, 5);
        assert_eq!(status.status, "healthy");
        assert_eq!(status.allow_map_entries, 100);
        assert_eq!(status.revocation_map_entries, 5);
    }

    #[test]
    fn health_status_serde() {
        let status = HealthStatus::healthy(10, 2);
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("10"));
    }
}
