//! Health check server for kanshi.
//!
//! The health endpoints now inspect real BPF loader state instead of
//! returning hardcoded "healthy" responses. `/healthz` (liveness) checks
//! that the process is alive and BPF programs are loaded. `/readyz`
//! (readiness) additionally verifies the allow map is non-empty after
//! the initial CRD sync.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::bpf_loader::BpfLoader;

/// Health status response.
#[derive(Clone, Debug, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub bpf_loaded: bool,
    pub allow_map_entries: usize,
    pub revocation_map_entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl HealthStatus {
    /// Create a healthy status reporting real map counts.
    #[must_use]
    pub fn healthy(allow_entries: usize, revocation_entries: usize) -> Self {
        Self {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            bpf_loaded: true,
            allow_map_entries: allow_entries,
            revocation_map_entries: revocation_entries,
            reason: None,
        }
    }

    /// Create an unhealthy status with a reason.
    #[must_use]
    pub fn unhealthy(reason: impl Into<String>) -> Self {
        Self {
            status: "unhealthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            bpf_loaded: false,
            allow_map_entries: 0,
            revocation_map_entries: 0,
            reason: Some(reason.into()),
        }
    }
}

/// Shared state for health check handlers.
pub struct HealthState<L: BpfLoader> {
    /// The BPF loader to query for liveness/readiness.
    pub loader: Arc<L>,
    /// When the daemon started (used in readiness heuristics).
    pub started_at: DateTime<Utc>,
}

/// Create the health check router backed by real BPF loader state.
///
/// Exposes `/healthz`, `/readyz`, and `/metrics` endpoints.
#[must_use]
pub fn health_router<L: BpfLoader + 'static>(state: Arc<HealthState<L>>) -> Router {
    Router::new()
        .route("/healthz", get(healthz::<L>))
        .route("/readyz", get(readyz::<L>))
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// GET /metrics -- Prometheus metrics endpoint.
///
/// Returns all registered Prometheus metrics in the text exposition format.
#[allow(clippy::unused_async)]
async fn metrics_handler() -> impl IntoResponse {
    let body = crate::metrics::gather();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

/// GET /healthz -- liveness probe.
///
/// Returns 200 if the process is alive and BPF programs are loaded.
/// Returns 503 if BPF programs have not been loaded yet.
async fn healthz<L: BpfLoader + 'static>(
    State(state): State<Arc<HealthState<L>>>,
) -> impl IntoResponse {
    let loaded = state.loader.is_loaded();
    if loaded {
        let status = HealthStatus::healthy(
            state.loader.allow_count(),
            state.loader.revocation_count(),
        );
        (StatusCode::OK, Json(status))
    } else {
        let status = HealthStatus::unhealthy("BPF programs not loaded");
        (StatusCode::SERVICE_UNAVAILABLE, Json(status))
    }
}

/// GET /readyz -- readiness probe.
///
/// Returns 200 if BPF programs are loaded AND the allow map has at least
/// one entry (indicating the initial CRD sync has populated data).
/// Returns 503 otherwise.
async fn readyz<L: BpfLoader + 'static>(
    State(state): State<Arc<HealthState<L>>>,
) -> impl IntoResponse {
    let loaded = state.loader.is_loaded();
    let allow_count = state.loader.allow_count();
    let revocation_count = state.loader.revocation_count();

    if !loaded {
        let status = HealthStatus::unhealthy("BPF programs not loaded");
        return (StatusCode::SERVICE_UNAVAILABLE, Json(status));
    }

    if allow_count == 0 {
        let status = HealthStatus {
            status: "not_ready".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            bpf_loaded: true,
            allow_map_entries: 0,
            revocation_map_entries: revocation_count,
            reason: Some("Allow map is empty — waiting for initial CRD sync".to_string()),
        };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(status));
    }

    let status = HealthStatus::healthy(allow_count, revocation_count);
    (StatusCode::OK, Json(status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf_loader::MockBpfLoader;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn health_status_healthy() {
        let status = HealthStatus::healthy(100, 5);
        assert_eq!(status.status, "healthy");
        assert!(status.bpf_loaded);
        assert_eq!(status.allow_map_entries, 100);
        assert_eq!(status.revocation_map_entries, 5);
        assert!(status.reason.is_none());
    }

    #[test]
    fn health_status_unhealthy() {
        let status = HealthStatus::unhealthy("test reason");
        assert_eq!(status.status, "unhealthy");
        assert!(!status.bpf_loaded);
        assert_eq!(status.reason.as_deref(), Some("test reason"));
    }

    #[test]
    fn health_status_serde() {
        let status = HealthStatus::healthy(10, 2);
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("10"));
        // reason should be absent when None (skip_serializing_if)
        assert!(!json.contains("reason"));
    }

    #[test]
    fn health_status_unhealthy_serde() {
        let status = HealthStatus::unhealthy("BPF programs not loaded");
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("unhealthy"));
        assert!(json.contains("BPF programs not loaded"));
    }

    fn make_state(loaded: bool, hashes: usize) -> Arc<HealthState<MockBpfLoader>> {
        let mut loader = MockBpfLoader::new();
        if loaded {
            loader.load().unwrap();
        }
        let loader = Arc::new(loader);
        // Add hashes to the allow map
        for i in 0..hashes {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            let hash = kanshi_common::BpfHash::new(bytes);
            loader.allow_hash(&hash).unwrap();
        }
        Arc::new(HealthState {
            loader,
            started_at: Utc::now(),
        })
    }

    #[tokio::test]
    async fn healthz_returns_ok_when_loaded() {
        let state = make_state(true, 1);
        let app = health_router(state);
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_returns_unavailable_when_not_loaded() {
        let state = make_state(false, 0);
        let app = health_router(state);
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readyz_returns_ok_when_loaded_with_entries() {
        let state = make_state(true, 3);
        let app = health_router(state);
        let req = Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_unavailable_when_not_loaded() {
        let state = make_state(false, 0);
        let app = health_router(state);
        let req = Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readyz_returns_unavailable_when_allow_map_empty() {
        let state = make_state(true, 0);
        let app = health_router(state);
        let req = Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_200() {
        let state = make_state(true, 1);
        let app = health_router(state);
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_response_contains_blocked_executions_counter() {
        // Record a blocked execution so the counter is guaranteed to appear.
        crate::metrics::record_blocked_execution("revoked", "/usr/bin/test");

        let state = make_state(true, 1);
        let app = health_router(state);
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            text.contains("tameshi_blocked_executions_total"),
            "metrics response should contain tameshi_blocked_executions_total"
        );
    }
}
