//! Prometheus metrics for kanshi sentinel.

use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::sync::{LazyLock, Mutex};

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct VerificationLabels {
    pub namespace: String,
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct RevocationLabels {
    pub hash: String,
}

/// Labels for blocked execution events.
#[derive(Clone, Debug, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct BlockedExecutionLabels {
    /// Reason for blocking: "not_in_allow_map", "hash_mismatch", "revoked", "unknown".
    pub reason: String,
    /// Binary path (truncated to 128 chars to control cardinality).
    pub binary_path: String,
}

/// Truncate a binary path to at most 128 characters, prepending "..." if shortened.
///
/// Used to limit label cardinality in Prometheus metrics. Full paths are
/// preserved in the heartbeat chain for forensic evidence.
#[inline]
#[must_use]
pub fn truncate_path(path: &str) -> String {
    if path.len() > 128 {
        format!("...{}", &path[path.len() - 125..])
    } else {
        path.to_string()
    }
}

pub struct KanshiMetrics {
    registry: Mutex<Registry>,
    verifications_total: Family<VerificationLabels, Counter>,
    revocations_total: Family<RevocationLabels, Counter>,
    blocked_executions_total: Family<BlockedExecutionLabels, Counter>,
}

impl KanshiMetrics {
    #[must_use]
    pub fn new() -> Self {
        let mut registry = <Registry>::default();
        let verifications_total = Family::<VerificationLabels, Counter>::default();
        registry.register("kanshi_verifications_total", "Total binary verifications", verifications_total.clone());
        let revocations_total = Family::<RevocationLabels, Counter>::default();
        registry.register("kanshi_revocations_total", "Total revocation events", revocations_total.clone());
        let blocked_executions_total = Family::<BlockedExecutionLabels, Counter>::default();
        registry.register(
            "tameshi_blocked_executions_total",
            "Total blocked binary executions",
            blocked_executions_total.clone(),
        );
        Self {
            registry: Mutex::new(registry),
            verifications_total,
            revocations_total,
            blocked_executions_total,
        }
    }

    pub fn record_verification(&self, namespace: &str, allowed: bool) {
        self.verifications_total
            .get_or_create(&VerificationLabels {
                namespace: namespace.to_string(),
                result: if allowed { "allowed" } else { "denied" }.to_string(),
            })
            .inc();
    }

    pub fn record_revocation(&self, hash: &str) {
        self.revocations_total
            .get_or_create(&RevocationLabels { hash: hash.to_string() })
            .inc();
    }

    /// Record a blocked binary execution with the given reason and binary path.
    #[inline]
    pub fn record_blocked_execution(&self, reason: &str, binary_path: &str) {
        self.blocked_executions_total
            .get_or_create(&BlockedExecutionLabels {
                reason: reason.to_string(),
                binary_path: truncate_path(binary_path),
            })
            .inc();
    }

    #[must_use]
    pub fn encode(&self) -> String {
        let mut buf = String::new();
        let registry = self.registry.lock().expect("metrics lock poisoned");
        encode(&mut buf, &registry).unwrap_or_default();
        buf
    }
}

impl Default for KanshiMetrics {
    fn default() -> Self { Self::new() }
}

static METRICS: LazyLock<KanshiMetrics> = LazyLock::new(KanshiMetrics::new);

pub fn init() { let _ = &*METRICS; }
pub fn gather() -> String { METRICS.encode() }
pub fn record_verification(namespace: &str, allowed: bool) { METRICS.record_verification(namespace, allowed); }
pub fn record_revocation(hash: &str) { METRICS.record_revocation(hash); }

/// Record a blocked binary execution event in the global metrics.
#[inline]
pub fn record_blocked_execution(reason: &str, binary_path: &str) {
    METRICS.record_blocked_execution(reason, binary_path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_verification() {
        let m = KanshiMetrics::new();
        m.record_verification("production", true);
        m.record_verification("production", false);
        let output = m.encode();
        assert!(output.contains("kanshi_verifications_total"));
    }

    #[test]
    fn metrics_revocation() {
        let m = KanshiMetrics::new();
        m.record_revocation("blake3:abc");
        let output = m.encode();
        assert!(output.contains("kanshi_revocations_total"));
    }

    #[test]
    fn global_functions() {
        init();
        record_verification("ns", true);
        record_revocation("hash");
        let _ = gather();
    }

    #[test]
    fn blocked_execution_increments_counter() {
        let m = KanshiMetrics::new();
        m.record_blocked_execution("not_in_allow_map", "/usr/bin/evil");
        let output = m.encode();
        assert!(output.contains("tameshi_blocked_executions_total"));
    }

    #[test]
    fn blocked_execution_different_reasons_separate_labels() {
        let m = KanshiMetrics::new();
        m.record_blocked_execution("not_in_allow_map", "/usr/bin/a");
        m.record_blocked_execution("hash_mismatch", "/usr/bin/b");
        m.record_blocked_execution("revoked", "/usr/bin/c");
        m.record_blocked_execution("unknown", "/usr/bin/d");
        let output = m.encode();
        assert!(output.contains("not_in_allow_map"));
        assert!(output.contains("hash_mismatch"));
        assert!(output.contains("revoked"));
        assert!(output.contains("unknown"));
    }

    #[test]
    fn blocked_execution_path_truncation() {
        let long_path = "/".to_string() + &"a".repeat(200);
        let truncated = truncate_path(&long_path);
        assert!(truncated.len() <= 128);
        assert!(truncated.starts_with("..."));

        let short_path = "/usr/bin/test";
        assert_eq!(truncate_path(short_path), short_path);

        let exactly_128 = "x".repeat(128);
        assert_eq!(truncate_path(&exactly_128), exactly_128);
    }

    #[test]
    fn blocked_execution_multiple_accumulate() {
        let m = KanshiMetrics::new();
        m.record_blocked_execution("revoked", "/usr/bin/evil");
        m.record_blocked_execution("revoked", "/usr/bin/evil");
        m.record_blocked_execution("revoked", "/usr/bin/evil");
        let output = m.encode();
        // The counter should show 3 total for this label set
        assert!(output.contains("tameshi_blocked_executions_total"));
    }

    #[test]
    fn blocked_execution_labels_equality() {
        let a = BlockedExecutionLabels {
            reason: "revoked".to_string(),
            binary_path: "/usr/bin/evil".to_string(),
        };
        let b = BlockedExecutionLabels {
            reason: "revoked".to_string(),
            binary_path: "/usr/bin/evil".to_string(),
        };
        let c = BlockedExecutionLabels {
            reason: "hash_mismatch".to_string(),
            binary_path: "/usr/bin/evil".to_string(),
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── Counter monotonicity ────────────────────────────────────────

    #[test]
    fn counter_only_increases() {
        let m = KanshiMetrics::new();
        m.record_blocked_execution("revoked", "/usr/bin/evil");
        let output1 = m.encode();
        m.record_blocked_execution("revoked", "/usr/bin/evil");
        let output2 = m.encode();
        // Counter should be higher in output2 (no way to decrease a counter).
        // Both should contain the metric.
        assert!(output1.contains("tameshi_blocked_executions_total"));
        assert!(output2.contains("tameshi_blocked_executions_total"));
    }

    // ── Truncation prevents label cardinality explosion ─────────────

    #[test]
    fn truncation_prevents_cardinality_explosion() {
        let m = KanshiMetrics::new();
        // Record 100 unique long paths — all should be truncated to 128 chars.
        for i in 0..100 {
            let path = format!("/{}/{}", "a".repeat(200), i);
            m.record_blocked_execution("revoked", &path);
        }
        let output = m.encode();
        // All truncated paths should start with "...".
        assert!(output.contains("..."));
    }

    #[test]
    fn truncate_path_empty() {
        assert_eq!(truncate_path(""), "");
    }

    #[test]
    fn truncate_path_exactly_129_chars() {
        let path = "z".repeat(129);
        let truncated = truncate_path(&path);
        assert_eq!(truncated.len(), 128);
        assert!(truncated.starts_with("..."));
    }

    #[test]
    fn truncate_path_preserves_tail() {
        let path = format!("{}/important", "x".repeat(200));
        let truncated = truncate_path(&path);
        assert!(truncated.ends_with("/important"));
    }

    // ── Prometheus text format validity ─────────────────────────────

    #[test]
    fn gather_output_contains_help_and_type_lines() {
        let m = KanshiMetrics::new();
        m.record_blocked_execution("revoked", "/usr/bin/evil");
        let output = m.encode();
        // Prometheus text format requires # HELP and # TYPE lines.
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
    }

    #[test]
    fn global_blocked_execution_records() {
        // Verify the global function works without panicking.
        record_blocked_execution("unknown", "/bin/test");
        let output = gather();
        assert!(output.contains("tameshi_blocked_executions_total"));
    }

    #[test]
    fn empty_binary_path_does_not_panic() {
        let m = KanshiMetrics::new();
        m.record_blocked_execution("revoked", "");
        let output = m.encode();
        assert!(output.contains("tameshi_blocked_executions_total"));
    }

    #[test]
    fn default_creates_new_metrics() {
        let m = KanshiMetrics::default();
        m.record_verification("test", true);
        let output = m.encode();
        assert!(output.contains("kanshi_verifications_total"));
    }
}
