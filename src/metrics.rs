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

pub struct KanshiMetrics {
    registry: Mutex<Registry>,
    verifications_total: Family<VerificationLabels, Counter>,
    revocations_total: Family<RevocationLabels, Counter>,
}

impl KanshiMetrics {
    #[must_use]
    pub fn new() -> Self {
        let mut registry = <Registry>::default();
        let verifications_total = Family::<VerificationLabels, Counter>::default();
        registry.register("kanshi_verifications_total", "Total binary verifications", verifications_total.clone());
        let revocations_total = Family::<RevocationLabels, Counter>::default();
        registry.register("kanshi_revocations_total", "Total revocation events", revocations_total.clone());
        Self { registry: Mutex::new(registry), verifications_total, revocations_total }
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
}
