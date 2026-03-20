//! CRD watcher for sekiban `SignatureGate` resources.
//!
//! Watches `SignatureGate` CRDs and syncs allowed hashes to the BPF maps
//! via the [`BpfLoader`] trait.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::bpf_loader::BpfLoader;
use crate::error::Error;
use kanshi_common::BpfHash;

/// Minimal `SignatureGate` CRD for kanshi (read-only).
/// The full CRD is defined in sekiban; kanshi only needs to read it.
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "sekiban.pleme.io",
    version = "v1alpha1",
    kind = "SignatureGate",
    namespaced
)]
pub struct SignatureGateSpec {
    /// Top-level expected signature (hex, optionally `blake3:` prefixed).
    pub expected_signature: String,
    /// Per-layer BLAKE3 hashes (hex, optionally `blake3:` prefixed).
    #[serde(default)]
    pub layer_hashes: Vec<String>,
}

/// Minimal reference to a `SignatureGate` CRD — just the fields kanshi needs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureGateRef {
    /// Name of the `SignatureGate` resource.
    pub name: String,
    /// Namespace the gate belongs to.
    pub namespace: String,
    /// Top-level expected signature (hex, optionally `blake3:` prefixed).
    pub expected_signature: String,
    /// Per-layer BLAKE3 hashes (hex, optionally `blake3:` prefixed).
    pub layer_hashes: Vec<String>,
}

impl SignatureGateRef {
    /// Create a `SignatureGateRef` from a Kubernetes `SignatureGate` resource.
    #[must_use]
    pub fn from_resource(gate: &SignatureGate) -> Self {
        Self {
            name: gate.metadata.name.clone().unwrap_or_default(),
            namespace: gate.metadata.namespace.clone().unwrap_or_default(),
            expected_signature: gate.spec.expected_signature.clone(),
            layer_hashes: gate.spec.layer_hashes.clone(),
        }
    }
}

/// Watches `SignatureGate` CRDs and syncs to BPF maps.
pub struct CrdWatcher<L: BpfLoader> {
    loader: Arc<L>,
}

impl<L: BpfLoader> CrdWatcher<L> {
    /// Create a new watcher backed by the given BPF loader.
    #[must_use]
    pub fn new(loader: Arc<L>) -> Self {
        Self { loader }
    }

    /// Process a gate-applied event — extract hashes and add them to the
    /// BPF allow map.
    ///
    /// # Errors
    ///
    /// Returns `Error::Bpf` if a map operation fails, or `Error::InvalidHash`
    /// for malformed hashes (which are logged and skipped, not propagated).
    pub fn on_gate_applied(&self, gate: &SignatureGateRef) -> Result<(), Error> {
        info!(gate = %gate.name, ns = %gate.namespace, "Processing SignatureGate");

        // Add each layer hash to the allow map
        for hash_str in &gate.layer_hashes {
            match parse_bpf_hash(hash_str) {
                Ok(hash) => self.loader.allow_hash(&hash)?,
                Err(e) => warn!(hash = %hash_str, err = %e, "Invalid hash format in SignatureGate"),
            }
        }

        // Add the expected signature to the allow map
        match parse_bpf_hash(&gate.expected_signature) {
            Ok(hash) => self.loader.allow_hash(&hash)?,
            Err(e) => warn!(
                hash = %gate.expected_signature,
                err = %e,
                "Invalid expected_signature in SignatureGate"
            ),
        }

        Ok(())
    }

    /// Process a gate-deleted event — remove hashes from the BPF allow map.
    ///
    /// # Errors
    ///
    /// Returns `Error::Bpf` if a map operation fails.
    pub fn on_gate_deleted(&self, gate: &SignatureGateRef) -> Result<(), Error> {
        info!(gate = %gate.name, ns = %gate.namespace, "Removing SignatureGate hashes");

        for hash_str in &gate.layer_hashes {
            match parse_bpf_hash(hash_str) {
                Ok(hash) => self.loader.remove_hash(&hash)?,
                Err(e) => warn!(hash = %hash_str, err = %e, "Invalid hash format during removal"),
            }
        }

        if let Ok(hash) = parse_bpf_hash(&gate.expected_signature) {
            self.loader.remove_hash(&hash)?;
        }

        Ok(())
    }
}

/// Shared state for the CRD reconciler.
pub struct ReconcileContext<L: BpfLoader> {
    /// The underlying CRD watcher that performs BPF map operations.
    pub watcher: CrdWatcher<L>,
}

/// Reconcile a `SignatureGate` CRD — sync its hashes to BPF maps.
///
/// Called by `kube::Controller` when a `SignatureGate` is created, updated, or
/// deleted. Idempotent: re-running on the same gate produces the same BPF map
/// state.
///
/// # Errors
///
/// Returns `Error::Bpf` if a map operation fails, propagating to the
/// controller's error policy for backoff.
pub async fn reconcile<L: BpfLoader + 'static>(
    gate: Arc<SignatureGate>,
    ctx: Arc<ReconcileContext<L>>,
) -> Result<Action, Error> {
    let gate_ref = SignatureGateRef::from_resource(&gate);
    ctx.watcher.on_gate_applied(&gate_ref)?;

    // Requeue after 5 minutes for periodic re-sync
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Error policy for failed reconciliations.
///
/// Uses the error's `requeue_duration()` to determine the backoff interval,
/// giving transient errors a shorter retry window than permanent ones.
pub fn error_policy<L: BpfLoader + 'static>(
    _gate: Arc<SignatureGate>,
    error: &Error,
    _ctx: Arc<ReconcileContext<L>>,
) -> Action {
    let requeue = error.requeue_duration();
    warn!(error = %error, requeue_secs = requeue.as_secs(), "Reconciliation failed");
    Action::requeue(requeue)
}

/// Parse a hex string (with optional `blake3:` prefix) into a [`BpfHash`].
///
/// # Errors
///
/// Returns `Error::InvalidHash` if the string is not exactly 64 hex characters
/// (after stripping the optional prefix) or contains non-hex characters.
pub fn parse_bpf_hash(s: &str) -> Result<BpfHash, Error> {
    let hex_str = s.strip_prefix("blake3:").unwrap_or(s);
    if hex_str.len() != 64 {
        return Err(Error::InvalidHash(format!(
            "expected 64 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = const_hex::decode(hex_str)
        .map_err(|e| Error::InvalidHash(format!("hex decode failed: {e}")))?;
    let mut hash = BpfHash::new([0u8; 32]);
    hash.bytes.copy_from_slice(&bytes[..32]);
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpf_loader::MockBpfLoader;

    /// A valid 64-char hex string (all `aa` bytes).
    fn valid_hex() -> String {
        "aa".repeat(32)
    }

    /// A different valid 64-char hex string (all `bb` bytes).
    fn valid_hex_2() -> String {
        "bb".repeat(32)
    }

    #[test]
    fn parse_bpf_hash_plain_hex() {
        let hex = valid_hex();
        let hash = parse_bpf_hash(&hex).unwrap();
        assert_eq!(hash.bytes, [0xaa; 32]);
    }

    #[test]
    fn parse_bpf_hash_with_prefix() {
        let hex = format!("blake3:{}", valid_hex());
        let hash = parse_bpf_hash(&hex).unwrap();
        assert_eq!(hash.bytes, [0xaa; 32]);
    }

    #[test]
    fn parse_bpf_hash_invalid_length() {
        let result = parse_bpf_hash("aabb");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("expected 64 hex chars"));
    }

    #[test]
    fn parse_bpf_hash_invalid_hex() {
        // 64 chars but not valid hex
        let bad = "zz".repeat(32);
        let result = parse_bpf_hash(&bad);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hex decode failed"));
    }

    #[test]
    fn crd_watcher_on_gate_applied() {
        let loader = Arc::new(MockBpfLoader::new());
        let watcher = CrdWatcher::new(Arc::clone(&loader));

        let gate = SignatureGateRef {
            name: "test-gate".to_string(),
            namespace: "production".to_string(),
            expected_signature: valid_hex(),
            layer_hashes: vec![valid_hex_2()],
        };

        watcher.on_gate_applied(&gate).unwrap();

        // expected_signature + 1 layer hash = 2 entries
        assert_eq!(loader.allow_count(), 2);
    }

    #[test]
    fn crd_watcher_on_gate_deleted() {
        let loader = Arc::new(MockBpfLoader::new());
        let watcher = CrdWatcher::new(Arc::clone(&loader));

        let gate = SignatureGateRef {
            name: "test-gate".to_string(),
            namespace: "staging".to_string(),
            expected_signature: valid_hex(),
            layer_hashes: vec![valid_hex_2()],
        };

        // First apply, then delete
        watcher.on_gate_applied(&gate).unwrap();
        assert_eq!(loader.allow_count(), 2);

        watcher.on_gate_deleted(&gate).unwrap();
        assert_eq!(loader.allow_count(), 0);
    }

    #[test]
    fn crd_watcher_handles_invalid_hash() {
        let loader = Arc::new(MockBpfLoader::new());
        let watcher = CrdWatcher::new(Arc::clone(&loader));

        let gate = SignatureGateRef {
            name: "bad-gate".to_string(),
            namespace: "dev".to_string(),
            expected_signature: valid_hex(),
            layer_hashes: vec!["tooshort".to_string(), valid_hex_2()],
        };

        // Should succeed — invalid hashes are warned, not fatal
        watcher.on_gate_applied(&gate).unwrap();

        // Only the valid layer hash + expected_signature should be added
        assert_eq!(loader.allow_count(), 2);
    }
}
