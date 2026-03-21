//! BPF program loader and map manager.
//!
//! Provides a trait-based abstraction over BPF map operations, with a real
//! implementation (Linux/aya, future) and a mock for testing on any platform.

use std::collections::HashMap;

use kanshi_common::{BpfHash, EnforcementPolicy};

use crate::error::Error;

/// Trait for loading and managing BPF maps.
///
/// The real implementation uses aya to load BPF programs and populate maps.
/// The mock implementation stores data in-memory for testing.
pub trait BpfLoader: Send + Sync {
    /// Load the BPF programs into the kernel.
    ///
    /// # Errors
    ///
    /// Returns `Error::Bpf` if the programs cannot be loaded.
    fn load(&mut self) -> Result<(), Error>;

    /// Check whether the BPF programs have been loaded.
    fn is_loaded(&self) -> bool;

    /// Add a hash to the allow map.
    ///
    /// # Errors
    ///
    /// Returns `Error::Bpf` if the map operation fails.
    fn allow_hash(&self, hash: &BpfHash) -> Result<(), Error>;

    /// Remove a hash from the allow map.
    ///
    /// # Errors
    ///
    /// Returns `Error::Bpf` if the map operation fails.
    fn remove_hash(&self, hash: &BpfHash) -> Result<(), Error>;

    /// Add a hash to the revocation list.
    ///
    /// # Errors
    ///
    /// Returns `Error::Bpf` if the map operation fails.
    fn revoke_hash(&self, hash: &BpfHash) -> Result<(), Error>;

    /// Remove a hash from the revocation list.
    ///
    /// # Errors
    ///
    /// Returns `Error::Bpf` if the map operation fails.
    fn unrevoke_hash(&self, hash: &BpfHash) -> Result<(), Error>;

    /// Set the enforcement policy for a namespace.
    ///
    /// # Errors
    ///
    /// Returns `Error::Bpf` if the map operation fails.
    fn set_policy(&self, namespace_hash: u32, policy: EnforcementPolicy) -> Result<(), Error>;

    /// Get current allow map size.
    fn allow_count(&self) -> usize;

    /// Get current revocation list size.
    fn revocation_count(&self) -> usize;
}

/// Real aya-based BPF program loader.
///
/// Loads the compiled eBPF object, attaches LSM hooks, and provides
/// typed access to BPF maps for hash verification.
///
/// Only available on Linux (requires kernel BTF support).
#[cfg(target_os = "linux")]
pub struct AyaBpfLoader {
    // Will hold aya::Ebpf when aya is added as dependency
    loaded: bool,
    // Placeholder — real impl loads from include_bytes_aligned!
}

#[cfg(target_os = "linux")]
impl AyaBpfLoader {
    /// Create a new unloaded aya BPF loader.
    #[must_use]
    pub fn new() -> Self {
        Self { loaded: false }
    }

    /// Check whether the BPF programs have been loaded.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }
}

#[cfg(target_os = "linux")]
impl Default for AyaBpfLoader {
    fn default() -> Self {
        Self::new()
    }
}

// Note: BpfLoader impl for AyaBpfLoader will be added when aya dependency
// is integrated. For now this is a compile-time placeholder.

/// Mock BPF loader for testing and macOS development.
///
/// Stores all map data in-memory behind `Mutex` locks so it can be
/// shared across threads while satisfying the `Send + Sync` bounds.
pub struct MockBpfLoader {
    loaded: bool,
    allow_map: std::sync::Mutex<HashMap<BpfHash, u8>>,
    revocation_map: std::sync::Mutex<HashMap<BpfHash, u8>>,
    policy_map: std::sync::Mutex<HashMap<u32, EnforcementPolicy>>,
}

impl MockBpfLoader {
    /// Create a new unloaded mock loader with empty maps.
    #[must_use]
    pub fn new() -> Self {
        Self {
            loaded: false,
            allow_map: std::sync::Mutex::new(HashMap::new()),
            revocation_map: std::sync::Mutex::new(HashMap::new()),
            policy_map: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Check whether the loader has been loaded.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }
}

impl Default for MockBpfLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfLoader for MockBpfLoader {
    fn load(&mut self) -> Result<(), Error> {
        self.loaded = true;
        Ok(())
    }

    fn is_loaded(&self) -> bool {
        self.loaded
    }

    fn allow_hash(&self, hash: &BpfHash) -> Result<(), Error> {
        let mut map = self.allow_map.lock().expect("allow_map lock poisoned");
        map.insert(*hash, 1);
        Ok(())
    }

    fn remove_hash(&self, hash: &BpfHash) -> Result<(), Error> {
        let mut map = self.allow_map.lock().expect("allow_map lock poisoned");
        map.remove(hash);
        Ok(())
    }

    fn revoke_hash(&self, hash: &BpfHash) -> Result<(), Error> {
        let mut map = self.revocation_map.lock().expect("revocation_map lock poisoned");
        map.insert(*hash, 1);
        Ok(())
    }

    fn unrevoke_hash(&self, hash: &BpfHash) -> Result<(), Error> {
        let mut map = self.revocation_map.lock().expect("revocation_map lock poisoned");
        map.remove(hash);
        Ok(())
    }

    fn set_policy(&self, namespace_hash: u32, policy: EnforcementPolicy) -> Result<(), Error> {
        let mut map = self.policy_map.lock().expect("policy_map lock poisoned");
        map.insert(namespace_hash, policy);
        Ok(())
    }

    fn allow_count(&self) -> usize {
        let map = self.allow_map.lock().expect("allow_map lock poisoned");
        map.len()
    }

    fn revocation_count(&self) -> usize {
        let map = self.revocation_map.lock().expect("revocation_map lock poisoned");
        map.len()
    }
}

/// A BPF loader that can be configured to fail in specific ways.
///
/// Wraps a [`MockBpfLoader`] and injects deterministic failures for negative
/// testing of the CRD watcher, verifier, and event pipeline.
pub struct FailableBpfLoader {
    inner: MockBpfLoader,
    /// If true, `allow_hash` returns an error (simulates map full).
    fail_on_allow: bool,
    /// If true, `revoke_hash` returns an error.
    fail_on_revoke: bool,
    /// If true, `load` returns an error (simulates BPF program won't attach).
    fail_on_load: bool,
    /// If true, `allow_hash` silently drops (does not store the hash).
    corrupt_lookups: bool,
}

impl FailableBpfLoader {
    /// Create a new failable loader with all failures disabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: MockBpfLoader::new(),
            fail_on_allow: false,
            fail_on_revoke: false,
            fail_on_load: false,
            corrupt_lookups: false,
        }
    }

    /// Configure to fail on `allow_hash` (simulates map full).
    #[must_use]
    pub fn with_fail_on_allow(mut self) -> Self {
        self.fail_on_allow = true;
        self
    }

    /// Configure to fail on `revoke_hash`.
    #[must_use]
    pub fn with_fail_on_revoke(mut self) -> Self {
        self.fail_on_revoke = true;
        self
    }

    /// Configure to fail on `load` (simulates BPF program won't attach).
    #[must_use]
    pub fn with_fail_on_load(mut self) -> Self {
        self.fail_on_load = true;
        self
    }

    /// Configure to corrupt lookups (allow_hash silently drops the hash).
    #[must_use]
    pub fn with_corrupt_lookups(mut self) -> Self {
        self.corrupt_lookups = true;
        self
    }
}

impl Default for FailableBpfLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfLoader for FailableBpfLoader {
    fn load(&mut self) -> Result<(), Error> {
        if self.fail_on_load {
            return Err(Error::Bpf(
                "BPF program load failed: cannot attach LSM hooks".to_string(),
            ));
        }
        self.inner.load()
    }

    fn is_loaded(&self) -> bool {
        self.inner.is_loaded()
    }

    fn allow_hash(&self, hash: &BpfHash) -> Result<(), Error> {
        if self.fail_on_allow {
            return Err(Error::Bpf(
                "BPF allow map full: cannot insert hash".to_string(),
            ));
        }
        if self.corrupt_lookups {
            // Silently drop: pretend success but don't store.
            return Ok(());
        }
        self.inner.allow_hash(hash)
    }

    fn remove_hash(&self, hash: &BpfHash) -> Result<(), Error> {
        self.inner.remove_hash(hash)
    }

    fn revoke_hash(&self, hash: &BpfHash) -> Result<(), Error> {
        if self.fail_on_revoke {
            return Err(Error::Bpf(
                "BPF revocation map write failed".to_string(),
            ));
        }
        self.inner.revoke_hash(hash)
    }

    fn unrevoke_hash(&self, hash: &BpfHash) -> Result<(), Error> {
        self.inner.unrevoke_hash(hash)
    }

    fn set_policy(&self, namespace_hash: u32, policy: EnforcementPolicy) -> Result<(), Error> {
        self.inner.set_policy(namespace_hash, policy)
    }

    fn allow_count(&self) -> usize {
        self.inner.allow_count()
    }

    fn revocation_count(&self) -> usize {
        self.inner.revocation_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_loader_starts_unloaded() {
        let loader = MockBpfLoader::new();
        assert!(!loader.is_loaded());
    }

    #[test]
    fn mock_loader_load_succeeds() {
        let mut loader = MockBpfLoader::new();
        assert!(loader.load().is_ok());
        assert!(loader.is_loaded());
    }

    #[test]
    fn mock_loader_allow_and_count() {
        let loader = MockBpfLoader::new();
        assert_eq!(loader.allow_count(), 0);

        let hash = BpfHash::new([1u8; 32]);
        loader.allow_hash(&hash).unwrap();
        assert_eq!(loader.allow_count(), 1);

        let hash2 = BpfHash::new([2u8; 32]);
        loader.allow_hash(&hash2).unwrap();
        assert_eq!(loader.allow_count(), 2);

        // Duplicate insert does not increase count
        loader.allow_hash(&hash).unwrap();
        assert_eq!(loader.allow_count(), 2);
    }

    #[test]
    fn mock_loader_revoke_and_count() {
        let loader = MockBpfLoader::new();
        assert_eq!(loader.revocation_count(), 0);

        let hash = BpfHash::new([3u8; 32]);
        loader.revoke_hash(&hash).unwrap();
        assert_eq!(loader.revocation_count(), 1);
    }

    #[test]
    fn mock_loader_remove_hash() {
        let loader = MockBpfLoader::new();
        let hash = BpfHash::new([4u8; 32]);

        loader.allow_hash(&hash).unwrap();
        assert_eq!(loader.allow_count(), 1);

        loader.remove_hash(&hash).unwrap();
        assert_eq!(loader.allow_count(), 0);

        // Removing a non-existent hash is a no-op
        loader.remove_hash(&hash).unwrap();
        assert_eq!(loader.allow_count(), 0);
    }

    #[test]
    fn mock_loader_unrevoke() {
        let loader = MockBpfLoader::new();
        let hash = BpfHash::new([5u8; 32]);

        loader.revoke_hash(&hash).unwrap();
        assert_eq!(loader.revocation_count(), 1);

        loader.unrevoke_hash(&hash).unwrap();
        assert_eq!(loader.revocation_count(), 0);
    }

    #[test]
    fn mock_loader_set_policy() {
        let loader = MockBpfLoader::new();
        loader
            .set_policy(42, EnforcementPolicy::Enforce)
            .unwrap();
        loader
            .set_policy(99, EnforcementPolicy::Audit)
            .unwrap();

        let map = loader.policy_map.lock().unwrap();
        assert_eq!(map.get(&42), Some(&EnforcementPolicy::Enforce));
        assert_eq!(map.get(&99), Some(&EnforcementPolicy::Audit));
    }

    // =========================================================================
    // FailableBpfLoader -- Negative Mock Tests (Directive 4)
    // =========================================================================

    #[test]
    fn failable_bpf_map_full_returns_error() {
        let loader = FailableBpfLoader::new().with_fail_on_allow();
        let hash = BpfHash::new([1u8; 32]);
        let result = loader.allow_hash(&hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("map full"),
            "Error should mention map full: {err_msg}"
        );
    }

    #[test]
    fn failable_bpf_load_failure() {
        let mut loader = FailableBpfLoader::new().with_fail_on_load();
        let result = loader.load();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("load failed"),
            "Error should mention load failure: {err_msg}"
        );
        assert!(!loader.is_loaded(), "Loader should remain unloaded after failure");
    }

    #[test]
    fn failable_bpf_corrupt_lookup() {
        let loader = FailableBpfLoader::new().with_corrupt_lookups();
        let hash = BpfHash::new([42u8; 32]);

        // allow_hash succeeds (no error), but the hash is silently dropped.
        loader.allow_hash(&hash).unwrap();
        assert_eq!(
            loader.allow_count(),
            0,
            "Corrupt lookup should silently drop the hash"
        );
    }

    #[test]
    fn failable_bpf_revoke_failure() {
        let loader = FailableBpfLoader::new().with_fail_on_revoke();
        let hash = BpfHash::new([5u8; 32]);
        let result = loader.revoke_hash(&hash);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("revocation map"),
            "Error should mention revocation: {err_msg}"
        );
    }

    #[test]
    fn failable_bpf_no_failure_passes_through() {
        let mut loader = FailableBpfLoader::new();
        assert!(loader.load().is_ok());
        assert!(loader.is_loaded());

        let hash = BpfHash::new([10u8; 32]);
        assert!(loader.allow_hash(&hash).is_ok());
        assert_eq!(loader.allow_count(), 1);

        assert!(loader.revoke_hash(&hash).is_ok());
        assert_eq!(loader.revocation_count(), 1);
    }

    #[test]
    fn failable_bpf_default_passes_through() {
        let mut loader = FailableBpfLoader::default();
        assert!(loader.load().is_ok());
        let hash = BpfHash::new([7u8; 32]);
        assert!(loader.allow_hash(&hash).is_ok());
        assert_eq!(loader.allow_count(), 1);
    }

    #[test]
    fn failable_bpf_load_failure_does_not_affect_other_ops() {
        let loader = FailableBpfLoader::new().with_fail_on_load();
        // allow_hash still works even if load failed (separate failure mode).
        let hash = BpfHash::new([3u8; 32]);
        assert!(loader.allow_hash(&hash).is_ok());
        assert_eq!(loader.allow_count(), 1);
    }

    #[test]
    fn failable_bpf_set_policy_unaffected_by_failures() {
        let loader = FailableBpfLoader::new()
            .with_fail_on_allow()
            .with_fail_on_load();
        // set_policy should still work.
        assert!(loader.set_policy(42, EnforcementPolicy::Enforce).is_ok());
    }
}
