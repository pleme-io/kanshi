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
}
