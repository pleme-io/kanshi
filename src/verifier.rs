//! Hash verification against tameshi signatures.

use kanshi_common::BpfHash;
use tameshi::hash::Blake3Hash;

/// Trait for hash verification, enabling mock injection in tests.
pub trait HashValidator: Send + Sync {
    /// Verify whether an inode's hash is allowed and not revoked.
    fn verify(&self, inode: u64, actual_hash: &BpfHash) -> VerifyResult;
    /// Get the number of entries in the allow map.
    fn allow_count(&self) -> usize;
    /// Get the number of entries in the revocation list.
    fn revocation_count(&self) -> usize;
}

/// Verifier that checks binary hashes against the allow map.
pub struct HashVerifier {
    allow_map: std::collections::HashMap<u64, BpfHash>,
    revocation_map: std::collections::HashSet<BpfHash>,
}

impl HashVerifier {
    /// Create a new empty verifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            allow_map: std::collections::HashMap::new(),
            revocation_map: std::collections::HashSet::new(),
        }
    }

    /// Add an allowed hash for an inode.
    pub fn allow(&mut self, inode: u64, hash: BpfHash) {
        self.allow_map.insert(inode, hash);
    }

    /// Remove an allowed hash.
    pub fn remove_allow(&mut self, inode: u64) {
        self.allow_map.remove(&inode);
    }

    /// Add a hash to the revocation list.
    pub fn revoke(&mut self, hash: BpfHash) {
        self.revocation_map.insert(hash);
    }

    /// Remove a hash from the revocation list.
    pub fn unrevoke(&mut self, hash: &BpfHash) {
        self.revocation_map.remove(hash);
    }

    /// Convert a tameshi `Blake3Hash` to a `BpfHash`.
    #[inline]
    #[must_use]
    pub fn to_bpf_hash(hash: &Blake3Hash) -> BpfHash {
        BpfHash::new(hash.0)
    }
}

impl HashValidator for HashVerifier {
    #[inline]
    fn verify(&self, inode: u64, actual_hash: &BpfHash) -> VerifyResult {
        let Some(expected) = self.allow_map.get(&inode) else {
            return VerifyResult::Unknown;
        };

        if expected != actual_hash {
            return VerifyResult::Mismatch;
        }

        if self.revocation_map.contains(actual_hash) {
            return VerifyResult::Revoked;
        }

        VerifyResult::Allowed
    }

    #[inline]
    fn allow_count(&self) -> usize {
        self.allow_map.len()
    }

    #[inline]
    fn revocation_count(&self) -> usize {
        self.revocation_map.len()
    }
}

impl Default for HashVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a hash verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    /// Hash is in the allow map and not revoked.
    Allowed,
    /// Hash does not match the expected value.
    Mismatch,
    /// Hash is in the revocation list.
    Revoked,
    /// Inode is not in the allow map (unknown binary).
    Unknown,
}

impl std::fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::Mismatch => write!(f, "mismatch"),
            Self::Revoked => write!(f, "revoked"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash(byte: u8) -> BpfHash {
        BpfHash::new([byte; 32])
    }

    #[test]
    fn verify_allowed() {
        let mut v = HashVerifier::new();
        let hash = test_hash(1);
        v.allow(100, hash);
        assert_eq!(v.verify(100, &test_hash(1)), VerifyResult::Allowed);
    }

    #[test]
    fn verify_unknown() {
        let v = HashVerifier::new();
        assert_eq!(v.verify(999, &test_hash(1)), VerifyResult::Unknown);
    }

    #[test]
    fn verify_mismatch() {
        let mut v = HashVerifier::new();
        v.allow(100, test_hash(1));
        assert_eq!(v.verify(100, &test_hash(2)), VerifyResult::Mismatch);
    }

    #[test]
    fn verify_revoked() {
        let mut v = HashVerifier::new();
        let hash = test_hash(1);
        v.allow(100, hash);
        v.revoke(test_hash(1));
        assert_eq!(v.verify(100, &test_hash(1)), VerifyResult::Revoked);
    }

    #[test]
    fn unrevoke() {
        let mut v = HashVerifier::new();
        let hash = test_hash(1);
        v.allow(100, hash);
        v.revoke(test_hash(1));
        assert_eq!(v.verify(100, &test_hash(1)), VerifyResult::Revoked);
        v.unrevoke(&test_hash(1));
        assert_eq!(v.verify(100, &test_hash(1)), VerifyResult::Allowed);
    }

    #[test]
    fn remove_allow() {
        let mut v = HashVerifier::new();
        v.allow(100, test_hash(1));
        v.remove_allow(100);
        assert_eq!(v.verify(100, &test_hash(1)), VerifyResult::Unknown);
    }

    #[test]
    fn counts() {
        let mut v = HashVerifier::new();
        assert_eq!(v.allow_count(), 0);
        assert_eq!(v.revocation_count(), 0);
        v.allow(1, test_hash(1));
        v.allow(2, test_hash(2));
        v.revoke(test_hash(3));
        assert_eq!(v.allow_count(), 2);
        assert_eq!(v.revocation_count(), 1);
    }

    #[test]
    fn to_bpf_hash_conversion() {
        let blake3 = Blake3Hash::digest(b"test");
        let bpf = HashVerifier::to_bpf_hash(&blake3);
        assert_eq!(bpf.bytes, blake3.0);
    }

    #[test]
    fn verify_result_display() {
        assert_eq!(VerifyResult::Allowed.to_string(), "allowed");
        assert_eq!(VerifyResult::Mismatch.to_string(), "mismatch");
        assert_eq!(VerifyResult::Revoked.to_string(), "revoked");
        assert_eq!(VerifyResult::Unknown.to_string(), "unknown");
    }

    #[test]
    fn default_is_new() {
        let v = HashVerifier::default();
        assert_eq!(v.allow_count(), 0);
        assert_eq!(v.revocation_count(), 0);
    }
}
