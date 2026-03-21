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
///
/// # SECURITY: Inode-Based vs Content-Hash Verification
///
/// Inode-based lookup (via [`verify`](HashValidator::verify)) is a performance
/// optimization that avoids re-hashing the binary on every `execve()`.
/// The ACTUAL security boundary is the content hash comparison: even if an
/// inode is reused (e.g., file deleted and new file created with same inode),
/// the content hash will differ for a different binary, causing verification
/// to fail with [`VerifyResult::Mismatch`] in Enforce mode.
///
/// In Audit and AllowUnknown modes, inode reuse is logged as a security event
/// but does not prevent execution. Production deployments MUST use Enforce
/// mode for security guarantees.
///
/// For inode-reuse-immune verification, use [`verify_by_hash`](HashVerifier::verify_by_hash)
/// which checks the content hash directly against the allow set, bypassing
/// inode lookup entirely.
pub struct HashVerifier {
    allow_map: std::collections::HashMap<u64, BpfHash>,
    revocation_map: std::collections::HashSet<BpfHash>,
    /// Content-hash-based allow set for inode-independent verification.
    allow_set: std::collections::HashSet<BpfHash>,
}

impl HashVerifier {
    /// Create a new empty verifier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            allow_map: std::collections::HashMap::new(),
            revocation_map: std::collections::HashSet::new(),
            allow_set: std::collections::HashSet::new(),
        }
    }

    /// Add an allowed hash for an inode.
    ///
    /// Also adds the hash to the content-based allow set for
    /// [`verify_by_hash`](Self::verify_by_hash) lookups.
    pub fn allow(&mut self, inode: u64, hash: BpfHash) {
        self.allow_set.insert(hash);
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

    /// Verify a binary by its content hash directly (no inode lookup).
    ///
    /// This is the secure path — immune to inode reuse attacks.
    /// Checks the hash against the revocation list first, then the
    /// content-based allow set.
    #[inline]
    #[must_use]
    pub fn verify_by_hash(&self, hash: &BpfHash) -> VerifyResult {
        if self.revocation_map.contains(hash) {
            return VerifyResult::Revoked;
        }
        if self.allow_set.contains(hash) {
            return VerifyResult::Allowed;
        }
        VerifyResult::Unknown
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

    // =========================================================================
    // Content-hash-based verification (inode-reuse-immune)
    // =========================================================================

    #[test]
    fn verify_by_hash_allowed() {
        let mut v = HashVerifier::new();
        let hash = test_hash(10);
        v.allow(200, hash);
        assert_eq!(v.verify_by_hash(&test_hash(10)), VerifyResult::Allowed);
    }

    #[test]
    fn verify_by_hash_revoked() {
        let mut v = HashVerifier::new();
        let hash = test_hash(20);
        v.revoke(hash);
        assert_eq!(v.verify_by_hash(&test_hash(20)), VerifyResult::Revoked);
    }

    #[test]
    fn verify_by_hash_unknown() {
        let v = HashVerifier::new();
        assert_eq!(v.verify_by_hash(&test_hash(99)), VerifyResult::Unknown);
    }

    #[test]
    fn verify_by_hash_revocation_takes_priority() {
        let mut v = HashVerifier::new();
        let hash = test_hash(30);
        v.allow(300, hash);
        v.revoke(test_hash(30));
        // Hash is in both allow_set and revocation_map — revocation wins.
        assert_eq!(v.verify_by_hash(&test_hash(30)), VerifyResult::Revoked);
    }

    #[test]
    fn inode_reuse_with_different_hash_detected() {
        let mut v = HashVerifier::new();
        let hash_h1 = test_hash(40);
        let hash_h2 = test_hash(41);
        let inode = 400;
        // Add inode with hash H1
        v.allow(inode, hash_h1);
        assert_eq!(v.verify(inode, &hash_h1), VerifyResult::Allowed);
        // Same inode, different hash H2 → Mismatch (inode reuse detected)
        assert_eq!(v.verify(inode, &hash_h2), VerifyResult::Mismatch);
    }
}
