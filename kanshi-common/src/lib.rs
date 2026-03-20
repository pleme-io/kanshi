//! Shared types between kanshi userspace daemon and eBPF programs.
//!
//! These types define the BPF map key/value structures used for
//! communication between kernel-space eBPF programs and the
//! userspace kanshi daemon.

/// Maximum hash length in bytes (BLAKE3 = 32 bytes).
pub const HASH_LEN: usize = 32;

/// BPF map key: file inode number.
pub type InodeKey = u64;

/// BPF map key: cgroup identifier.
pub type CgroupKey = u64;

/// BLAKE3 hash value stored in BPF maps.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "userspace", derive(serde::Serialize, serde::Deserialize))]
pub struct BpfHash {
    pub bytes: [u8; HASH_LEN],
}

impl BpfHash {
    /// Create a new BPF hash from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self { bytes }
    }

    /// Create a zero hash (used as sentinel for "no previous entry").
    #[must_use]
    pub const fn zero() -> Self {
        Self { bytes: [0u8; HASH_LEN] }
    }

    /// Check if this is the zero sentinel.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.bytes == [0u8; HASH_LEN]
    }
}

impl From<[u8; HASH_LEN]> for BpfHash {
    fn from(bytes: [u8; HASH_LEN]) -> Self {
        Self { bytes }
    }
}

impl From<BpfHash> for [u8; HASH_LEN] {
    fn from(hash: BpfHash) -> [u8; HASH_LEN] {
        hash.bytes
    }
}

/// Per-namespace enforcement policy stored in the BPF policy map.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "userspace", derive(serde::Serialize, serde::Deserialize))]
pub enum EnforcementPolicy {
    /// Log violations but do not block execution.
    Audit = 0,
    /// Block execution of unattested binaries.
    Enforce = 1,
    /// Allow all execution (unmanaged namespace).
    AllowUnknown = 2,
}

impl From<u8> for EnforcementPolicy {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Audit,
            1 => Self::Enforce,
            _ => Self::AllowUnknown,
        }
    }
}

impl From<EnforcementPolicy> for u8 {
    fn from(policy: EnforcementPolicy) -> u8 {
        policy as u8
    }
}

/// Verification result passed from eBPF to userspace via perf events.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "userspace", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationEvent {
    /// Process ID that triggered the event.
    pub pid: u32,
    /// Inode of the binary being executed.
    pub inode: u64,
    /// Cgroup ID of the container.
    pub cgroup_id: u64,
    /// The hash found in the allow map (zero if not found).
    pub expected_hash: BpfHash,
    /// The enforcement policy that was applied.
    pub policy: u8,
    /// Whether the execution was allowed (1) or denied (0).
    pub allowed: u8,
    /// Padding for alignment.
    pub _pad: [u8; 2],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_hash_zero() {
        let h = BpfHash::zero();
        assert!(h.is_zero());
        assert_eq!(h.bytes, [0u8; 32]);
    }

    #[test]
    fn bpf_hash_non_zero() {
        let h = BpfHash::new([1u8; 32]);
        assert!(!h.is_zero());
    }

    #[test]
    fn bpf_hash_from_bytes() {
        let bytes = [42u8; 32];
        let h: BpfHash = bytes.into();
        assert_eq!(h.bytes, bytes);
        let back: [u8; 32] = h.into();
        assert_eq!(back, bytes);
    }

    #[test]
    fn enforcement_policy_roundtrip() {
        assert_eq!(EnforcementPolicy::from(0), EnforcementPolicy::Audit);
        assert_eq!(EnforcementPolicy::from(1), EnforcementPolicy::Enforce);
        assert_eq!(EnforcementPolicy::from(2), EnforcementPolicy::AllowUnknown);
        assert_eq!(EnforcementPolicy::from(255), EnforcementPolicy::AllowUnknown);
    }

    #[test]
    fn enforcement_policy_to_u8() {
        assert_eq!(u8::from(EnforcementPolicy::Audit), 0);
        assert_eq!(u8::from(EnforcementPolicy::Enforce), 1);
        assert_eq!(u8::from(EnforcementPolicy::AllowUnknown), 2);
    }

    #[test]
    fn verification_event_size() {
        // Ensure the struct has a predictable size for BPF compatibility
        assert!(std::mem::size_of::<VerificationEvent>() <= 128);
    }

    #[test]
    fn bpf_hash_equality() {
        let a = BpfHash::new([1u8; 32]);
        let b = BpfHash::new([1u8; 32]);
        let c = BpfHash::new([2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
