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

/// Maximum length of a binary path in a blocked execution event.
pub const BINARY_PATH_LEN: usize = 256;

/// Reason why a binary execution was blocked.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "userspace", derive(serde::Serialize, serde::Deserialize))]
pub enum BlockReason {
    /// Binary hash not found in allow map.
    NotInAllowMap = 0,
    /// Binary hash found but doesn't match expected.
    HashMismatch = 1,
    /// Binary hash is in the revocation list.
    Revoked = 2,
    /// Unknown reason (fallback).
    Unknown = 3,
}

impl From<u8> for BlockReason {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::NotInAllowMap,
            1 => Self::HashMismatch,
            2 => Self::Revoked,
            _ => Self::Unknown,
        }
    }
}

impl From<BlockReason> for u8 {
    fn from(reason: BlockReason) -> Self {
        reason as u8
    }
}

/// Event emitted by the eBPF sentinel when a binary execution is blocked.
///
/// This is the kernel-to-userspace communication format via BPF ring buffer.
/// Must be `#[repr(C)]` for BPF compatibility.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct BlockedExecutionEvent {
    /// Process ID that attempted execution.
    pub pid: u32,
    /// Inode number of the binary.
    pub inode: u64,
    /// Cgroup ID (for namespace identification).
    pub cgroup_id: u64,
    /// Hash that was looked up (computed by userspace, stored in map).
    pub looked_up_hash: BpfHash,
    /// Enforcement policy that was applied.
    pub policy: EnforcementPolicy,
    /// Why the execution was blocked.
    pub reason: BlockReason,
    /// Length of the binary path (excluding null terminator).
    pub binary_path_len: u16,
    /// Null-terminated binary path (truncated to [`BINARY_PATH_LEN`] bytes).
    pub binary_path: [u8; BINARY_PATH_LEN],
}

impl BlockedExecutionEvent {
    /// Create a zero-initialized event.
    #[must_use]
    pub fn zeroed() -> Self {
        Self {
            pid: 0,
            inode: 0,
            cgroup_id: 0,
            looked_up_hash: BpfHash::zero(),
            policy: EnforcementPolicy::AllowUnknown,
            reason: BlockReason::Unknown,
            binary_path_len: 0,
            binary_path: [0u8; BINARY_PATH_LEN],
        }
    }

    /// Extract the binary path as a string (up to `binary_path_len` or first null).
    #[must_use]
    pub fn path(&self) -> &str {
        let len = (self.binary_path_len as usize).min(BINARY_PATH_LEN);
        let slice = &self.binary_path[..len];
        // Find first null byte
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        core::str::from_utf8(&slice[..end]).unwrap_or("<invalid-utf8>")
    }

    /// Create a test event with the given path and reason.
    #[must_use]
    pub fn for_test(path: &str, reason: BlockReason) -> Self {
        let mut event = Self::zeroed();
        event.reason = reason;
        let bytes = path.as_bytes();
        let copy_len = bytes.len().min(BINARY_PATH_LEN);
        event.binary_path[..copy_len].copy_from_slice(&bytes[..copy_len]);
        event.binary_path_len = copy_len as u16;
        event
    }
}

/// Userspace-friendly representation of a [`BlockedExecutionEvent`].
///
/// Converts fixed-size BPF-compatible fields into owned strings suitable
/// for JSON serialization, logging, and API responses.
#[cfg(feature = "userspace")]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UserBlockedEvent {
    /// Process ID that attempted execution.
    pub pid: u32,
    /// Inode number of the binary.
    pub inode: u64,
    /// Cgroup ID (for namespace identification).
    pub cgroup_id: u64,
    /// Hex-encoded BLAKE3 hash that was looked up.
    pub hash: String,
    /// Enforcement policy name (e.g. "Audit", "Enforce").
    pub policy: String,
    /// Block reason name (e.g. "NotInAllowMap", "Revoked").
    pub reason: String,
    /// Binary path as a UTF-8 string.
    pub binary_path: String,
}

#[cfg(feature = "userspace")]
impl From<&BlockedExecutionEvent> for UserBlockedEvent {
    fn from(event: &BlockedExecutionEvent) -> Self {
        Self {
            pid: event.pid,
            inode: event.inode,
            cgroup_id: event.cgroup_id,
            hash: event
                .looked_up_hash
                .bytes
                .iter()
                .fold(String::with_capacity(64), |mut acc, b| {
                    use core::fmt::Write;
                    let _ = write!(acc, "{b:02x}");
                    acc
                }),
            policy: format!("{:?}", event.policy),
            reason: format!("{:?}", event.reason),
            binary_path: event.path().to_owned(),
        }
    }
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

    #[test]
    fn blocked_execution_event_zeroed() {
        let event = BlockedExecutionEvent::zeroed();
        assert_eq!(event.pid, 0);
        assert_eq!(event.inode, 0);
        assert_eq!(event.cgroup_id, 0);
        assert!(event.looked_up_hash.is_zero());
        assert_eq!(event.policy, EnforcementPolicy::AllowUnknown);
        assert_eq!(event.reason, BlockReason::Unknown);
        assert_eq!(event.binary_path_len, 0);
        assert_eq!(event.binary_path, [0u8; BINARY_PATH_LEN]);
    }

    #[test]
    fn blocked_execution_event_for_test() {
        let event = BlockedExecutionEvent::for_test("/usr/bin/evil", BlockReason::Revoked);
        assert_eq!(event.path(), "/usr/bin/evil");
        assert_eq!(event.reason, BlockReason::Revoked);
        assert_eq!(event.binary_path_len, 13);
    }

    #[test]
    fn blocked_execution_event_path_extracts_correctly() {
        let mut event = BlockedExecutionEvent::zeroed();
        let path = b"/usr/local/bin/test";
        event.binary_path[..path.len()].copy_from_slice(path);
        event.binary_path_len = path.len() as u16;
        assert_eq!(event.path(), "/usr/local/bin/test");
    }

    #[test]
    fn blocked_execution_event_path_handles_embedded_null() {
        let mut event = BlockedExecutionEvent::zeroed();
        let path = b"/usr/bin\0extra";
        event.binary_path[..path.len()].copy_from_slice(path);
        event.binary_path_len = path.len() as u16;
        assert_eq!(event.path(), "/usr/bin");
    }

    #[test]
    fn block_reason_from_u8_roundtrip() {
        assert_eq!(BlockReason::from(0), BlockReason::NotInAllowMap);
        assert_eq!(u8::from(BlockReason::NotInAllowMap), 0);
        assert_eq!(BlockReason::from(1), BlockReason::HashMismatch);
        assert_eq!(u8::from(BlockReason::HashMismatch), 1);
        assert_eq!(BlockReason::from(2), BlockReason::Revoked);
        assert_eq!(u8::from(BlockReason::Revoked), 2);
        assert_eq!(BlockReason::from(3), BlockReason::Unknown);
        assert_eq!(u8::from(BlockReason::Unknown), 3);
    }

    #[test]
    fn block_reason_from_invalid_u8_returns_unknown() {
        assert_eq!(BlockReason::from(4), BlockReason::Unknown);
        assert_eq!(BlockReason::from(100), BlockReason::Unknown);
        assert_eq!(BlockReason::from(255), BlockReason::Unknown);
    }

    #[cfg(feature = "userspace")]
    #[test]
    fn user_blocked_event_from_blocked_execution_event() {
        let mut event =
            BlockedExecutionEvent::for_test("/usr/bin/malware", BlockReason::NotInAllowMap);
        event.pid = 1234;
        event.inode = 5678;
        event.cgroup_id = 42;
        event.policy = EnforcementPolicy::Enforce;
        event.looked_up_hash = BpfHash::new([0xab; HASH_LEN]);

        let user_event = UserBlockedEvent::from(&event);
        assert_eq!(user_event.pid, 1234);
        assert_eq!(user_event.inode, 5678);
        assert_eq!(user_event.cgroup_id, 42);
        assert_eq!(user_event.hash, "ab".repeat(32));
        assert_eq!(user_event.policy, "Enforce");
        assert_eq!(user_event.reason, "NotInAllowMap");
        assert_eq!(user_event.binary_path, "/usr/bin/malware");
    }

    #[cfg(feature = "userspace")]
    #[test]
    fn user_blocked_event_serde_roundtrip() {
        let mut event =
            BlockedExecutionEvent::for_test("/opt/bin/test", BlockReason::HashMismatch);
        event.pid = 99;
        event.inode = 111;
        event.cgroup_id = 222;
        event.policy = EnforcementPolicy::Audit;

        let user_event = UserBlockedEvent::from(&event);
        let json = serde_json::to_string(&user_event).expect("serialize");
        let deserialized: UserBlockedEvent =
            serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.pid, user_event.pid);
        assert_eq!(deserialized.inode, user_event.inode);
        assert_eq!(deserialized.cgroup_id, user_event.cgroup_id);
        assert_eq!(deserialized.hash, user_event.hash);
        assert_eq!(deserialized.policy, user_event.policy);
        assert_eq!(deserialized.reason, user_event.reason);
        assert_eq!(deserialized.binary_path, user_event.binary_path);
    }
}
