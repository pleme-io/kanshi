//! kanshi eBPF LSM programs for runtime binary verification.
//!
//! This crate contains BPF programs that hook into Linux Security Module (LSM)
//! attachment points to verify binary integrity at exec time.
//!
//! # Programs
//!
//! - `bprm_check_security` — Intercepts execve() to verify binary BLAKE3 hash
//!   against the allow map populated from SignatureGate CRDs.
//! - `file_open` — Monitors script execution (shebangs, interpreted files).
//! - `mmap_file` — Catches mmap PROT_EXEC to detect runtime code loading.
//!
//! # BPF Maps
//!
//! - `tameshi_allow_map` — HashMap<BpfHash, u8> of allowed binary hashes
//! - `tameshi_revocation_list` — HashMap<BpfHash, u8> of revoked hashes
//! - `tameshi_policy_map` — HashMap<u32, EnforcementPolicy> per-namespace policies
//!
//! # Build
//!
//! ```bash
//! # Requires Linux + nightly + bpf target
//! cargo +nightly build --target bpfel-unknown-none -Z build-std=core
//! ```
//!
//! On macOS, this crate serves as documentation only. The actual BPF programs
//! are cross-compiled in CI on Linux runners.

// BPF program stubs — these document the intended hooks
// Real implementation requires aya-bpf on Linux with nightly toolchain

/// BPF map type definitions matching kanshi-common.
pub mod maps {
    /// Allow map: BLAKE3 hash → 1 (allowed)
    /// Type: BPF_MAP_TYPE_HASH, key_size=32, value_size=1, max_entries=10000
    pub const ALLOW_MAP_NAME: &str = "tameshi_allow_map";

    /// Revocation list: BLAKE3 hash → 1 (revoked)
    /// Type: BPF_MAP_TYPE_HASH, key_size=32, value_size=1, max_entries=1000
    pub const REVOCATION_MAP_NAME: &str = "tameshi_revocation_list";

    /// Policy map: namespace_hash → EnforcementPolicy
    /// Type: BPF_MAP_TYPE_HASH, key_size=4, value_size=1, max_entries=256
    pub const POLICY_MAP_NAME: &str = "tameshi_policy_map";

    /// Event ring buffer for verification events
    /// Type: BPF_MAP_TYPE_RINGBUF, max_entries=256*1024
    pub const EVENT_RINGBUF_NAME: &str = "tameshi_events";
}

/// LSM hook: bprm_check_security
///
/// Called before exec. Computes BLAKE3 hash of the binary and checks
/// against allow_map. If not found or revoked, denies execution based
/// on the namespace's enforcement policy.
pub mod bprm_check {
    /// Hook signature: fn(ctx: &LsmContext) -> i32
    /// Returns: 0 = allow, -EPERM = deny
    pub const HOOK_NAME: &str = "bprm_check_security";
}

/// LSM hook: file_open
///
/// Monitors file opens with executable intent to catch script execution.
pub mod file_open {
    pub const HOOK_NAME: &str = "file_open";
}

/// LSM hook: mmap_file
///
/// Catches mmap with PROT_EXEC to detect runtime code loading (JIT, dlopen).
pub mod mmap_file {
    pub const HOOK_NAME: &str = "mmap_file";
}

fn main() {
    // This binary is a placeholder. On Linux with the BPF toolchain,
    // the real eBPF programs are compiled as BPF bytecode, not as
    // a regular binary. This main() exists only to satisfy cargo.
    eprintln!("kanshi-ebpf: This is a documentation scaffold.");
    eprintln!("Build BPF programs with: cargo +nightly build --target bpfel-unknown-none -Z build-std=core");
}
