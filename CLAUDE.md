# kanshi -- eBPF runtime integrity sentinel

eBPF-based runtime binary verification daemon. Uses LSM hooks to verify binary
integrity at execution time. Watches tameshi SignatureGate CRDs and populates
BPF hash maps. Edition 2024, Rust 1.89.0, MIT.

## Build

```bash
cargo check
cargo test          # userspace tests only (eBPF requires Linux)
cargo build --release
```

## Architecture

```
src/
  lib.rs               -- module declarations
  error.rs             -- Error enum (categorized: transient/permanent)
  config.rs            -- Config (layered: defaults -> YAML -> KANSHI_ env)
  policy.rs            -- Per-namespace enforcement (Audit/Enforce/AllowUnknown)
  verifier.rs          -- Hash verification against allow/revocation maps
  health.rs            -- Health server (/healthz, /readyz)
  metrics.rs           -- Prometheus metrics
kanshi-common/
  src/lib.rs           -- Shared BPF map types (BpfHash, EnforcementPolicy, VerificationEvent)
```

## Key Types

### `BpfHash` (kanshi-common)
- `[u8; 32]` hash stored in BPF maps
- `zero()`, `is_zero()`, `From<[u8; 32]>`

### `EnforcementPolicy` (kanshi-common)
- `Audit` (0), `Enforce` (1), `AllowUnknown` (2)
- Maps to/from `u8` for BPF map storage

### `HashVerifier` (verifier.rs)
- `allow(inode, hash)`, `revoke(hash)`, `verify(inode, hash) -> VerifyResult`
- `VerifyResult`: `Allowed | Mismatch | Revoked | Unknown`

### `PolicyEngine` (policy.rs)
- `set_policy(namespace, policy)`, `get_policy(namespace)`
- `should_enforce(namespace)`, `is_audit_only(namespace)`

## BPF Map Layout

```
tameshi_allow_map:      inode(u64) -> BpfHash([u8;32])     // allowed binary hashes
tameshi_revocation_list: BpfHash([u8;32]) -> u8(1)          // revoked hashes
tameshi_policy_map:     cgroup_id(u64) -> EnforcementPolicy(u8) // per-ns policy
```

## LSM Hooks (Linux only, kanshi-ebpf crate)

- `bprm_check_security` -- binary verification at execve
- `file_open` -- script/config verification at open
- `mmap_file` -- shared library verification at mmap
- `file_mprotect` -- W^X enforcement (Write XOR Execute)
- `inode_permission` -- procfs/sysfs write masking

## Dependencies

| Crate | Purpose |
|-------|---------|
| kanshi-common | Shared BPF map types |
| tameshi | Core integrity library |
| tokio | Async runtime |
| axum | Health + admin HTTP server |
| prometheus-client | Metrics |
| figment | Layered config |
