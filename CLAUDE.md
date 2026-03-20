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
                    ┌─────────────────────────────┐
                    │    Kubernetes API Server     │
                    │  (SignatureGate CRDs)        │
                    └─────────┬───────────────────┘
                              │ kube-rs watcher
                              ▼
              ┌───────────────────────────────────┐
              │         kanshi (userspace)         │
              │                                   │
              │  crd_watcher.rs → bpf_loader.rs   │
              │       │               │           │
              │       │          BPF map ops       │
              │       ▼               ▼           │
              │  verifier.rs    policy.rs          │
              │  config.rs      metrics.rs         │
              │  health.rs      error.rs           │
              └───────────────┬───────────────────┘
                              │ BPF syscall
                              ▼
              ┌───────────────────────────────────┐
              │     kanshi-ebpf (kernel space)     │
              │                                   │
              │  bprm_check_security (execve)      │
              │  file_open (scripts)               │
              │  mmap_file (dlopen/JIT)            │
              └───────────────────────────────────┘
```

```
src/
  lib.rs               -- module declarations
  error.rs             -- Error enum (categorized: transient/permanent)
  config.rs            -- Config (layered: defaults -> YAML -> KANSHI_ env)
  policy.rs            -- Per-namespace enforcement (Audit/Enforce/AllowUnknown)
  verifier.rs          -- Hash verification against allow/revocation maps
  health.rs            -- Health server (/healthz, /readyz)
  metrics.rs           -- Prometheus metrics
  bpf_loader.rs        -- BpfLoader trait, MockBpfLoader (userspace BPF map management)
  crd_watcher.rs       -- CrdWatcher, SignatureGateRef, parse_bpf_hash
kanshi-common/
  src/lib.rs           -- Shared BPF map types (BpfHash, EnforcementPolicy, VerificationEvent)
kanshi-ebpf/           -- eBPF program scaffold (Linux-only, cross-compile in CI)
  src/main.rs          -- LSM hook documentation + map constants
chart/
  kanshi/              -- Helm DaemonSet chart
```

## Development Flow

### macOS Development (Cross-Compile Model)

kanshi has a split architecture:
- **Userspace daemon** (`src/`) — compiles and tests on macOS
- **eBPF programs** (`kanshi-ebpf/`) — Linux-only, cross-compiled in CI

On macOS:
1. All userspace code compiles and tests natively
2. `BpfLoader` trait has `MockBpfLoader` for testing without kernel
3. `CrdWatcher` tests use mock loader, no real K8s cluster needed
4. `kanshi-ebpf/` is a documentation scaffold — does NOT compile on macOS

### Linux CI/CD

```bash
# Build eBPF programs (Linux only, nightly required)
cd kanshi-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core

# Build userspace daemon
cargo build --release

# Run integration tests with real BPF (Linux CI runners only)
cargo test --features integration-tests
```

### CRD → BPF Map Sync Flow

```
SignatureGate CRD (create/update)
  → CrdWatcher.on_gate_applied()
    → parse layer hashes from CRD spec
    → BpfLoader.allow_hash() for each layer hash
    → BpfLoader.allow_hash() for expected signature

SignatureGate CRD (delete)
  → CrdWatcher.on_gate_deleted()
    → BpfLoader.remove_hash() for each layer hash
```

## Key Types

### `BpfHash` (kanshi-common)
- `[u8; 32]` hash stored in BPF maps
- `zero()`, `is_zero()`, `From<[u8; 32]>`

### `EnforcementPolicy` (kanshi-common)
- `Audit` (0), `Enforce` (1), `AllowUnknown` (2)
- Maps to/from `u8` for BPF map storage

### `BpfLoader` trait (bpf_loader.rs)
- `fn load(&mut self) -> Result<()>`
- `fn allow_hash(&self, hash: &BpfHash) -> Result<()>`
- `fn remove_hash(&self, hash: &BpfHash) -> Result<()>`
- `fn revoke_hash(&self, hash: &BpfHash) -> Result<()>`
- `fn set_policy(&self, namespace_hash, policy) -> Result<()>`
- Impl: `MockBpfLoader` (in-memory)

### `CrdWatcher<L: BpfLoader>` (crd_watcher.rs)
- `fn on_gate_applied(&self, gate: &SignatureGateRef) -> Result<()>`
- `fn on_gate_deleted(&self, gate: &SignatureGateRef) -> Result<()>`

### `HashVerifier` (verifier.rs)
- `allow(inode, hash)`, `revoke(hash)`, `verify(inode, hash) -> VerifyResult`

### `PolicyEngine` (policy.rs)
- `set_policy(namespace, policy)`, `get_policy(namespace)`
- `should_enforce(namespace)`, `is_audit_only(namespace)`

## BPF Map Layout

```
tameshi_allow_map:       BpfHash([u8;32]) → u8(1)               // allowed binary hashes
tameshi_revocation_list: BpfHash([u8;32]) → u8(1)               // revoked hashes
tameshi_policy_map:      namespace_hash(u32) → EnforcementPolicy // per-ns policy
tameshi_events:          ringbuf(256KB)                          // verification events
```

## LSM Hooks (Linux only, kanshi-ebpf crate)

- `bprm_check_security` — binary verification at execve
- `file_open` — script/config verification at open
- `mmap_file` — shared library verification at mmap
- `file_mprotect` — W^X enforcement (Write XOR Execute)
- `inode_permission` — procfs/sysfs write masking

## Dependencies

| Crate | Purpose |
|-------|---------|
| kanshi-common | Shared BPF map types |
| tameshi | Core integrity library |
| tokio | Async runtime |
| axum | Health + admin HTTP server |
| kube | Kubernetes client + CRD watcher |
| k8s-openapi | K8s API types |
| prometheus-client | Metrics |
| figment | Layered config |
| const-hex | Hex encode/decode |
