# kanshi Development Flow

## Architecture Overview

kanshi is a split-architecture daemon:
- **Userspace** (`src/`) — Rust, compiles on macOS + Linux, handles K8s CRD watching and BPF map management
- **Kernel space** (`kanshi-ebpf/`) — eBPF LSM programs, Linux-only, requires nightly toolchain

## Development on macOS

All userspace development happens on macOS:

```bash
# Normal development cycle
cargo check           # type check
cargo test            # run all userspace tests
cargo clippy          # lint (pedantic)
cargo build           # debug build
```

### Trait-Based Testing

Every kernel interaction is behind a trait:

```rust
pub trait BpfLoader: Send + Sync {
    fn load(&mut self) -> Result<(), KanshiError>;
    fn allow_hash(&self, hash: &BpfHash) -> Result<(), KanshiError>;
    fn remove_hash(&self, hash: &BpfHash) -> Result<(), KanshiError>;
    fn revoke_hash(&self, hash: &BpfHash) -> Result<(), KanshiError>;
    fn set_policy(&self, ns_hash: u32, policy: EnforcementPolicy) -> Result<(), KanshiError>;
}
```

Tests use `MockBpfLoader`:

```rust
#[test]
fn crd_watcher_populates_allow_map() {
    let loader = Arc::new(MockBpfLoader::new());
    let watcher = CrdWatcher::new(Arc::clone(&loader));

    let gate = SignatureGateRef {
        name: "my-gate".into(),
        namespace: "prod".into(),
        expected_signature: "blake3:af1349b9...".into(),
        layer_hashes: vec!["blake3:deadbeef...".into()],
    };

    watcher.on_gate_applied(&gate).unwrap();
    assert_eq!(loader.allow_count(), 2); // layer hash + expected sig
}
```

### No Real K8s Needed

The `CrdWatcher` is generic over `BpfLoader`:
```rust
pub struct CrdWatcher<L: BpfLoader> { loader: Arc<L> }
```

In tests, use `MockBpfLoader`. In production, use the real aya-based loader (Linux only).

## CRD → BPF Map Sync

```
┌──────────────────────────────────────┐
│           Kubernetes API             │
│                                      │
│  SignatureGate (sekiban.pleme.io)     │
│    spec:                             │
│      expectedSignature: blake3:abc   │
│      layers: [nix, oci, helm]        │
│      layerHashes:                    │
│        - blake3:def...               │
│        - blake3:123...               │
│        - blake3:456...               │
└──────────────┬───────────────────────┘
               │ kube-rs watcher (Applied/Deleted events)
               ▼
┌──────────────────────────────────────┐
│         CrdWatcher<L>                │
│                                      │
│  on_gate_applied(gate):              │
│    for hash in gate.layer_hashes:    │
│      loader.allow_hash(parse(hash))  │
│    loader.allow_hash(parse(sig))     │
│                                      │
│  on_gate_deleted(gate):              │
│    for hash in gate.layer_hashes:    │
│      loader.remove_hash(parse(hash)) │
│    loader.remove_hash(parse(sig))    │
└──────────────┬───────────────────────┘
               │ BPF syscall (Linux) / in-memory (test)
               ▼
┌──────────────────────────────────────┐
│         BPF Maps (kernel)            │
│                                      │
│  tameshi_allow_map:                  │
│    blake3:def → 1                    │
│    blake3:123 → 1                    │
│    blake3:456 → 1                    │
│    blake3:abc → 1                    │
│                                      │
│  tameshi_revocation_list:            │
│    (populated by CVE ingestion)      │
│                                      │
│  tameshi_policy_map:                 │
│    ns_hash(prod) → Enforce           │
│    ns_hash(dev)  → Audit             │
└──────────────────────────────────────┘
```

## eBPF Development (Linux Only)

### Prerequisites

```bash
# Install aya toolchain
rustup install nightly
rustup target add --toolchain nightly bpfel-unknown-none

# Build eBPF programs
cd kanshi-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core
```

### LSM Hook Flow

```
execve("./my-binary")
  └→ bprm_check_security (LSM hook)
      ├→ compute BLAKE3 hash of binary
      ├→ lookup in tameshi_revocation_list → if found: DENY
      ├→ lookup in tameshi_allow_map → if found: ALLOW
      ├→ lookup tameshi_policy_map for namespace
      │   ├→ Enforce: DENY (unknown binary)
      │   ├→ Audit: ALLOW + log to ringbuf
      │   └→ AllowUnknown: ALLOW
      └→ emit VerificationEvent to tameshi_events ringbuf
```

## Integration with tameshi Ecosystem

```
inshou (Nix gate) ─── pre-rebuild hash verification
        │
tameshi (core) ──── layer signature composition
        │
kensa (compliance) ─ NIST/OSCAL assessment → compliance hash
        │
sekiban (K8s gate) ─ admission webhook → SignatureGate CRDs
        │
kanshi (runtime) ── CRD watcher → BPF maps → LSM enforcement
```

kanshi is the last mile: after a deployment passes all gates (inshou, sekiban),
kanshi ensures the actual running binaries match their attested hashes.
