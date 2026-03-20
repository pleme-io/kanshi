# kanshi Development Flow

## Architecture Overview

kanshi is a split-architecture daemon implementing Pillars 3 and 4 of the Unified Theory of Infrastructure Proof:
- **Pillar 3 (Runtime Verification):** eBPF LSM hooks verify binary integrity at execution time
- **Pillar 4 (Continuous Monitoring):** EventMetricsCollector records all blocked executions into HeartbeatChain and generates CIRCIA regulatory evidence

Split architecture:
- **Userspace** (`src/`) -- Rust, compiles on macOS + Linux, handles K8s CRD watching, BPF map management, event processing, metrics, and heartbeat chain
- **Kernel space** (`kanshi-ebpf/`) -- eBPF LSM programs, Linux-only, requires nightly toolchain

## Development on macOS

All userspace development happens on macOS. All 130 tests pass natively.

```bash
# Normal development cycle
cargo check           # type check
cargo test            # run all 130 tests (123 lib + 6 integration + 1 doc)
cargo clippy          # lint (pedantic)
cargo build           # debug build
```

### Trait-Based Testing

Every kernel interaction is behind a trait:

```rust
// Pillar 3: BPF map management
pub trait BpfLoader: Send + Sync {
    fn load(&mut self) -> Result<(), KanshiError>;
    fn allow_hash(&self, hash: &BpfHash) -> Result<(), KanshiError>;
    fn remove_hash(&self, hash: &BpfHash) -> Result<(), KanshiError>;
    fn revoke_hash(&self, hash: &BpfHash) -> Result<(), KanshiError>;
    fn set_policy(&self, ns_hash: u32, policy: EnforcementPolicy) -> Result<(), KanshiError>;
}

// Pillar 4: BPF ring buffer reading
pub trait EventReader: Send + Sync {
    fn poll_events(&self) -> Result<Vec<BlockedExecutionEvent>, Error>;
}
```

Tests use `MockBpfLoader` and `MockEventReader`:

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

#[test]
fn event_metrics_collector_records_heartbeat() {
    let reader = Arc::new(MockEventReader::new());
    reader.push_event(BlockedExecutionEvent::for_test("/usr/bin/evil", BlockReason::Revoked));

    let chain = Arc::new(HeartbeatChain::new());
    let verifier = VerifierIdentity::new("kanshi", "test-node", "0.1.0");
    let collector = EventMetricsCollector::new(reader, Arc::clone(&chain), verifier);

    let count = collector.poll_and_record().unwrap();
    assert_eq!(count, 1);
    assert_eq!(chain.len(), 1);
    assert!(chain.verify_integrity());

    let entries = chain.entries();
    assert_eq!(entries[0].event, HeartbeatEvent::BinaryVerification);
    assert_eq!(entries[0].result, VerificationOutcome::Denied);
    assert_eq!(entries[0].resource, "/usr/bin/evil");
}
```

### No Real K8s Needed

The `CrdWatcher` is generic over `BpfLoader`:
```rust
pub struct CrdWatcher<L: BpfLoader> { loader: Arc<L> }
```

In tests, use `MockBpfLoader`. In production, use the real aya-based loader (Linux only).

### No Real BPF Ring Buffer Needed

The `EventMetricsCollector` is generic over `EventReader`:
```rust
pub struct EventMetricsCollector<E: EventReader> {
    event_reader: Arc<E>,
    heartbeat_chain: Arc<HeartbeatChain>,
    verifier_identity: VerifierIdentity,
}
```

In tests, use `MockEventReader` with pre-populated events. In production, use aya's `RingBuf` reader.

## CRD to BPF Map Sync (Pillar 3)

```
+--------------------------------------+
|           Kubernetes API             |
|                                      |
|  SignatureGate (sekiban.pleme.io)     |
|    spec:                             |
|      expectedSignature: blake3:abc   |
|      layers: [nix, oci, helm]        |
|      layerHashes:                    |
|        - blake3:def...               |
|        - blake3:123...               |
|        - blake3:456...               |
+--------------+-----------------------+
               | kube-rs watcher (Applied/Deleted events)
               v
+--------------------------------------+
|         CrdWatcher<L>                |
|                                      |
|  on_gate_applied(gate):              |
|    for hash in gate.layer_hashes:    |
|      loader.allow_hash(parse(hash))  |
|    loader.allow_hash(parse(sig))     |
|                                      |
|  on_gate_deleted(gate):              |
|    for hash in gate.layer_hashes:    |
|      loader.remove_hash(parse(hash)) |
|    loader.remove_hash(parse(sig))    |
+--------------+-----------------------+
               | BPF syscall (Linux) / in-memory (test)
               v
+--------------------------------------+
|         BPF Maps (kernel)            |
|                                      |
|  tameshi_allow_map:                  |
|    blake3:def -> 1                   |
|    blake3:123 -> 1                   |
|    blake3:456 -> 1                   |
|    blake3:abc -> 1                   |
|                                      |
|  tameshi_revocation_list:            |
|    (populated by CVE ingestion)      |
|                                      |
|  tameshi_policy_map:                 |
|    ns_hash(prod) -> Enforce          |
|    ns_hash(dev)  -> Audit            |
+--------------------------------------+
```

## Event Processing Flow (Pillar 4)

```
+--------------------------------------+
|  BPF ring buffer (tameshi_events)    |
|  BlockedExecutionEvent:              |
|    pid, inode, cgroup_id,            |
|    looked_up_hash, policy,           |
|    reason, binary_path               |
+--------------+-----------------------+
               | EventReader.poll_events()
               v
+--------------------------------------+
|  EventMetricsCollector.poll_and_record()  |
|                                      |
|  For each BlockedExecutionEvent:     |
|    1. Map BlockReason to label:      |
|       NotInAllowMap -> "not_in_allow_map" |
|       HashMismatch  -> "hash_mismatch"    |
|       Revoked       -> "revoked"          |
|       Unknown       -> "unknown"          |
|                                      |
|    2. Record Prometheus metric:      |
|       tameshi_blocked_executions_total    |
|       {reason="...", binary="..."}   |
|                                      |
|    3. Append to HeartbeatChain:      |
|       verifier: kanshi/node-id/ver   |
|       event: BinaryVerification      |
|       outcome: Denied                |
|       resource: /path/to/binary      |
|       signature_checked: looked_up_hash |
+--------------+-----------------------+
               | generate_circia_report(window_hours)
               v
+--------------------------------------+
|  CirciaReport (CIRCIA evidence)      |
|                                      |
|  window_start, window_end            |
|  total_blocked: u64                  |
|  blocked_by_reason: BTreeMap         |
|  blocked_binaries: [                 |
|    { binary_path, block_count,       |
|      first_seen, last_seen, reason } |
|  ]                                   |
|  heartbeat_chain_length: u64         |
|  chain_integrity_verified: bool      |
|                                      |
|  is_clean() -> bool                  |
|  to_json() -> String                 |
+--------------------------------------+
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
  +-> bprm_check_security (LSM hook)
      +-> compute BLAKE3 hash of binary
      +-> lookup in tameshi_revocation_list -> if found: DENY
      +-> lookup in tameshi_allow_map -> if found: ALLOW
      +-> lookup tameshi_policy_map for namespace
      |   +-> Enforce: DENY (unknown binary)
      |   +-> Audit: ALLOW + log to ringbuf
      |   +-> AllowUnknown: ALLOW
      +-> emit BlockedExecutionEvent to tameshi_events ringbuf
```

### Additional LSM Hooks

| Hook | Purpose | Attack Mitigated |
|------|---------|-----------------|
| `file_open` | Script/config verification | Malicious scripts |
| `mmap_file` | Shared library verification | dlopen injection, JIT exploitation |
| `file_mprotect` | W^X enforcement (Write XOR Execute) | Code injection via writable+executable pages |
| `inode_permission` | procfs/sysfs write masking | Container escape via proc manipulation |

## Integration with tameshi Ecosystem

```
inshou (Nix gate, 366 tests)
        |
        v
tameshi (core, 925 tests) --- layer signature composition
        |
        v
kensa (compliance, 377 tests) --- NIST/OSCAL assessment
        |
        v
sekiban (K8s gate, 315 tests) --- admission webhook -> SignatureGate CRDs
        |
        v
kanshi (runtime, 130 tests)
  |
  +-- Pillar 3: CRD watcher -> BPF maps -> LSM enforcement
  |     (CrdWatcher -> BpfLoader -> kernel LSM hooks)
  |
  +-- Pillar 4: Event reader -> metrics + heartbeat -> CIRCIA report
        (EventReader -> EventMetricsCollector -> HeartbeatChain -> CirciaReport)
```

kanshi is the last mile: after a deployment passes all gates (inshou, sekiban), kanshi ensures the actual running binaries match their attested hashes at execution time. The EventMetricsCollector provides the continuous monitoring evidence required by CIRCIA for the 72-hour regulatory reporting window.

## Test Categories

```bash
# All tests
cargo test

# Pillar 3: BPF map management
cargo test bpf_loader
cargo test crd_watcher
cargo test verifier
cargo test policy

# Pillar 4: Event processing and CIRCIA
cargo test event_reader
cargo test event_metrics

# Shared types
cargo test --package kanshi-common

# Integration (full pipeline)
cargo test --test pillar3_4_integration
```
