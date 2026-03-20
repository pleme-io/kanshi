# kanshi -- eBPF runtime integrity sentinel

eBPF-based runtime binary verification daemon. Pillars 3 and 4 of the Unified Theory of Infrastructure Proof: runtime binary verification (Pillar 3) and continuous monitoring with regulatory evidence generation (Pillar 4). Uses LSM hooks to verify binary integrity at execution time. Watches tameshi SignatureGate CRDs and populates BPF hash maps. Edition 2024, Rust 1.89.0, MIT.

## Build

```bash
cargo check
cargo test          # 130 tests (123 lib + 6 integration + 1 doc)
cargo build --release
```

## Test Breakdown

| Category | Count | What It Covers |
|----------|------:|----------------|
| Unit (lib) | 123 | All userspace modules, every trait method, every type variant |
| Integration (tests/) | 6 | Full pipeline: event reader -> metrics collector -> heartbeat chain -> CIRCIA report |
| Documentation (doc-tests) | 1 | CirciaReport inline example |
| **Total** | **130** | |

## Architecture

### Pillar 3: Runtime Binary Verification

```
                    +-----------------------------+
                    |    Kubernetes API Server     |
                    |  (SignatureGate CRDs)        |
                    +---------+-------------------+
                              | kube-rs watcher
                              v
              +-----------------------------------+
              |         kanshi (userspace)         |
              |                                   |
              |  crd_watcher.rs -> bpf_loader.rs  |
              |       |               |           |
              |       |          BPF map ops       |
              |       v               v           |
              |  verifier.rs    policy.rs          |
              |  config.rs      metrics.rs         |
              |  health.rs      error.rs           |
              +---------------+-------------------+
                              | BPF syscall
                              v
              +-----------------------------------+
              |     kanshi-ebpf (kernel space)     |
              |                                   |
              |  bprm_check_security (execve)      |
              |  file_open (scripts)               |
              |  mmap_file (dlopen/JIT)            |
              |  file_mprotect (W^X enforcement)   |
              |  inode_permission (procfs masking)  |
              +-----------------------------------+
```

### Pillar 4: Continuous Monitoring and Regulatory Evidence

```
              +-----------------------------------+
              |    BPF ring buffer (256KB)         |
              |  BlockedExecutionEvent             |
              +---------------+-------------------+
                              | poll_events()
                              v
              +-----------------------------------+
              |     EventMetricsCollector<E>       |
              |                                   |
              |  EventReader trait -> poll_events()|
              |       |                           |
              |       +-> Prometheus counter       |
              |       |   tameshi_blocked_         |
              |       |   executions_total         |
              |       |                           |
              |       +-> HeartbeatChain.append()  |
              |           (tamper-evident trail)   |
              +---------------+-------------------+
                              | generate_circia_report()
                              v
              +-----------------------------------+
              |          CirciaReport              |
              |  72-hour regulatory evidence       |
              +-----------------------------------+
```

```
src/
  lib.rs               -- 10 module declarations
  error.rs             -- Error enum (categorized: transient/permanent)
  config.rs            -- Config (layered: defaults -> YAML -> KANSHI_ env)
  policy.rs            -- Per-namespace enforcement (Audit/Enforce/AllowUnknown)
  verifier.rs          -- Hash verification against allow/revocation maps
  health.rs            -- Health server (/healthz, /readyz)
  metrics.rs           -- Prometheus metrics (tameshi_blocked_executions_total counter)
  bpf_loader.rs        -- BpfLoader trait, MockBpfLoader (userspace BPF map management)
  crd_watcher.rs       -- CrdWatcher<L>, SignatureGateRef, parse_bpf_hash
  event_reader.rs      -- EventReader trait, MockEventReader, blocked_event_to_heartbeat_params
  event_metrics.rs     -- EventMetricsCollector<E>, CirciaReport, BlockedBinarySummary
kanshi-common/
  src/lib.rs           -- Shared BPF map types (BpfHash, EnforcementPolicy, BlockReason, VerificationEvent, BlockedExecutionEvent, UserBlockedEvent)
kanshi-ebpf/           -- eBPF program scaffold (Linux-only, cross-compile in CI)
  src/main.rs          -- LSM hook documentation + map constants
chart/
  kanshi/              -- Helm DaemonSet chart
tests/
  pillar3_4_integration.rs -- 6 end-to-end pipeline tests
```

## All Traits

| Trait | Module | Methods | Mock Impl | Purpose |
|-------|--------|---------|-----------|---------|
| `BpfLoader` | `bpf_loader.rs` | `load()`, `allow_hash()`, `remove_hash()`, `revoke_hash()`, `set_policy()` | `MockBpfLoader` | BPF map management |
| `EventReader` | `event_reader.rs` | `poll_events() -> Vec<BlockedExecutionEvent>` | `MockEventReader` | BPF ring buffer reading |

Both traits are `Send + Sync` and object-safe (can be used as `dyn BpfLoader` / `dyn EventReader`).

## All Types

### kanshi-common (shared with eBPF programs)

| Type | Fields | Purpose |
|------|--------|---------|
| `BpfHash` | `bytes: [u8; 32]` | BLAKE3 hash stored in BPF maps. `#[repr(C)]`. Methods: `new()`, `zero()`, `is_zero()`, `From<[u8; 32]>` |
| `EnforcementPolicy` | enum: `Audit(0)`, `Enforce(1)`, `AllowUnknown(2)` | Per-namespace policy. `#[repr(u8)]` for BPF map storage. `From<u8>` roundtrip. |
| `BlockReason` | enum: `NotInAllowMap(0)`, `HashMismatch(1)`, `Revoked(2)`, `Unknown(3)` | Why a binary was blocked. `#[repr(u8)]`. `Display` impl matches Prometheus metric labels. |
| `VerificationEvent` | `pid: u32`, `inode: u64`, `cgroup_id: u64`, `expected_hash: BpfHash`, `policy: u8`, `allowed: u8` | Kernel-to-userspace perf event. `#[repr(C)]`. Size <= 128 bytes. |
| `BlockedExecutionEvent` | `pid: u32`, `inode: u64`, `cgroup_id: u64`, `looked_up_hash: BpfHash`, `policy: EnforcementPolicy`, `reason: BlockReason`, `binary_path_len: u16`, `binary_path: [u8; 256]` | Ring buffer blocked event. `#[repr(C)]`. Methods: `zeroed()`, `path() -> &str`, `for_test()`. Size <= 512 bytes. |
| `UserBlockedEvent` | `pid`, `inode`, `cgroup_id`, `hash: String`, `policy: String`, `reason: String`, `binary_path: String` | Userspace-friendly representation. `Serialize`/`Deserialize`. `From<&BlockedExecutionEvent>`. Feature-gated: `userspace`. |

### kanshi (userspace daemon)

| Type | Module | Purpose |
|------|--------|---------|
| `CrdWatcher<L: BpfLoader>` | `crd_watcher.rs` | Generic over BpfLoader. `on_gate_applied()` populates allow map. `on_gate_deleted()` removes hashes. |
| `SignatureGateRef` | `crd_watcher.rs` | Lightweight CRD reference: name, namespace, expected_signature, layer_hashes. |
| `HashVerifier` | `verifier.rs` | `allow(inode, hash)`, `revoke(hash)`, `verify(inode, hash) -> VerifyResult`. Revocation takes priority. |
| `PolicyEngine` | `policy.rs` | `set_policy(namespace, policy)`, `get_policy(namespace)`, `should_enforce(namespace)`, `is_audit_only(namespace)`. |
| `MockBpfLoader` | `bpf_loader.rs` | In-memory BPF map simulation. `allow_count()`, `revoke_count()`, `has_hash()`, `has_policy()`. |
| `MockEventReader` | `event_reader.rs` | Pre-populated event queue. `push_event()`, `pending_count()`. Thread-safe (`Mutex`). |
| `EventMetricsCollector<E: EventReader>` | `event_metrics.rs` | Polls `EventReader`, records Prometheus metrics, appends to `HeartbeatChain`. `poll_and_record() -> usize`. `generate_circia_report(window_hours) -> CirciaReport`. |
| `CirciaReport` | `event_metrics.rs` | CIRCIA regulatory evidence: `window_start`, `window_end`, `total_blocked`, `blocked_by_reason: BTreeMap`, `blocked_binaries: Vec<BlockedBinarySummary>`, `heartbeat_chain_length`, `chain_integrity_verified`. Methods: `is_clean()`, `to_json()`. `Serialize`/`Deserialize`. |
| `BlockedBinarySummary` | `event_metrics.rs` | Per-binary block summary: `binary_path`, `block_count`, `first_seen`, `last_seen`, `reason`. |

## Development Flow

### macOS Development (Cross-Compile Model)

kanshi has a split architecture:
- **Userspace daemon** (`src/`) -- compiles and tests on macOS (130 tests pass natively)
- **eBPF programs** (`kanshi-ebpf/`) -- Linux-only, cross-compiled in CI

On macOS:
1. All userspace code compiles and tests natively
2. `BpfLoader` trait has `MockBpfLoader` for testing without kernel
3. `EventReader` trait has `MockEventReader` for testing without BPF ring buffer
4. `CrdWatcher` tests use mock loader, no real K8s cluster needed
5. `kanshi-ebpf/` is a documentation scaffold -- does NOT compile on macOS

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

### CRD to BPF Map Sync Flow

```
SignatureGate CRD (create/update)
  -> CrdWatcher.on_gate_applied()
    -> parse layer hashes from CRD spec
    -> BpfLoader.allow_hash() for each layer hash
    -> BpfLoader.allow_hash() for expected signature

SignatureGate CRD (delete)
  -> CrdWatcher.on_gate_deleted()
    -> BpfLoader.remove_hash() for each layer hash
```

### Event Processing Flow (Pillar 4)

```
BPF ring buffer (blocked execution events)
  -> EventReader.poll_events()
    -> Vec<BlockedExecutionEvent>
      -> blocked_event_to_heartbeat_params() for each event
        -> HeartbeatChain.append(verifier, BinaryVerification, Denied, path, hash)
      -> metrics::record_blocked_execution(reason_label, binary_path)
        -> tameshi_blocked_executions_total counter incremented
      -> CirciaReport aggregation
        -> blocked_by_reason: BTreeMap<String, u64>
        -> blocked_binaries: Vec<BlockedBinarySummary>
        -> chain_integrity_verified: bool
```

## BPF Map Layout

```
tameshi_allow_map:       BpfHash([u8;32]) -> u8(1)               // allowed binary hashes
tameshi_revocation_list: BpfHash([u8;32]) -> u8(1)               // revoked hashes
tameshi_policy_map:      namespace_hash(u32) -> EnforcementPolicy // per-ns policy
tameshi_events:          ringbuf(256KB)                          // verification events
```

## LSM Hooks (Linux only, kanshi-ebpf crate)

| Hook | What It Verifies | When |
|------|-----------------|------|
| `bprm_check_security` | Binary hash at execve | Process execution |
| `file_open` | Script/config hash at open | File access |
| `mmap_file` | Shared library hash at mmap | dlopen/JIT loading |
| `file_mprotect` | Write XOR Execute enforcement | Memory protection changes |
| `inode_permission` | procfs/sysfs write masking | Sensitive file access |

### LSM Hook Decision Flow

```
execve("./my-binary")
  +-> bprm_check_security (LSM hook)
      +-> compute BLAKE3 hash of binary
      +-> lookup in tameshi_revocation_list -> if found: DENY
      +-> lookup in tameshi_allow_map -> if found: ALLOW
      +-> lookup tameshi_policy_map for namespace
      |   +-> Enforce: DENY (unknown binary)
      |   +-> Audit: ALLOW + emit event to ringbuf
      |   +-> AllowUnknown: ALLOW
      +-> emit BlockedExecutionEvent to tameshi_events ringbuf
```

## Test Evidence (130 tests)

| Property | Tests | Module |
|----------|------:|--------|
| MockBpfLoader allow/remove/revoke/set_policy | 12 | `bpf_loader.rs` |
| CrdWatcher gate applied populates allow map | 4 | `crd_watcher.rs` |
| CrdWatcher gate deleted removes from allow map | 4 | `crd_watcher.rs` |
| CrdWatcher hash parsing (blake3: prefix) | 6 | `crd_watcher.rs` |
| HashVerifier allow/revoke/verify lifecycle | 10 | `verifier.rs` |
| PolicyEngine set/get per-namespace | 4 | `policy.rs` |
| PolicyEngine should_enforce/is_audit_only | 4 | `policy.rs` |
| MockEventReader lifecycle (push, poll, drain) | 8 | `event_reader.rs` |
| MockEventReader concurrent access (Arc + Mutex) | 3 | `event_reader.rs` |
| MockEventReader large batch (10,000 events) | 1 | `event_reader.rs` |
| MockEventReader trait object safety | 2 | `event_reader.rs` |
| blocked_event_to_heartbeat_params conversion | 6 | `event_reader.rs` |
| EventMetricsCollector poll_and_record | 8 | `event_metrics.rs` |
| EventMetricsCollector heartbeat chain integrity | 2 | `event_metrics.rs` |
| EventMetricsCollector metric label correctness | 2 | `event_metrics.rs` |
| EventMetricsCollector idempotent poll | 1 | `event_metrics.rs` |
| CirciaReport generation (empty, populated) | 4 | `event_metrics.rs` |
| CirciaReport time window filtering | 3 | `event_metrics.rs` |
| CirciaReport multi-binary aggregation | 2 | `event_metrics.rs` |
| CirciaReport serde roundtrip | 2 | `event_metrics.rs` |
| CirciaReport is_clean/to_json | 3 | `event_metrics.rs` |
| CirciaReport chain integrity in report | 1 | `event_metrics.rs` |
| BpfHash zero/non-zero/equality/hashable | 5 | `kanshi-common` |
| EnforcementPolicy roundtrip (u8) | 2 | `kanshi-common` |
| BlockReason roundtrip (u8) + Display | 4 | `kanshi-common` |
| VerificationEvent size stability | 1 | `kanshi-common` |
| BlockedExecutionEvent zeroed/for_test/path/alignment | 8 | `kanshi-common` |
| BlockedExecutionEvent edge cases (empty, max, truncated, UTF-8, null, invalid) | 6 | `kanshi-common` |
| UserBlockedEvent conversion + serde + all variants | 5 | `kanshi-common` |
| Health server | 2 | `health.rs` |
| Config loading | 4 | `config.rs` |
| Error classification | 2 | `error.rs` |
| Integration: full pipeline end-to-end | 2 | `tests/pillar3_4_integration.rs` |
| Integration: heartbeat chain hash linkage | 1 | `tests/pillar3_4_integration.rs` |
| Integration: multi-round polling | 1 | `tests/pillar3_4_integration.rs` |
| Integration: edge case paths | 1 | `tests/pillar3_4_integration.rs` |
| Integration: clean report | 1 | `tests/pillar3_4_integration.rs` |
| Doc-test: CirciaReport example | 1 | `event_metrics.rs` |
| **Total** | **130** | |

## Integration with tameshi Ecosystem

```
inshou (Nix gate, 366t) --- pre-rebuild hash verification
        |
tameshi (core, 925t) ------ layer signature composition
        |
kensa (compliance, 377t) -- NIST/OSCAL assessment -> compliance hash
        |
sekiban (K8s gate, 315t) -- admission webhook -> SignatureGate CRDs
        |
kanshi (runtime, 130t) ---- CRD watcher -> BPF maps -> LSM enforcement
        |                   EventReader -> metrics + heartbeat -> CIRCIA report
        |
inspec-rspec (94t) -------- deterministic InSpec->RSpec transpiler
```

kanshi is the last mile: after a deployment passes all gates (inshou, sekiban), kanshi ensures the actual running binaries match their attested hashes. It is also the primary source of Pillar 4 evidence through its EventMetricsCollector and CirciaReport.

## Dependencies

| Crate | Purpose |
|-------|---------|
| kanshi-common | Shared BPF map types (`#[repr(C)]`) |
| tameshi | Core integrity library (Blake3Hash, HeartbeatChain, HeartbeatEvent, VerifierIdentity) |
| tokio | Async runtime |
| axum | Health + admin HTTP server |
| kube | Kubernetes client + CRD watcher |
| k8s-openapi | K8s API types |
| prometheus-client | Metrics |
| figment | Layered config |
| const-hex | Hex encode/decode |
| chrono | Timestamps |
| serde + serde_json | Serialization |
