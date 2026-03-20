//! Kanshi (監視) - eBPF runtime integrity sentinel.
//!
//! Kanshi is a Linux daemon that uses eBPF LSM hooks to verify binary
//! integrity at execution time. It watches tameshi SignatureGate CRDs
//! via kube-rs and populates BPF hash maps that the kernel-space
//! eBPF programs use for allow/deny decisions.
//!
//! # Architecture
//!
//! ```text
//! Userspace (kanshi daemon)          Kernel (eBPF programs)
//! ┌───────────────────────┐          ┌─────────────────────────┐
//! │ CRD Watcher           │──maps──▶│ bprm_check_security     │
//! │ Hash Verifier         │          │ file_open               │
//! │ Policy Engine         │          │ mmap_file               │
//! │ Heartbeat Emitter     │◀─events─│ perf_event_output       │
//! │ Health Server         │          └─────────────────────────┘
//! │ Metrics               │
//! └───────────────────────┘
//! ```

pub mod bpf_loader;
pub mod config;
pub mod crd_watcher;
pub mod error;
pub mod health;
pub mod metrics;
pub mod policy;
pub mod verifier;

pub use error::{Error, Result};
