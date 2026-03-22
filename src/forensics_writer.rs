//! Forensics writer for binary verification events.
//!
//! Captures deployment context when binary verifications occur,
//! producing forensics entries that can be queried for blast radius
//! analysis and compliance evidence.

use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Forensics entry capturing binary verification with deployment context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForensicsEntry {
    /// Timestamp of the verification event.
    pub timestamp: DateTime<Utc>,
    /// Path to the binary that was verified.
    pub binary_path: String,
    /// BLAKE3 hash of the binary.
    pub binary_hash: String,
    /// Node where the verification occurred.
    pub node: String,
    /// Kubernetes namespace.
    pub namespace: String,
    /// Pod name.
    pub pod: String,
    /// Verification decision: `"ALLOW"` or `"DENY"`.
    pub decision: String,
    /// Composed Merkle root, if available.
    pub composed_root: Option<String>,
    /// Policy that was in effect.
    pub policy: String,
}

/// Trait for writing forensics entries.
///
/// Implementors are expected to be thread-safe.
pub trait ForensicsWriter: Send + Sync {
    /// Write a forensics entry, returning the total entry count after writing.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be persisted.
    fn write_entry(&self, entry: &ForensicsEntry) -> crate::Result<u64>;

    /// Returns the current number of stored entries.
    fn entry_count(&self) -> usize;
}

/// In-memory forensics writer for testing.
pub struct InMemoryForensicsWriter {
    entries: Mutex<Vec<ForensicsEntry>>,
}

impl InMemoryForensicsWriter {
    /// Create a new empty in-memory forensics writer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Return a snapshot of all stored entries.
    #[must_use]
    pub fn entries(&self) -> Vec<ForensicsEntry> {
        self.entries.lock().unwrap().clone()
    }
}

impl Default for InMemoryForensicsWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsWriter for InMemoryForensicsWriter {
    fn write_entry(&self, entry: &ForensicsEntry) -> crate::Result<u64> {
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry.clone());
        Ok(entries.len() as u64)
    }

    fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::Arc;

    fn make_entry(decision: &str, composed_root: Option<&str>) -> ForensicsEntry {
        ForensicsEntry {
            timestamp: Utc::now(),
            binary_path: "/usr/bin/test".to_string(),
            binary_hash: "blake3:aabbccdd".to_string(),
            node: "node-1".to_string(),
            namespace: "default".to_string(),
            pod: "pod-abc".to_string(),
            decision: decision.to_string(),
            composed_root: composed_root.map(String::from),
            policy: "enforce".to_string(),
        }
    }

    // 1. write_entry stores entry
    #[test]
    fn write_entry_stores_entry() {
        let writer = InMemoryForensicsWriter::new();
        let entry = make_entry("ALLOW", None);
        writer.write_entry(&entry).unwrap();
        let stored = writer.entries();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].binary_path, "/usr/bin/test");
    }

    // 2. entry_count accurate
    #[test]
    fn entry_count_accurate() {
        let writer = InMemoryForensicsWriter::new();
        assert_eq!(writer.entry_count(), 0);
        writer.write_entry(&make_entry("ALLOW", None)).unwrap();
        assert_eq!(writer.entry_count(), 1);
        writer.write_entry(&make_entry("DENY", None)).unwrap();
        assert_eq!(writer.entry_count(), 2);
    }

    // 3. multiple entries stored in order
    #[test]
    fn multiple_entries_stored_in_order() {
        let writer = InMemoryForensicsWriter::new();
        for i in 0..5 {
            let mut entry = make_entry("ALLOW", None);
            entry.binary_path = format!("/bin/app_{i}");
            writer.write_entry(&entry).unwrap();
        }
        let stored = writer.entries();
        assert_eq!(stored.len(), 5);
        for (i, entry) in stored.iter().enumerate() {
            assert_eq!(entry.binary_path, format!("/bin/app_{i}"));
        }
    }

    // 4. ForensicsEntry serde roundtrip
    #[test]
    fn forensics_entry_serde_roundtrip() {
        let entry = make_entry("DENY", Some("merkle:root123"));
        let json = serde_json::to_string(&entry).unwrap();
        let back: ForensicsEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.binary_path, entry.binary_path);
        assert_eq!(back.binary_hash, entry.binary_hash);
        assert_eq!(back.decision, entry.decision);
        assert_eq!(back.composed_root, entry.composed_root);
        assert_eq!(back.node, entry.node);
        assert_eq!(back.namespace, entry.namespace);
        assert_eq!(back.pod, entry.pod);
        assert_eq!(back.policy, entry.policy);
    }

    // 5. InMemoryForensicsWriter thread-safe
    #[test]
    fn in_memory_forensics_writer_thread_safe() {
        let writer = Arc::new(InMemoryForensicsWriter::new());
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let w = Arc::clone(&writer);
                std::thread::spawn(move || {
                    let mut entry = make_entry("ALLOW", None);
                    entry.binary_path = format!("/bin/thread_{i}");
                    w.write_entry(&entry).unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(writer.entry_count(), 10);
    }

    // 6. ForensicsWriter trait is dyn-safe
    #[test]
    fn forensics_writer_trait_is_dyn_safe() {
        fn accept_writer(_: &dyn ForensicsWriter) {}
        let writer = InMemoryForensicsWriter::new();
        accept_writer(&writer);
    }

    // 7. ForensicsWriter trait as Box<dyn>
    #[test]
    fn forensics_writer_trait_boxed() {
        let writer: Box<dyn ForensicsWriter> = Box::new(InMemoryForensicsWriter::new());
        assert_eq!(writer.entry_count(), 0);
        writer.write_entry(&make_entry("ALLOW", None)).unwrap();
        assert_eq!(writer.entry_count(), 1);
    }

    // 8. Entry with ALLOW decision
    #[test]
    fn entry_with_allow_decision() {
        let writer = InMemoryForensicsWriter::new();
        let entry = make_entry("ALLOW", None);
        writer.write_entry(&entry).unwrap();
        let stored = writer.entries();
        assert_eq!(stored[0].decision, "ALLOW");
    }

    // 9. Entry with DENY decision
    #[test]
    fn entry_with_deny_decision() {
        let writer = InMemoryForensicsWriter::new();
        let entry = make_entry("DENY", None);
        writer.write_entry(&entry).unwrap();
        let stored = writer.entries();
        assert_eq!(stored[0].decision, "DENY");
    }

    // 10. Entry with composed_root present
    #[test]
    fn entry_with_composed_root_present() {
        let entry = make_entry("ALLOW", Some("merkle:root_abc"));
        assert_eq!(entry.composed_root, Some("merkle:root_abc".to_string()));
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("merkle:root_abc"));
    }

    // 11. Entry with composed_root absent
    #[test]
    fn entry_with_composed_root_absent() {
        let entry = make_entry("ALLOW", None);
        assert!(entry.composed_root.is_none());
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"composed_root\":null"));
    }

    // 12. write_entry returns correct count
    #[test]
    fn write_entry_returns_correct_count() {
        let writer = InMemoryForensicsWriter::new();
        let count1 = writer.write_entry(&make_entry("ALLOW", None)).unwrap();
        assert_eq!(count1, 1);
        let count2 = writer.write_entry(&make_entry("DENY", None)).unwrap();
        assert_eq!(count2, 2);
        let count3 = writer.write_entry(&make_entry("ALLOW", None)).unwrap();
        assert_eq!(count3, 3);
    }

    // 13. Default impl works
    #[test]
    fn default_impl_works() {
        let writer = InMemoryForensicsWriter::default();
        assert_eq!(writer.entry_count(), 0);
    }

    // 14. Entry fields are preserved exactly
    #[test]
    fn entry_fields_preserved_exactly() {
        let writer = InMemoryForensicsWriter::new();
        let entry = ForensicsEntry {
            timestamp: Utc::now(),
            binary_path: "/opt/special/binary".to_string(),
            binary_hash: "blake3:deadbeef".to_string(),
            node: "worker-42".to_string(),
            namespace: "production".to_string(),
            pod: "my-pod-xyz".to_string(),
            decision: "DENY".to_string(),
            composed_root: Some("root:abc123".to_string()),
            policy: "audit".to_string(),
        };
        writer.write_entry(&entry).unwrap();
        let stored = writer.entries();
        assert_eq!(stored[0].binary_path, "/opt/special/binary");
        assert_eq!(stored[0].binary_hash, "blake3:deadbeef");
        assert_eq!(stored[0].node, "worker-42");
        assert_eq!(stored[0].namespace, "production");
        assert_eq!(stored[0].pod, "my-pod-xyz");
        assert_eq!(stored[0].policy, "audit");
    }

    // 15. Multiple entries with different decisions
    #[test]
    fn multiple_entries_mixed_decisions() {
        let writer = InMemoryForensicsWriter::new();
        writer.write_entry(&make_entry("ALLOW", None)).unwrap();
        writer.write_entry(&make_entry("DENY", None)).unwrap();
        writer.write_entry(&make_entry("ALLOW", None)).unwrap();
        writer.write_entry(&make_entry("DENY", None)).unwrap();
        let stored = writer.entries();
        assert_eq!(stored[0].decision, "ALLOW");
        assert_eq!(stored[1].decision, "DENY");
        assert_eq!(stored[2].decision, "ALLOW");
        assert_eq!(stored[3].decision, "DENY");
    }

    // 16. ForensicsEntry clone is independent
    #[test]
    fn forensics_entry_clone_is_independent() {
        let entry = make_entry("ALLOW", Some("root:xyz"));
        let cloned = entry.clone();
        assert_eq!(entry.binary_path, cloned.binary_path);
        assert_eq!(entry.composed_root, cloned.composed_root);
    }

    // 17. ForensicsEntry debug format
    #[test]
    fn forensics_entry_debug_format() {
        let entry = make_entry("ALLOW", None);
        let debug = format!("{entry:?}");
        assert!(debug.contains("ForensicsEntry"));
        assert!(debug.contains("ALLOW"));
    }

    // 18. Large batch write
    #[test]
    fn large_batch_write() {
        let writer = InMemoryForensicsWriter::new();
        for i in 0..1000 {
            let mut entry = make_entry("ALLOW", None);
            entry.binary_path = format!("/bin/batch_{i}");
            writer.write_entry(&entry).unwrap();
        }
        assert_eq!(writer.entry_count(), 1000);
        let stored = writer.entries();
        assert_eq!(stored.len(), 1000);
    }

    // 19. Empty entries snapshot
    #[test]
    fn empty_entries_snapshot() {
        let writer = InMemoryForensicsWriter::new();
        let entries = writer.entries();
        assert!(entries.is_empty());
    }

    // 20. Integration: EventMetricsCollector -> ForensicsWriter
    //     Verifies that events polled by the collector can be converted
    //     to ForensicsEntry records and written to the forensics writer.
    #[test]
    fn integration_event_metrics_to_forensics_writer() {
        use crate::event_metrics::EventMetricsCollector;
        use crate::event_reader::MockEventReader;
        use kanshi_common::BlockReason;
        use std::sync::Arc;
        use tameshi::heartbeat::{HeartbeatChain, VerifierIdentity};

        let reader = Arc::new(MockEventReader::new());
        reader.push_event(kanshi_common::BlockedExecutionEvent::for_test(
            "/usr/bin/evil",
            BlockReason::Revoked,
        ));
        reader.push_event(kanshi_common::BlockedExecutionEvent::for_test(
            "/usr/bin/suspect",
            BlockReason::HashMismatch,
        ));

        let chain = Arc::new(HeartbeatChain::new());
        let verifier = VerifierIdentity::new("kanshi", "test-node", "0.1.0");
        let collector = EventMetricsCollector::new(reader, Arc::clone(&chain), verifier);

        // Poll events via the collector.
        let count = collector.poll_and_record().unwrap();
        assert_eq!(count, 2);

        // Now convert heartbeat entries to forensics entries and write them.
        let forensics_writer = InMemoryForensicsWriter::new();
        let heartbeat_entries = chain.entries();
        for he in &heartbeat_entries {
            let forensics_entry = ForensicsEntry {
                timestamp: he.timestamp,
                binary_path: he.resource.clone(),
                binary_hash: format!("{:?}", he.signature_checked),
                node: "test-node".to_string(),
                namespace: "default".to_string(),
                pod: "test-pod".to_string(),
                decision: match he.result {
                    tameshi::heartbeat::VerificationOutcome::Denied => "DENY".to_string(),
                    _ => "ALLOW".to_string(),
                },
                composed_root: None,
                policy: "enforce".to_string(),
            };
            forensics_writer.write_entry(&forensics_entry).unwrap();
        }

        assert_eq!(forensics_writer.entry_count(), 2);
        let entries = forensics_writer.entries();
        assert_eq!(entries[0].binary_path, "/usr/bin/evil");
        assert_eq!(entries[0].decision, "DENY");
        assert_eq!(entries[1].binary_path, "/usr/bin/suspect");
        assert_eq!(entries[1].decision, "DENY");
    }
}
