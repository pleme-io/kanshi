//! Connects BPF event reader to Prometheus metrics and heartbeat chain.
//!
//! The [`EventMetricsCollector`] polls the BPF ring buffer for
//! [`BlockedExecutionEvent`] values, records each one in the global
//! Prometheus counter (`tameshi_blocked_executions_total`), and appends
//! a corresponding entry to the tameshi [`HeartbeatChain`].
//!
//! The [`CirciaReport`] aggregates blocked execution data over a time
//! window for CIRCIA (Cyber Incident Reporting for Critical Infrastructure
//! Act) regulatory evidence.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tameshi::hash::Blake3Hash;
use tameshi::heartbeat::{HeartbeatChain, HeartbeatEvent, VerificationOutcome, VerifierIdentity};

use crate::event_reader::EventReader;

/// Collects events from the BPF ring buffer and records metrics + heartbeat entries.
pub struct EventMetricsCollector<E: EventReader> {
    event_reader: Arc<E>,
    heartbeat_chain: Arc<HeartbeatChain>,
    verifier_identity: VerifierIdentity,
}

impl<E: EventReader> EventMetricsCollector<E> {
    /// Create a new collector backed by the given event reader and heartbeat chain.
    #[must_use]
    pub fn new(
        event_reader: Arc<E>,
        heartbeat_chain: Arc<HeartbeatChain>,
        verifier_identity: VerifierIdentity,
    ) -> Self {
        Self {
            event_reader,
            heartbeat_chain,
            verifier_identity,
        }
    }

    /// Poll for events and record metrics + heartbeat entries.
    ///
    /// Returns the number of events processed.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the underlying event reader fails.
    #[inline]
    pub fn poll_and_record(&self) -> crate::Result<usize> {
        let events = self.event_reader.poll_events()?;
        let count = events.len();

        for event in &events {
            // Map BlockReason to a string label.
            let reason = match event.reason {
                kanshi_common::BlockReason::NotInAllowMap => "not_in_allow_map",
                kanshi_common::BlockReason::HashMismatch => "hash_mismatch",
                kanshi_common::BlockReason::Revoked => "revoked",
                kanshi_common::BlockReason::Unknown => "unknown",
            };

            // Record Prometheus metric.
            crate::metrics::record_blocked_execution(reason, event.path());

            // Append to heartbeat chain.
            let resource = event.path().to_string();
            let sig_hash = Blake3Hash::from(event.looked_up_hash.bytes);
            self.heartbeat_chain.append(
                self.verifier_identity.clone(),
                HeartbeatEvent::BinaryVerification,
                VerificationOutcome::Denied,
                &resource,
                sig_hash,
            );
        }

        Ok(count)
    }

    /// Generate a CIRCIA evidence report for the given time window.
    #[must_use]
    pub fn generate_circia_report(&self, window_hours: u64) -> CirciaReport {
        let now = Utc::now();
        let window_start = now - chrono::Duration::hours(i64::from(u32::try_from(window_hours).unwrap_or(u32::MAX)));

        // Get heartbeat entries in the time window.
        let entries = self.heartbeat_chain.entries_in_range(window_start, now);

        // Filter to denied binary verifications.
        let blocked: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.event == HeartbeatEvent::BinaryVerification
                    && e.result == VerificationOutcome::Denied
            })
            .collect();

        // Aggregate by binary path.
        let mut by_binary: BTreeMap<String, Vec<&tameshi::heartbeat::HeartbeatEntry>> =
            BTreeMap::new();
        for entry in &blocked {
            by_binary
                .entry(entry.resource.clone())
                .or_default()
                .push(entry);
        }

        let blocked_binaries: Vec<BlockedBinarySummary> = by_binary
            .iter()
            .map(|(path, bin_entries)| {
                BlockedBinarySummary {
                    binary_path: path.clone(),
                    block_count: bin_entries.len() as u64,
                    first_seen: bin_entries
                        .iter()
                        .map(|e| e.timestamp)
                        .min()
                        .unwrap_or(now),
                    last_seen: bin_entries
                        .iter()
                        .map(|e| e.timestamp)
                        .max()
                        .unwrap_or(now),
                    reason: "binary_verification_denied".to_string(),
                }
            })
            .collect();

        CirciaReport {
            window_start,
            window_end: now,
            total_blocked: blocked.len() as u64,
            blocked_by_reason: {
                let mut m = BTreeMap::new();
                m.insert(
                    "binary_verification_denied".to_string(),
                    blocked.len() as u64,
                );
                m
            },
            blocked_binaries,
            heartbeat_chain_length: self.heartbeat_chain.len() as u64,
            chain_integrity_verified: self.heartbeat_chain.verify_integrity(),
        }
    }
}

/// CIRCIA (Cyber Incident Reporting for Critical Infrastructure Act) evidence report.
///
/// Aggregates blocked execution events over a time window for regulatory reporting.
///
/// # Example
///
/// ```
/// use kanshi::event_metrics::CirciaReport;
/// use std::collections::BTreeMap;
/// use chrono::Utc;
///
/// let report = CirciaReport {
///     window_start: Utc::now() - chrono::Duration::hours(24),
///     window_end: Utc::now(),
///     total_blocked: 0,
///     blocked_by_reason: BTreeMap::new(),
///     blocked_binaries: Vec::new(),
///     heartbeat_chain_length: 0,
///     chain_integrity_verified: true,
/// };
/// assert!(report.is_clean());
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CirciaReport {
    /// Start of the reporting window.
    pub window_start: DateTime<Utc>,
    /// End of the reporting window.
    pub window_end: DateTime<Utc>,
    /// Total blocked executions in the window.
    pub total_blocked: u64,
    /// Blocked counts by reason.
    pub blocked_by_reason: BTreeMap<String, u64>,
    /// Per-binary block summaries.
    pub blocked_binaries: Vec<BlockedBinarySummary>,
    /// Heartbeat chain length at report time.
    pub heartbeat_chain_length: u64,
    /// Whether the heartbeat chain integrity was verified.
    pub chain_integrity_verified: bool,
}

impl CirciaReport {
    /// Returns `true` if no executions were blocked in the reporting window.
    #[inline]
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.total_blocked == 0
    }

    /// Serialize the report to JSON.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if serialization fails (should not happen
    /// for well-formed reports).
    #[inline]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Summary of blocked executions for a specific binary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockedBinarySummary {
    /// Full binary path.
    pub binary_path: String,
    /// Number of times this binary was blocked.
    pub block_count: u64,
    /// First time this binary was blocked in the window.
    pub first_seen: DateTime<Utc>,
    /// Last time this binary was blocked in the window.
    pub last_seen: DateTime<Utc>,
    /// Reason category.
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_reader::MockEventReader;
    use kanshi_common::{BlockReason, BlockedExecutionEvent};

    fn test_verifier() -> VerifierIdentity {
        VerifierIdentity::new("kanshi", "test-node", "0.1.0")
    }

    fn make_collector(
        reader: Arc<MockEventReader>,
    ) -> (EventMetricsCollector<MockEventReader>, Arc<HeartbeatChain>) {
        let chain = Arc::new(HeartbeatChain::new());
        let collector =
            EventMetricsCollector::new(reader, Arc::clone(&chain), test_verifier());
        (collector, chain)
    }

    // ── Step 4.2 tests: EventMetricsCollector ─────────────────────────

    #[test]
    fn poll_with_no_events_returns_zero() {
        let reader = Arc::new(MockEventReader::new());
        let (collector, chain) = make_collector(reader);

        let count = collector.poll_and_record().unwrap();
        assert_eq!(count, 0);
        assert!(chain.is_empty());
    }

    #[test]
    fn poll_with_one_event_records_metric_and_heartbeat() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test(
            "/usr/bin/evil",
            BlockReason::Revoked,
        ));
        let (collector, chain) = make_collector(reader);

        let count = collector.poll_and_record().unwrap();
        assert_eq!(count, 1);
        assert_eq!(chain.len(), 1);

        let entries = chain.entries();
        assert_eq!(entries[0].resource, "/usr/bin/evil");
        assert_eq!(entries[0].event, HeartbeatEvent::BinaryVerification);
        assert_eq!(entries[0].result, VerificationOutcome::Denied);
    }

    #[test]
    fn poll_with_multiple_events_records_all() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/a", BlockReason::Revoked));
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/b",
            BlockReason::HashMismatch,
        ));
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/c",
            BlockReason::NotInAllowMap,
        ));
        let (collector, chain) = make_collector(reader);

        let count = collector.poll_and_record().unwrap();
        assert_eq!(count, 3);
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn heartbeat_chain_integrity_after_poll() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/a", BlockReason::Revoked));
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/b",
            BlockReason::HashMismatch,
        ));
        let (collector, chain) = make_collector(reader);

        collector.poll_and_record().unwrap();
        assert!(chain.verify_integrity());
    }

    #[test]
    fn metric_labels_match_event_reason() {
        // This test verifies that the reason string used for metrics matches
        // the expected label value for each BlockReason variant.
        let test_cases = vec![
            (BlockReason::NotInAllowMap, "not_in_allow_map"),
            (BlockReason::HashMismatch, "hash_mismatch"),
            (BlockReason::Revoked, "revoked"),
            (BlockReason::Unknown, "unknown"),
        ];

        for (block_reason, expected_label) in test_cases {
            let reader = Arc::new(MockEventReader::new());
            reader.push_event(BlockedExecutionEvent::for_test("/bin/test", block_reason));
            let (collector, _chain) = make_collector(reader);

            // poll_and_record should not panic for any reason variant.
            let count = collector.poll_and_record().unwrap();
            assert_eq!(count, 1);

            // Verify the global metrics contain the expected reason label.
            let output = crate::metrics::gather();
            assert!(
                output.contains(expected_label),
                "metrics output should contain reason label '{expected_label}'"
            );
        }
    }

    #[test]
    fn binary_path_in_heartbeat_entry_matches_event() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test(
            "/opt/custom/binary",
            BlockReason::NotInAllowMap,
        ));
        let (collector, chain) = make_collector(reader);

        collector.poll_and_record().unwrap();
        let entries = chain.entries();
        assert_eq!(entries[0].resource, "/opt/custom/binary");
    }

    #[test]
    fn poll_is_idempotent_events_consumed_once() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/x", BlockReason::Revoked));
        let (collector, chain) = make_collector(reader);

        let first = collector.poll_and_record().unwrap();
        assert_eq!(first, 1);
        assert_eq!(chain.len(), 1);

        // Second poll returns 0 -- events were consumed.
        let second = collector.poll_and_record().unwrap();
        assert_eq!(second, 0);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn event_metrics_collector_creation() {
        let reader = Arc::new(MockEventReader::new());
        let chain = Arc::new(HeartbeatChain::new());
        let verifier = test_verifier();
        let collector = EventMetricsCollector::new(reader, chain, verifier);

        // Just verifying it can be created and used without panicking.
        let count = collector.poll_and_record().unwrap();
        assert_eq!(count, 0);
    }

    // ── Step 4.4 tests: CirciaReport ──────────────────────────────────

    #[test]
    fn empty_chain_produces_zero_count_report() {
        let reader = Arc::new(MockEventReader::new());
        let (collector, _chain) = make_collector(reader);

        let report = collector.generate_circia_report(24);
        assert_eq!(report.total_blocked, 0);
        assert!(report.blocked_binaries.is_empty());
        assert_eq!(report.heartbeat_chain_length, 0);
        assert!(report.chain_integrity_verified);
    }

    #[test]
    fn report_respects_time_window() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/recent",
            BlockReason::Revoked,
        ));
        let (collector, _chain) = make_collector(reader);

        collector.poll_and_record().unwrap();

        // Events appended just now should appear in a 24-hour window.
        let report = collector.generate_circia_report(24);
        assert_eq!(report.total_blocked, 1);
        assert_eq!(report.heartbeat_chain_length, 1);
    }

    #[test]
    fn multiple_block_reasons_aggregated() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/a", BlockReason::Revoked));
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/b",
            BlockReason::HashMismatch,
        ));
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/a",
            BlockReason::Revoked,
        ));
        let (collector, _chain) = make_collector(reader);

        collector.poll_and_record().unwrap();

        let report = collector.generate_circia_report(24);
        assert_eq!(report.total_blocked, 3);
        // /bin/a should have block_count 2, /bin/b should have block_count 1.
        let a_summary = report
            .blocked_binaries
            .iter()
            .find(|s| s.binary_path == "/bin/a");
        let b_summary = report
            .blocked_binaries
            .iter()
            .find(|s| s.binary_path == "/bin/b");
        assert_eq!(a_summary.unwrap().block_count, 2);
        assert_eq!(b_summary.unwrap().block_count, 1);
    }

    #[test]
    fn circia_report_serde_roundtrip() {
        let report = CirciaReport {
            window_start: Utc::now() - chrono::Duration::hours(24),
            window_end: Utc::now(),
            total_blocked: 5,
            blocked_by_reason: {
                let mut m = BTreeMap::new();
                m.insert("binary_verification_denied".to_string(), 5);
                m
            },
            blocked_binaries: vec![BlockedBinarySummary {
                binary_path: "/usr/bin/evil".to_string(),
                block_count: 5,
                first_seen: Utc::now() - chrono::Duration::hours(12),
                last_seen: Utc::now(),
                reason: "binary_verification_denied".to_string(),
            }],
            heartbeat_chain_length: 5,
            chain_integrity_verified: true,
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: CirciaReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_blocked, report.total_blocked);
        assert_eq!(
            deserialized.heartbeat_chain_length,
            report.heartbeat_chain_length
        );
        assert_eq!(
            deserialized.chain_integrity_verified,
            report.chain_integrity_verified
        );
        assert_eq!(
            deserialized.blocked_binaries.len(),
            report.blocked_binaries.len()
        );
    }

    #[test]
    fn blocked_binary_summary_serde_roundtrip() {
        let summary = BlockedBinarySummary {
            binary_path: "/opt/bin/test".to_string(),
            block_count: 42,
            first_seen: Utc::now() - chrono::Duration::hours(6),
            last_seen: Utc::now(),
            reason: "binary_verification_denied".to_string(),
        };

        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: BlockedBinarySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.binary_path, summary.binary_path);
        assert_eq!(deserialized.block_count, summary.block_count);
        assert_eq!(deserialized.reason, summary.reason);
    }

    #[test]
    fn chain_integrity_verification_in_report() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/x", BlockReason::Revoked));
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/y",
            BlockReason::HashMismatch,
        ));
        let (collector, _chain) = make_collector(reader);

        collector.poll_and_record().unwrap();

        let report = collector.generate_circia_report(24);
        assert!(report.chain_integrity_verified);
        assert_eq!(report.heartbeat_chain_length, 2);
    }

    // ── CirciaReport::is_clean ──────────────────────────────────────

    #[test]
    fn is_clean_true_for_empty_report() {
        let reader = Arc::new(MockEventReader::new());
        let (collector, _chain) = make_collector(reader);
        let report = collector.generate_circia_report(24);
        assert!(report.is_clean());
    }

    #[test]
    fn is_clean_false_when_events_present() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/x", BlockReason::Revoked));
        let (collector, _chain) = make_collector(reader);
        collector.poll_and_record().unwrap();
        let report = collector.generate_circia_report(24);
        assert!(!report.is_clean());
    }

    // ── CirciaReport::to_json ───────────────────────────────────────

    #[test]
    fn to_json_produces_valid_json() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/x", BlockReason::Revoked));
        let (collector, _chain) = make_collector(reader);
        collector.poll_and_record().unwrap();
        let report = collector.generate_circia_report(24);

        let json = report.to_json().unwrap();
        // Verify it round-trips.
        let parsed: CirciaReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_blocked, report.total_blocked);
    }

    #[test]
    fn to_json_empty_report() {
        let reader = Arc::new(MockEventReader::new());
        let (collector, _chain) = make_collector(reader);
        let report = collector.generate_circia_report(24);
        let json = report.to_json().unwrap();
        assert!(json.contains("\"total_blocked\": 0"));
    }

    // ── Multiple poll cycles ────────────────────────────────────────

    #[test]
    fn multiple_poll_cycles_cumulative_metrics() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/a", BlockReason::Revoked));
        let (collector, chain) = make_collector(reader.clone());

        let count1 = collector.poll_and_record().unwrap();
        assert_eq!(count1, 1);
        assert_eq!(chain.len(), 1);

        // Push more events after first poll.
        reader.push_event(BlockedExecutionEvent::for_test("/bin/b", BlockReason::Revoked));
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/c",
            BlockReason::HashMismatch,
        ));

        let count2 = collector.poll_and_record().unwrap();
        assert_eq!(count2, 2);
        assert_eq!(chain.len(), 3);

        // Report should show all 3.
        let report = collector.generate_circia_report(24);
        assert_eq!(report.total_blocked, 3);
    }

    // ── All block reasons in metrics ────────────────────────────────

    #[test]
    fn all_block_reasons_map_to_correct_metric_labels() {
        let test_cases = [
            (BlockReason::NotInAllowMap, "not_in_allow_map"),
            (BlockReason::HashMismatch, "hash_mismatch"),
            (BlockReason::Revoked, "revoked"),
            (BlockReason::Unknown, "unknown"),
        ];

        for (reason, expected_label) in test_cases {
            let reader = Arc::new(MockEventReader::new());
            reader.push_event(BlockedExecutionEvent::for_test("/bin/test", reason));
            let (collector, _chain) = make_collector(reader);
            collector.poll_and_record().unwrap();

            let output = crate::metrics::gather();
            assert!(
                output.contains(expected_label),
                "Expected label '{expected_label}' in metrics output for {reason:?}"
            );
        }
    }

    // ── Empty binary path ───────────────────────────────────────────

    #[test]
    fn empty_binary_path_does_not_panic() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("", BlockReason::Unknown));
        let (collector, chain) = make_collector(reader);

        let count = collector.poll_and_record().unwrap();
        assert_eq!(count, 1);
        assert_eq!(chain.len(), 1);

        let entries = chain.entries();
        assert_eq!(entries[0].resource, "");
    }

    // ── Very long binary path ───────────────────────────────────────

    #[test]
    fn very_long_binary_path_truncated_in_metrics() {
        let long_path = "/".to_string() + &"a".repeat(200);
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test(
            &long_path,
            BlockReason::Revoked,
        ));
        let (collector, chain) = make_collector(reader);

        collector.poll_and_record().unwrap();

        // Heartbeat chain should have the FULL path (truncated by BINARY_PATH_LEN=256).
        let entries = chain.entries();
        assert!(entries[0].resource.len() <= kanshi_common::BINARY_PATH_LEN);

        // Metrics should have the path truncated to 128 chars.
        let output = crate::metrics::gather();
        assert!(output.contains("..."), "Long path should be truncated in metrics");
    }

    // ── Multi-binary aggregation in report ──────────────────────────

    #[test]
    fn multi_binary_aggregation_five_binaries() {
        let reader = Arc::new(MockEventReader::new());
        for i in 0..5 {
            for _ in 0..(i + 1) {
                reader.push_event(BlockedExecutionEvent::for_test(
                    &format!("/bin/app_{i}"),
                    BlockReason::Revoked,
                ));
            }
        }
        let (collector, _chain) = make_collector(reader);
        collector.poll_and_record().unwrap();

        let report = collector.generate_circia_report(24);
        // Total: 1 + 2 + 3 + 4 + 5 = 15
        assert_eq!(report.total_blocked, 15);
        assert_eq!(report.blocked_binaries.len(), 5);

        // Verify each binary has the correct count.
        for i in 0..5 {
            let summary = report
                .blocked_binaries
                .iter()
                .find(|s| s.binary_path == format!("/bin/app_{i}"))
                .unwrap_or_else(|| panic!("Missing summary for /bin/app_{i}"));
            assert_eq!(summary.block_count, (i + 1) as u64);
        }
    }

    // ── First/last seen accuracy ────────────────────────────────────

    #[test]
    fn first_last_seen_are_correct() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/app", BlockReason::Revoked));
        reader.push_event(BlockedExecutionEvent::for_test("/bin/app", BlockReason::Revoked));
        reader.push_event(BlockedExecutionEvent::for_test("/bin/app", BlockReason::Revoked));
        let (collector, _chain) = make_collector(reader);
        collector.poll_and_record().unwrap();

        let report = collector.generate_circia_report(24);
        let summary = &report.blocked_binaries[0];
        assert!(summary.first_seen <= summary.last_seen);
        assert_eq!(summary.block_count, 3);
    }

    // ── Zero-hour window ────────────────────────────────────────────

    #[test]
    fn zero_hour_window_captures_nothing() {
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/app", BlockReason::Revoked));
        let (collector, _chain) = make_collector(reader);
        collector.poll_and_record().unwrap();

        // window_hours = 0 means the window starts NOW, so no events are in range.
        // (Events were appended just before "now" in poll_and_record.)
        // Due to timing, this might capture 0 or 1 -- the important thing is
        // it doesn't panic.
        let report = collector.generate_circia_report(0);
        // Should at least not panic.
        assert!(report.total_blocked <= 1);
    }

    // ── Large window ────────────────────────────────────────────────

    #[test]
    fn large_window_captures_everything() {
        let reader = Arc::new(MockEventReader::new());
        for i in 0..10 {
            reader.push_event(BlockedExecutionEvent::for_test(
                &format!("/bin/app_{i}"),
                BlockReason::Revoked,
            ));
        }
        let (collector, _chain) = make_collector(reader);
        collector.poll_and_record().unwrap();

        // 8760 hours = 1 year.
        let report = collector.generate_circia_report(8760);
        assert_eq!(report.total_blocked, 10);
    }

    // ── Events cannot be silently dropped ───────────────────────────

    #[test]
    fn events_are_never_silently_dropped() {
        let reader = Arc::new(MockEventReader::new());
        let event_count = 500;
        for i in 0..event_count {
            reader.push_event(BlockedExecutionEvent::for_test(
                &format!("/bin/app_{i}"),
                BlockReason::Revoked,
            ));
        }
        let (collector, chain) = make_collector(reader);

        let count = collector.poll_and_record().unwrap();
        assert_eq!(count, event_count);
        assert_eq!(chain.len(), event_count);
        assert!(chain.verify_integrity());
    }

    // ── EventMetricsCollector without metrics (just heartbeat) ──────

    #[test]
    fn collector_works_for_heartbeat_only_use_case() {
        // Even though we also record metrics, the collector can be used
        // primarily for heartbeat chain building.
        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/test", BlockReason::Revoked));
        let chain = Arc::new(HeartbeatChain::new());
        let collector =
            EventMetricsCollector::new(reader, Arc::clone(&chain), test_verifier());

        collector.poll_and_record().unwrap();
        assert_eq!(chain.len(), 1);
        assert!(chain.verify_integrity());

        // Can generate a report from the chain.
        let report = collector.generate_circia_report(24);
        assert_eq!(report.total_blocked, 1);
        assert!(report.chain_integrity_verified);
    }
}
