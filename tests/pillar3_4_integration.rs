//! Integration test: Full Pillar 3-4 pipeline.
//!
//! Exercises the complete flow from BPF event creation through metrics
//! recording and heartbeat chain building to CIRCIA report generation.

use std::sync::Arc;

use kanshi::event_metrics::{CirciaReport, EventMetricsCollector};
use kanshi::event_reader::MockEventReader;
use kanshi_common::{BlockReason, BlockedExecutionEvent, BpfHash, BINARY_PATH_LEN};
use tameshi::heartbeat::{HeartbeatChain, HeartbeatEvent, VerificationOutcome, VerifierIdentity};

fn test_verifier() -> VerifierIdentity {
    VerifierIdentity::new("kanshi", "integration-test-node", "0.1.0")
}

/// Full pipeline: create events -> poll_and_record -> verify metrics + heartbeat -> CIRCIA report.
#[test]
fn full_pipeline_end_to_end() {
    // 1. Create MockEventReader with various events.
    let reader = Arc::new(MockEventReader::new());

    // 2. Push events with different reasons and binaries.
    let events_spec: &[(&str, BlockReason)] = &[
        ("/usr/bin/malware", BlockReason::NotInAllowMap),
        ("/usr/bin/malware", BlockReason::NotInAllowMap),
        ("/opt/evil/payload", BlockReason::HashMismatch),
        ("/tmp/exploit", BlockReason::Revoked),
        ("/tmp/exploit", BlockReason::Revoked),
        ("/tmp/exploit", BlockReason::Revoked),
        ("/usr/local/bin/unknown", BlockReason::Unknown),
    ];

    for &(path, reason) in events_spec {
        let mut event = BlockedExecutionEvent::for_test(path, reason);
        event.pid = 1000;
        event.inode = 42;
        event.cgroup_id = 100;
        event.looked_up_hash = BpfHash::new([0xab; 32]);
        reader.push_event(event);
    }

    // 3. Create HeartbeatChain + VerifierIdentity.
    let chain = Arc::new(HeartbeatChain::new());
    let verifier = test_verifier();

    // 4. Create EventMetricsCollector.
    let collector = EventMetricsCollector::new(
        Arc::clone(&reader),
        Arc::clone(&chain),
        verifier,
    );

    // 5. Call poll_and_record.
    let count = collector.poll_and_record().unwrap();
    assert_eq!(count, 7, "All 7 events should be processed");

    // 6. Verify metrics recorded correctly.
    let metrics_output = kanshi::metrics::gather();
    assert!(
        metrics_output.contains("tameshi_blocked_executions_total"),
        "Blocked executions counter must exist"
    );
    assert!(metrics_output.contains("not_in_allow_map"));
    assert!(metrics_output.contains("hash_mismatch"));
    assert!(metrics_output.contains("revoked"));
    assert!(metrics_output.contains("unknown"));

    // 7. Verify heartbeat chain has correct entries.
    assert_eq!(chain.len(), 7, "Chain should have 7 entries");
    assert!(chain.verify_integrity(), "Chain integrity must pass");

    let entries = chain.entries();
    for entry in &entries {
        assert_eq!(entry.event, HeartbeatEvent::BinaryVerification);
        assert_eq!(entry.result, VerificationOutcome::Denied);
        assert_eq!(entry.verifier.component, "kanshi");
        assert_eq!(entry.verifier.instance, "integration-test-node");
    }

    // Verify resources match the binary paths.
    assert_eq!(entries[0].resource, "/usr/bin/malware");
    assert_eq!(entries[1].resource, "/usr/bin/malware");
    assert_eq!(entries[2].resource, "/opt/evil/payload");
    assert_eq!(entries[3].resource, "/tmp/exploit");
    assert_eq!(entries[6].resource, "/usr/local/bin/unknown");

    // 8. Generate CIRCIA report.
    let report = collector.generate_circia_report(24);

    // 9. Verify report aggregation.
    assert_eq!(report.total_blocked, 7);
    assert!(!report.is_clean());
    assert_eq!(report.blocked_binaries.len(), 4); // 4 unique binaries

    let malware_summary = report
        .blocked_binaries
        .iter()
        .find(|s| s.binary_path == "/usr/bin/malware")
        .expect("/usr/bin/malware should be in report");
    assert_eq!(malware_summary.block_count, 2);

    let exploit_summary = report
        .blocked_binaries
        .iter()
        .find(|s| s.binary_path == "/tmp/exploit")
        .expect("/tmp/exploit should be in report");
    assert_eq!(exploit_summary.block_count, 3);

    let payload_summary = report
        .blocked_binaries
        .iter()
        .find(|s| s.binary_path == "/opt/evil/payload")
        .expect("/opt/evil/payload should be in report");
    assert_eq!(payload_summary.block_count, 1);

    let unknown_summary = report
        .blocked_binaries
        .iter()
        .find(|s| s.binary_path == "/usr/local/bin/unknown")
        .expect("/usr/local/bin/unknown should be in report");
    assert_eq!(unknown_summary.block_count, 1);

    // 10. Verify chain integrity in report.
    assert!(report.chain_integrity_verified);
    assert_eq!(report.heartbeat_chain_length, 7);

    // Verify report serialization.
    let json = report.to_json().unwrap();
    let parsed: CirciaReport = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.total_blocked, 7);
    assert!(parsed.chain_integrity_verified);
}

/// Verify that a second poll round appends correctly to the chain.
#[test]
fn multi_round_polling() {
    let reader = Arc::new(MockEventReader::new());
    let chain = Arc::new(HeartbeatChain::new());
    let collector = EventMetricsCollector::new(
        Arc::clone(&reader),
        Arc::clone(&chain),
        test_verifier(),
    );

    // Round 1: 3 events.
    for i in 0..3 {
        reader.push_event(BlockedExecutionEvent::for_test(
            &format!("/bin/round1_{i}"),
            BlockReason::Revoked,
        ));
    }
    let count1 = collector.poll_and_record().unwrap();
    assert_eq!(count1, 3);
    assert_eq!(chain.len(), 3);
    assert!(chain.verify_integrity());

    // Round 2: 5 more events.
    for i in 0..5 {
        reader.push_event(BlockedExecutionEvent::for_test(
            &format!("/bin/round2_{i}"),
            BlockReason::HashMismatch,
        ));
    }
    let count2 = collector.poll_and_record().unwrap();
    assert_eq!(count2, 5);
    assert_eq!(chain.len(), 8);
    assert!(chain.verify_integrity());

    // Report should show all 8.
    let report = collector.generate_circia_report(24);
    assert_eq!(report.total_blocked, 8);
    assert_eq!(report.blocked_binaries.len(), 8); // all unique
    assert!(!report.is_clean());
}

/// Verify clean report when no events are pushed.
#[test]
fn clean_report_no_events() {
    let reader = Arc::new(MockEventReader::new());
    let chain = Arc::new(HeartbeatChain::new());
    let collector = EventMetricsCollector::new(
        Arc::clone(&reader),
        Arc::clone(&chain),
        test_verifier(),
    );

    let count = collector.poll_and_record().unwrap();
    assert_eq!(count, 0);

    let report = collector.generate_circia_report(24);
    assert!(report.is_clean());
    assert_eq!(report.total_blocked, 0);
    assert!(report.blocked_binaries.is_empty());
    assert!(report.chain_integrity_verified);
    assert_eq!(report.heartbeat_chain_length, 0);

    let json = report.to_json().unwrap();
    assert!(json.contains("\"total_blocked\": 0"));
}

/// Verify that blocked execution events with edge-case paths work end-to-end.
#[test]
fn edge_case_paths_end_to_end() {
    let reader = Arc::new(MockEventReader::new());
    let chain = Arc::new(HeartbeatChain::new());
    let collector = EventMetricsCollector::new(
        Arc::clone(&reader),
        Arc::clone(&chain),
        test_verifier(),
    );

    // Empty path.
    reader.push_event(BlockedExecutionEvent::for_test("", BlockReason::Unknown));

    // Max-length path.
    let max_path = "m".repeat(BINARY_PATH_LEN);
    reader.push_event(BlockedExecutionEvent::for_test(&max_path, BlockReason::Revoked));

    // UTF-8 path.
    reader.push_event(BlockedExecutionEvent::for_test(
        "/usr/bin/\u{76E3}\u{8996}",
        BlockReason::NotInAllowMap,
    ));

    let count = collector.poll_and_record().unwrap();
    assert_eq!(count, 3);
    assert_eq!(chain.len(), 3);
    assert!(chain.verify_integrity());

    let entries = chain.entries();
    assert_eq!(entries[0].resource, "");
    assert_eq!(entries[1].resource, max_path);
    assert_eq!(entries[2].resource, "/usr/bin/\u{76E3}\u{8996}");

    let report = collector.generate_circia_report(24);
    assert_eq!(report.total_blocked, 3);
    assert_eq!(report.blocked_binaries.len(), 3);
}

/// Verify the heartbeat chain sequence numbers are correct across rounds.
#[test]
fn heartbeat_chain_sequence_numbers() {
    let reader = Arc::new(MockEventReader::new());
    let chain = Arc::new(HeartbeatChain::new());
    let collector = EventMetricsCollector::new(
        Arc::clone(&reader),
        Arc::clone(&chain),
        test_verifier(),
    );

    for i in 0..5 {
        reader.push_event(BlockedExecutionEvent::for_test(
            &format!("/bin/seq_{i}"),
            BlockReason::Revoked,
        ));
    }
    collector.poll_and_record().unwrap();

    let entries = chain.entries();
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.sequence, i as u64, "Sequence number mismatch at index {i}");
    }
}

/// Verify previous_hash linkage across entries.
#[test]
fn heartbeat_chain_hash_linkage() {
    let reader = Arc::new(MockEventReader::new());
    let chain = Arc::new(HeartbeatChain::new());
    let collector = EventMetricsCollector::new(
        Arc::clone(&reader),
        Arc::clone(&chain),
        test_verifier(),
    );

    for i in 0..3 {
        reader.push_event(BlockedExecutionEvent::for_test(
            &format!("/bin/link_{i}"),
            BlockReason::Revoked,
        ));
    }
    collector.poll_and_record().unwrap();

    let entries = chain.entries();
    // First entry's previous_hash should be zero.
    assert_eq!(
        entries[0].previous_hash,
        tameshi::hash::Blake3Hash::from([0u8; 32])
    );
    // Subsequent entries should link to the previous entry's hash.
    for i in 1..entries.len() {
        assert_eq!(
            entries[i].previous_hash, entries[i - 1].entry_hash,
            "Hash linkage broken at index {i}"
        );
    }
}
