//! BPF ring buffer event reader.
//!
//! Reads blocked execution events from the BPF ring buffer and makes
//! them available to the metrics collector and heartbeat chain.

use kanshi_common::BlockedExecutionEvent;
use tameshi::hash::Blake3Hash;
use tameshi::heartbeat::{HeartbeatEvent, VerificationOutcome, VerifierIdentity};

use crate::error::Error;

/// Trait for reading blocked execution events from BPF.
///
/// The real implementation reads from aya's `RingBuf`.
/// [`MockEventReader`] provides events for testing on macOS.
pub trait EventReader: Send + Sync {
    /// Poll for new blocked execution events.
    /// Returns all events since the last poll.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the underlying ring buffer read fails.
    fn poll_events(&self) -> Result<Vec<BlockedExecutionEvent>, Error>;
}

/// Mock event reader for testing on macOS.
pub struct MockEventReader {
    events: std::sync::Mutex<Vec<BlockedExecutionEvent>>,
}

impl MockEventReader {
    /// Create a new empty mock event reader.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Pre-populate with events for testing.
    #[must_use]
    pub fn with_events(events: Vec<BlockedExecutionEvent>) -> Self {
        Self {
            events: std::sync::Mutex::new(events),
        }
    }

    /// Push a single event (for incremental test setup).
    pub fn push_event(&self, event: BlockedExecutionEvent) {
        self.events
            .lock()
            .expect("MockEventReader lock")
            .push(event);
    }

    /// Get current event count (without consuming).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.events.lock().expect("MockEventReader lock").len()
    }
}

impl Default for MockEventReader {
    fn default() -> Self {
        Self::new()
    }
}

impl EventReader for MockEventReader {
    fn poll_events(&self) -> Result<Vec<BlockedExecutionEvent>, Error> {
        let mut guard = self.events.lock().expect("MockEventReader lock");
        Ok(guard.drain(..).collect())
    }
}

/// Failure modes for the [`FailableEventReader`].
#[derive(Clone, Debug)]
pub enum EventReaderFailMode {
    /// Simulate ring buffer overflow: silently drop some events.
    /// The value is the maximum number of events returned per poll.
    DropEvents(usize),
    /// Simulate partial/corrupted events: return events with zeroed paths.
    PartialEvents,
    /// Simulate delayed delivery: return empty on first N polls, then deliver.
    DelayedDelivery(usize),
    /// Simulate a hard error on poll.
    PollError,
}

/// An event reader that can be configured to fail in specific ways.
///
/// Wraps a [`MockEventReader`] and injects deterministic failures for
/// negative testing of the metrics collector and heartbeat pipeline.
pub struct FailableEventReader {
    inner: MockEventReader,
    fail_mode: Option<EventReaderFailMode>,
    poll_count: std::sync::atomic::AtomicUsize,
}

impl FailableEventReader {
    /// Create with no failure mode (passes through to inner).
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: MockEventReader::new(),
            fail_mode: None,
            poll_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Configure to drop events (ring buffer overflow simulation).
    #[must_use]
    pub fn with_drop_events(mut self, max_per_poll: usize) -> Self {
        self.fail_mode = Some(EventReaderFailMode::DropEvents(max_per_poll));
        self
    }

    /// Configure to return partial/corrupted events.
    #[must_use]
    pub fn with_partial_events(mut self) -> Self {
        self.fail_mode = Some(EventReaderFailMode::PartialEvents);
        self
    }

    /// Configure to delay delivery for N polls.
    #[must_use]
    pub fn with_delayed_delivery(mut self, delay_polls: usize) -> Self {
        self.fail_mode = Some(EventReaderFailMode::DelayedDelivery(delay_polls));
        self
    }

    /// Configure to return a hard error on poll.
    #[must_use]
    pub fn with_poll_error(mut self) -> Self {
        self.fail_mode = Some(EventReaderFailMode::PollError);
        self
    }

    /// Push a single event (delegates to inner).
    pub fn push_event(&self, event: BlockedExecutionEvent) {
        self.inner.push_event(event);
    }

    /// Get pending event count (delegates to inner).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }
}

impl Default for FailableEventReader {
    fn default() -> Self {
        Self::new()
    }
}

impl EventReader for FailableEventReader {
    fn poll_events(&self) -> Result<Vec<BlockedExecutionEvent>, Error> {
        match &self.fail_mode {
            Some(EventReaderFailMode::PollError) => {
                Err(Error::Bpf("ring buffer read failed: I/O error".to_string()))
            }
            Some(EventReaderFailMode::DropEvents(max)) => {
                let events = self.inner.poll_events()?;
                // Silently drop events beyond the max.
                Ok(events.into_iter().take(*max).collect())
            }
            Some(EventReaderFailMode::PartialEvents) => {
                let events = self.inner.poll_events()?;
                // Return events with zeroed binary paths (simulates corruption).
                let corrupted: Vec<BlockedExecutionEvent> = events
                    .into_iter()
                    .map(|mut e| {
                        e.binary_path = [0u8; 256];
                        e.binary_path_len = 0;
                        e
                    })
                    .collect();
                Ok(corrupted)
            }
            Some(EventReaderFailMode::DelayedDelivery(delay)) => {
                let count = self
                    .poll_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if count < *delay {
                    // Return empty until delay is exhausted.
                    Ok(Vec::new())
                } else {
                    self.inner.poll_events()
                }
            }
            None => self.inner.poll_events(),
        }
    }
}

/// Convert a blocked execution event to heartbeat chain parameters.
///
/// Returns the tuple `(verifier, event, outcome, resource, signature_checked)`
/// that can be passed directly to [`HeartbeatChain::append()`].
///
/// [`HeartbeatChain::append()`]: tameshi::heartbeat::HeartbeatChain::append
#[must_use]
pub fn blocked_event_to_heartbeat_params(
    event: &BlockedExecutionEvent,
    verifier: &VerifierIdentity,
) -> (
    VerifierIdentity,
    HeartbeatEvent,
    VerificationOutcome,
    String,
    Blake3Hash,
) {
    let resource = event.path().to_string();
    let sig_hash = Blake3Hash::from(event.looked_up_hash.bytes);
    let verifier = verifier.clone();
    let heartbeat_event = HeartbeatEvent::BinaryVerification;
    let outcome = VerificationOutcome::Denied;
    (verifier, heartbeat_event, outcome, resource, sig_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kanshi_common::{BlockReason, BpfHash};

    // ── MockEventReader tests ──────────────────────────────────────

    #[test]
    fn mock_event_reader_starts_empty() {
        let reader = MockEventReader::new();
        let events = reader.poll_events().unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn mock_event_reader_push_event_adds_event() {
        let reader = MockEventReader::new();
        let event = BlockedExecutionEvent::for_test("/usr/bin/evil", BlockReason::Revoked);
        reader.push_event(event);
        assert_eq!(reader.pending_count(), 1);
    }

    #[test]
    fn mock_event_reader_poll_events_drains_and_returns_all() {
        let reader = MockEventReader::new();
        reader.push_event(BlockedExecutionEvent::for_test("/bin/a", BlockReason::Revoked));
        reader.push_event(BlockedExecutionEvent::for_test("/bin/b", BlockReason::HashMismatch));
        reader.push_event(BlockedExecutionEvent::for_test("/bin/c", BlockReason::NotInAllowMap));

        let events = reader.poll_events().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].path(), "/bin/a");
        assert_eq!(events[1].path(), "/bin/b");
        assert_eq!(events[2].path(), "/bin/c");
    }

    #[test]
    fn mock_event_reader_poll_events_returns_empty_after_drain() {
        let reader = MockEventReader::new();
        reader.push_event(BlockedExecutionEvent::for_test("/bin/a", BlockReason::Revoked));

        let first = reader.poll_events().unwrap();
        assert_eq!(first.len(), 1);

        let second = reader.poll_events().unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn mock_event_reader_with_events_pre_populates() {
        let events = vec![
            BlockedExecutionEvent::for_test("/bin/x", BlockReason::Revoked),
            BlockedExecutionEvent::for_test("/bin/y", BlockReason::HashMismatch),
        ];
        let reader = MockEventReader::with_events(events);
        assert_eq!(reader.pending_count(), 2);

        let polled = reader.poll_events().unwrap();
        assert_eq!(polled.len(), 2);
    }

    #[test]
    fn mock_event_reader_pending_count_is_accurate() {
        let reader = MockEventReader::new();
        assert_eq!(reader.pending_count(), 0);

        reader.push_event(BlockedExecutionEvent::for_test("/a", BlockReason::Revoked));
        assert_eq!(reader.pending_count(), 1);

        reader.push_event(BlockedExecutionEvent::for_test("/b", BlockReason::Revoked));
        assert_eq!(reader.pending_count(), 2);

        let _ = reader.poll_events().unwrap();
        assert_eq!(reader.pending_count(), 0);
    }

    #[test]
    fn event_reader_trait_is_object_safe() {
        let reader = MockEventReader::new();
        let boxed: Box<dyn EventReader> = Box::new(reader);
        let events = boxed.poll_events().unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn default_impl_creates_empty_reader() {
        let reader = MockEventReader::default();
        assert_eq!(reader.pending_count(), 0);
        let events = reader.poll_events().unwrap();
        assert!(events.is_empty());
    }

    // ── blocked_event_to_heartbeat_params tests ────────────────────

    fn test_verifier() -> VerifierIdentity {
        VerifierIdentity::new("kanshi", "kanshi-node-1", "0.1.0")
    }

    #[test]
    fn converts_to_binary_verification_event_type() {
        let event = BlockedExecutionEvent::for_test("/usr/bin/evil", BlockReason::Revoked);
        let (_, heartbeat_event, _, _, _) =
            blocked_event_to_heartbeat_params(&event, &test_verifier());
        assert_eq!(heartbeat_event, HeartbeatEvent::BinaryVerification);
    }

    #[test]
    fn converts_to_denied_outcome() {
        let event = BlockedExecutionEvent::for_test("/usr/bin/evil", BlockReason::Revoked);
        let (_, _, outcome, _, _) = blocked_event_to_heartbeat_params(&event, &test_verifier());
        assert_eq!(outcome, VerificationOutcome::Denied);
    }

    #[test]
    fn binary_path_from_event_is_the_resource() {
        let event = BlockedExecutionEvent::for_test("/opt/suspicious/payload", BlockReason::NotInAllowMap);
        let (_, _, _, resource, _) = blocked_event_to_heartbeat_params(&event, &test_verifier());
        assert_eq!(resource, "/opt/suspicious/payload");
    }

    #[test]
    fn hash_from_event_matches_signature_checked() {
        let mut event = BlockedExecutionEvent::for_test("/usr/bin/evil", BlockReason::Revoked);
        event.looked_up_hash = BpfHash::new([42u8; 32]);
        let (_, _, _, _, sig_hash) = blocked_event_to_heartbeat_params(&event, &test_verifier());
        assert_eq!(sig_hash, Blake3Hash::from([42u8; 32]));
    }

    #[test]
    fn works_with_different_block_reasons() {
        for reason in [
            BlockReason::NotInAllowMap,
            BlockReason::HashMismatch,
            BlockReason::Revoked,
            BlockReason::Unknown,
        ] {
            let event = BlockedExecutionEvent::for_test("/bin/test", reason);
            let (verifier, heartbeat_event, outcome, resource, _) =
                blocked_event_to_heartbeat_params(&event, &test_verifier());

            assert_eq!(verifier.component, "kanshi");
            assert_eq!(heartbeat_event, HeartbeatEvent::BinaryVerification);
            assert_eq!(outcome, VerificationOutcome::Denied);
            assert_eq!(resource, "/bin/test");
        }
    }

    // ── Concurrent access tests ─────────────────────────────────────

    #[test]
    fn mock_event_reader_concurrent_push_and_poll() {
        use std::sync::Arc;
        use std::thread;

        let reader = Arc::new(MockEventReader::new());

        // Spawn a thread that pushes events.
        let writer = Arc::clone(&reader);
        let handle = thread::spawn(move || {
            for i in 0..100 {
                let path = format!("/bin/concurrent_{i}");
                writer.push_event(BlockedExecutionEvent::for_test(
                    &path,
                    BlockReason::Revoked,
                ));
            }
        });

        // Wait for writer to finish.
        handle.join().unwrap();

        // All 100 events should be available.
        let events = reader.poll_events().unwrap();
        assert_eq!(events.len(), 100);
    }

    #[test]
    fn mock_event_reader_large_batch_10000_events() {
        let events: Vec<BlockedExecutionEvent> = (0..10_000)
            .map(|i| {
                BlockedExecutionEvent::for_test(
                    &format!("/bin/batch_{i}"),
                    BlockReason::NotInAllowMap,
                )
            })
            .collect();
        let reader = MockEventReader::with_events(events);
        assert_eq!(reader.pending_count(), 10_000);

        let polled = reader.poll_events().unwrap();
        assert_eq!(polled.len(), 10_000);
        assert_eq!(reader.pending_count(), 0);
    }

    #[test]
    fn mock_event_reader_poll_after_poll_returns_empty() {
        let reader = MockEventReader::with_events(vec![
            BlockedExecutionEvent::for_test("/bin/a", BlockReason::Revoked),
            BlockedExecutionEvent::for_test("/bin/b", BlockReason::Revoked),
        ]);

        let first = reader.poll_events().unwrap();
        assert_eq!(first.len(), 2);

        let second = reader.poll_events().unwrap();
        assert!(second.is_empty());

        let third = reader.poll_events().unwrap();
        assert!(third.is_empty());
    }

    #[test]
    fn mock_event_reader_behind_arc_works() {
        use std::sync::Arc;

        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/arc_test",
            BlockReason::HashMismatch,
        ));

        // Use the Arc reference to poll.
        let events = reader.poll_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path(), "/bin/arc_test");
    }

    #[test]
    fn mock_event_reader_push_after_poll_gives_new_events() {
        let reader = MockEventReader::new();

        reader.push_event(BlockedExecutionEvent::for_test("/bin/a", BlockReason::Revoked));
        let first = reader.poll_events().unwrap();
        assert_eq!(first.len(), 1);

        // Push more after consuming.
        reader.push_event(BlockedExecutionEvent::for_test("/bin/b", BlockReason::Revoked));
        reader.push_event(BlockedExecutionEvent::for_test("/bin/c", BlockReason::Revoked));
        let second = reader.poll_events().unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].path(), "/bin/b");
        assert_eq!(second[1].path(), "/bin/c");
    }

    #[test]
    fn event_reader_trait_behind_arc_is_object_safe() {
        use std::sync::Arc;

        let reader = Arc::new(MockEventReader::new());
        reader.push_event(BlockedExecutionEvent::for_test("/bin/obj", BlockReason::Revoked));

        // Use as trait object behind Arc.
        let trait_ref: Arc<dyn EventReader> = reader;
        let events = trait_ref.poll_events().unwrap();
        assert_eq!(events.len(), 1);
    }

    // ── blocked_event_to_heartbeat_params edge cases ────────────────

    #[test]
    fn heartbeat_params_empty_path() {
        let event = BlockedExecutionEvent::for_test("", BlockReason::Unknown);
        let (_, _, _, resource, _) = blocked_event_to_heartbeat_params(&event, &test_verifier());
        assert_eq!(resource, "");
    }

    #[test]
    fn heartbeat_params_zero_hash() {
        let event = BlockedExecutionEvent::for_test("/bin/test", BlockReason::Revoked);
        let (_, _, _, _, sig_hash) = blocked_event_to_heartbeat_params(&event, &test_verifier());
        assert_eq!(sig_hash, Blake3Hash::from([0u8; 32]));
    }

    #[test]
    fn heartbeat_params_preserves_verifier_identity() {
        let verifier = VerifierIdentity::new("kanshi", "node-42", "1.2.3");
        let event = BlockedExecutionEvent::for_test("/bin/test", BlockReason::Revoked);
        let (v, _, _, _, _) = blocked_event_to_heartbeat_params(&event, &verifier);
        assert_eq!(v.component, "kanshi");
        assert_eq!(v.instance, "node-42");
        assert_eq!(v.version, "1.2.3");
    }

    // =========================================================================
    // FailableEventReader -- Negative Mock Tests (Directive 4)
    // =========================================================================

    #[test]
    fn event_reader_drops_events() {
        let reader = FailableEventReader::new().with_drop_events(2);

        // Push 5 events.
        for i in 0..5 {
            reader.push_event(BlockedExecutionEvent::for_test(
                &format!("/bin/drop_{i}"),
                BlockReason::Revoked,
            ));
        }

        // Only 2 should be returned (3 silently dropped).
        let events = reader.poll_events().unwrap();
        assert_eq!(events.len(), 2, "Should only return max_per_poll events");
    }

    #[test]
    fn event_reader_partial_events() {
        let reader = FailableEventReader::new().with_partial_events();
        reader.push_event(BlockedExecutionEvent::for_test(
            "/usr/bin/corrupted",
            BlockReason::HashMismatch,
        ));

        let events = reader.poll_events().unwrap();
        assert_eq!(events.len(), 1);

        // The path should be empty/zeroed (corrupted).
        let path = events[0].path();
        assert!(
            path.is_empty(),
            "Corrupted event should have empty path, got: '{path}'"
        );
    }

    #[test]
    fn event_reader_delayed_delivery() {
        let reader = FailableEventReader::new().with_delayed_delivery(3);
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/delayed",
            BlockReason::Revoked,
        ));

        // First 3 polls return empty.
        for i in 0..3 {
            let events = reader.poll_events().unwrap();
            assert!(
                events.is_empty(),
                "Poll {i} should return empty during delay"
            );
        }

        // 4th poll delivers the event.
        let events = reader.poll_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path(), "/bin/delayed");
    }

    #[test]
    fn event_reader_poll_error() {
        let reader = FailableEventReader::new().with_poll_error();
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/error",
            BlockReason::Revoked,
        ));

        let result = reader.poll_events();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("ring buffer"),
            "Error should mention ring buffer: {err_msg}"
        );
    }

    #[test]
    fn failable_event_reader_no_fail_passes_through() {
        let reader = FailableEventReader::new();
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/ok",
            BlockReason::Revoked,
        ));

        let events = reader.poll_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path(), "/bin/ok");
    }

    #[test]
    fn failable_event_reader_default_passes_through() {
        let reader = FailableEventReader::default();
        assert_eq!(reader.pending_count(), 0);
        let events = reader.poll_events().unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn failable_event_reader_drop_zero_returns_empty() {
        let reader = FailableEventReader::new().with_drop_events(0);
        reader.push_event(BlockedExecutionEvent::for_test(
            "/bin/drop_all",
            BlockReason::Revoked,
        ));

        let events = reader.poll_events().unwrap();
        assert!(events.is_empty(), "drop_events(0) should return no events");
    }

    #[test]
    fn failable_event_reader_partial_preserves_count() {
        let reader = FailableEventReader::new().with_partial_events();
        for i in 0..3 {
            reader.push_event(BlockedExecutionEvent::for_test(
                &format!("/bin/partial_{i}"),
                BlockReason::NotInAllowMap,
            ));
        }

        let events = reader.poll_events().unwrap();
        assert_eq!(
            events.len(),
            3,
            "Partial events should still return all events, just corrupted"
        );
        for event in &events {
            assert!(event.path().is_empty());
        }
    }
}
