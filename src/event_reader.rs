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
}
