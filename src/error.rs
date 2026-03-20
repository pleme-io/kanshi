//! Error types for the kanshi sentinel.

use std::time::Duration;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("BPF error: {0}")]
    Bpf(String),

    #[error("hash verification failed for inode {inode}: expected {expected}, got {actual}")]
    HashMismatch {
        inode: u64,
        expected: String,
        actual: String,
    },

    #[error("policy error: {0}")]
    Policy(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("health check failed: {0}")]
    Health(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("tameshi error: {0}")]
    Tameshi(#[from] tameshi::error::TameshiError),

    #[error("internal error: {0}")]
    Internal(String),
}

impl Error {
    #[inline]
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::Io(_) | Error::Health(_))
    }

    #[inline]
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(self, Error::Config(_) | Error::Policy(_))
    }

    #[inline]
    #[must_use]
    pub fn requeue_duration(&self) -> Duration {
        match self {
            Error::Io(_) => Duration::from_secs(5),
            Error::Bpf(_) => Duration::from_secs(10),
            Error::HashMismatch { .. } => Duration::from_secs(30),
            _ => Duration::from_secs(60),
        }
    }

    #[inline]
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Error::Bpf(_) => "bpf",
            Error::HashMismatch { .. } => "verification",
            Error::Policy(_) => "policy",
            Error::Config(_) => "configuration",
            Error::Health(_) => "health",
            Error::Io(_) => "io",
            Error::Serialization(_) => "serialization",
            Error::Tameshi(_) => "tameshi",
            Error::Internal(_) => "internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = Error::Bpf("program load failed".to_string());
        assert!(err.to_string().contains("program load failed"));
    }

    #[test]
    fn error_hash_mismatch() {
        let err = Error::HashMismatch {
            inode: 12345,
            expected: "blake3:aaa".to_string(),
            actual: "blake3:bbb".to_string(),
        };
        assert!(err.to_string().contains("12345"));
    }

    #[test]
    fn error_transient() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let err: Error = Error::from(io_err);
        assert!(err.is_transient());
        assert!(!err.is_permanent());
    }

    #[test]
    fn error_permanent() {
        let err = Error::Config("bad".to_string());
        assert!(err.is_permanent());
        assert!(!err.is_transient());
    }

    #[test]
    fn error_category() {
        assert_eq!(Error::Bpf("x".to_string()).category(), "bpf");
        assert_eq!(Error::Config("x".to_string()).category(), "configuration");
        assert_eq!(Error::Internal("x".to_string()).category(), "internal");
    }

    #[test]
    fn error_requeue() {
        assert_eq!(Error::Bpf("x".to_string()).requeue_duration(), Duration::from_secs(10));
    }
}
