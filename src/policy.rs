//! Per-namespace enforcement policy engine.

use kanshi_common::EnforcementPolicy;
use std::collections::HashMap;

/// Trait for policy lookup, enabling mock injection in tests.
pub trait PolicyProvider: Send + Sync {
    /// Get the effective policy for a namespace.
    fn get_policy(&self, namespace: &str) -> EnforcementPolicy;
    /// Check if a namespace should enforce (block) unattested binaries.
    fn should_enforce(&self, namespace: &str) -> bool;
    /// Check if a namespace is in audit-only mode.
    fn is_audit_only(&self, namespace: &str) -> bool;
}

/// Policy engine that maps namespaces to enforcement levels.
pub struct PolicyEngine {
    policies: std::sync::RwLock<HashMap<String, EnforcementPolicy>>,
    default_policy: EnforcementPolicy,
}

impl PolicyEngine {
    /// Create a new policy engine with a default policy.
    #[must_use]
    pub fn new(default_policy: EnforcementPolicy) -> Self {
        Self {
            policies: std::sync::RwLock::new(HashMap::new()),
            default_policy,
        }
    }

    /// Set the policy for a specific namespace.
    pub fn set_policy(&self, namespace: &str, policy: EnforcementPolicy) {
        let mut policies = self.policies.write().expect("policy engine write lock");
        policies.insert(namespace.to_string(), policy);
    }

    /// Remove the policy for a namespace (falls back to default).
    /// Returns `true` if the policy existed and was removed.
    pub fn remove_policy(&self, namespace: &str) -> bool {
        let mut policies = self.policies.write().expect("policy engine write lock");
        policies.remove(namespace).is_some()
    }

    /// Get the number of configured namespace policies.
    #[inline]
    #[must_use]
    pub fn policy_count(&self) -> usize {
        let policies = self.policies.read().expect("policy engine read lock");
        policies.len()
    }
}

impl PolicyProvider for PolicyEngine {
    #[inline]
    fn get_policy(&self, namespace: &str) -> EnforcementPolicy {
        let policies = self.policies.read().expect("policy engine read lock");
        policies
            .get(namespace)
            .copied()
            .unwrap_or(self.default_policy)
    }

    #[inline]
    fn should_enforce(&self, namespace: &str) -> bool {
        self.get_policy(namespace) == EnforcementPolicy::Enforce
    }

    #[inline]
    fn is_audit_only(&self, namespace: &str) -> bool {
        self.get_policy(namespace) == EnforcementPolicy::Audit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_applied() {
        let engine = PolicyEngine::new(EnforcementPolicy::Audit);
        assert_eq!(engine.get_policy("unknown-ns"), EnforcementPolicy::Audit);
        assert!(engine.is_audit_only("unknown-ns"));
        assert!(!engine.should_enforce("unknown-ns"));
    }

    #[test]
    fn namespace_override() {
        let engine = PolicyEngine::new(EnforcementPolicy::Audit);
        engine.set_policy("production", EnforcementPolicy::Enforce);
        assert!(engine.should_enforce("production"));
        assert!(engine.is_audit_only("staging"));
    }

    #[test]
    fn remove_policy_falls_back() {
        let engine = PolicyEngine::new(EnforcementPolicy::Audit);
        engine.set_policy("ns", EnforcementPolicy::Enforce);
        assert!(engine.should_enforce("ns"));
        engine.remove_policy("ns");
        assert!(!engine.should_enforce("ns"));
    }

    #[test]
    fn policy_count() {
        let engine = PolicyEngine::new(EnforcementPolicy::Audit);
        assert_eq!(engine.policy_count(), 0);
        engine.set_policy("a", EnforcementPolicy::Enforce);
        engine.set_policy("b", EnforcementPolicy::AllowUnknown);
        assert_eq!(engine.policy_count(), 2);
    }

    #[test]
    fn allow_unknown_policy() {
        let engine = PolicyEngine::new(EnforcementPolicy::Enforce);
        engine.set_policy("dev", EnforcementPolicy::AllowUnknown);
        assert!(!engine.should_enforce("dev"));
        assert!(!engine.is_audit_only("dev"));
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let engine = PolicyEngine::new(EnforcementPolicy::Audit);
        assert!(!engine.remove_policy("nonexistent"));
    }

    #[test]
    fn remove_existing_returns_true() {
        let engine = PolicyEngine::new(EnforcementPolicy::Audit);
        engine.set_policy("ns", EnforcementPolicy::Enforce);
        assert!(engine.remove_policy("ns"));
        assert!(!engine.remove_policy("ns")); // second time returns false
    }
}
