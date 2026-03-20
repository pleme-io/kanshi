//! Per-namespace enforcement policy engine.

use kanshi_common::EnforcementPolicy;
use std::collections::HashMap;

/// Policy engine that maps namespaces to enforcement levels.
pub struct PolicyEngine {
    policies: HashMap<String, EnforcementPolicy>,
    default_policy: EnforcementPolicy,
}

impl PolicyEngine {
    /// Create a new policy engine with a default policy.
    #[must_use]
    pub fn new(default_policy: EnforcementPolicy) -> Self {
        Self {
            policies: HashMap::new(),
            default_policy,
        }
    }

    /// Set the policy for a specific namespace.
    pub fn set_policy(&mut self, namespace: &str, policy: EnforcementPolicy) {
        self.policies.insert(namespace.to_string(), policy);
    }

    /// Remove the policy for a namespace (falls back to default).
    pub fn remove_policy(&mut self, namespace: &str) {
        self.policies.remove(namespace);
    }

    /// Get the effective policy for a namespace.
    #[must_use]
    pub fn get_policy(&self, namespace: &str) -> EnforcementPolicy {
        self.policies
            .get(namespace)
            .copied()
            .unwrap_or(self.default_policy)
    }

    /// Get the number of configured namespace policies.
    #[must_use]
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Check if a namespace should enforce (block) unattested binaries.
    #[must_use]
    pub fn should_enforce(&self, namespace: &str) -> bool {
        self.get_policy(namespace) == EnforcementPolicy::Enforce
    }

    /// Check if a namespace is in audit-only mode.
    #[must_use]
    pub fn is_audit_only(&self, namespace: &str) -> bool {
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
        let mut engine = PolicyEngine::new(EnforcementPolicy::Audit);
        engine.set_policy("production", EnforcementPolicy::Enforce);
        assert!(engine.should_enforce("production"));
        assert!(engine.is_audit_only("staging"));
    }

    #[test]
    fn remove_policy_falls_back() {
        let mut engine = PolicyEngine::new(EnforcementPolicy::Audit);
        engine.set_policy("ns", EnforcementPolicy::Enforce);
        assert!(engine.should_enforce("ns"));
        engine.remove_policy("ns");
        assert!(!engine.should_enforce("ns"));
    }

    #[test]
    fn policy_count() {
        let mut engine = PolicyEngine::new(EnforcementPolicy::Audit);
        assert_eq!(engine.policy_count(), 0);
        engine.set_policy("a", EnforcementPolicy::Enforce);
        engine.set_policy("b", EnforcementPolicy::AllowUnknown);
        assert_eq!(engine.policy_count(), 2);
    }

    #[test]
    fn allow_unknown_policy() {
        let mut engine = PolicyEngine::new(EnforcementPolicy::Enforce);
        engine.set_policy("dev", EnforcementPolicy::AllowUnknown);
        assert!(!engine.should_enforce("dev"));
        assert!(!engine.is_audit_only("dev"));
    }
}
