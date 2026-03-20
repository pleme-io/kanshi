//! Kanshi configuration — layered: defaults -> YAML -> KANSHI_ env vars.

use serde::{Deserialize, Serialize};
use tameshi::config::load_config;

/// Heartbeat emitter configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    /// Whether heartbeat emission is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Emitter type: "noop", "stdout", "file", "http".
    #[serde(default = "default_emitter_type")]
    pub emitter: String,
    /// File path for the file emitter.
    #[serde(default = "default_heartbeat_path")]
    pub file_path: String,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            emitter: default_emitter_type(),
            file_path: default_heartbeat_path(),
        }
    }
}

#[inline]
fn default_emitter_type() -> String { "noop".to_string() }
#[inline]
fn default_heartbeat_path() -> String { "/var/log/kanshi/heartbeat.jsonl".to_string() }

/// Kanshi daemon configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Health server listen address.
    #[serde(default = "default_health_addr")]
    pub health_addr: String,
    /// Metrics port.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
    /// Default enforcement policy for unmanaged namespaces.
    #[serde(default = "default_policy")]
    pub default_policy: String,
    /// BPF map sizes (number of entries).
    #[serde(default)]
    pub map_config: MapConfig,
    /// Heartbeat configuration.
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            health_addr: default_health_addr(),
            metrics_port: default_metrics_port(),
            default_policy: default_policy(),
            map_config: MapConfig::default(),
            heartbeat: HeartbeatConfig::default(),
        }
    }
}

impl Config {
    /// Validate configuration values.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.map_config.allow_map_size == 0 {
            errors.push("allow_map_size must be > 0".to_string());
        }
        if self.map_config.revocation_map_size == 0 {
            errors.push("revocation_map_size must be > 0".to_string());
        }
        if self.map_config.policy_map_size == 0 {
            errors.push("policy_map_size must be > 0".to_string());
        }
        let valid_policies = ["audit", "enforce", "allow_unknown"];
        if !valid_policies.contains(&self.default_policy.as_str()) {
            errors.push(format!(
                "invalid default_policy: '{}' (expected: audit, enforce, allow_unknown)",
                self.default_policy
            ));
        }
        errors
    }
}

/// BPF map size configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MapConfig {
    /// Max entries in the allow map.
    #[serde(default = "default_allow_map_size")]
    pub allow_map_size: u32,
    /// Max entries in the revocation map.
    #[serde(default = "default_revocation_map_size")]
    pub revocation_map_size: u32,
    /// Max entries in the policy map.
    #[serde(default = "default_policy_map_size")]
    pub policy_map_size: u32,
}

impl Default for MapConfig {
    fn default() -> Self {
        Self {
            allow_map_size: default_allow_map_size(),
            revocation_map_size: default_revocation_map_size(),
            policy_map_size: default_policy_map_size(),
        }
    }
}

#[inline]
fn default_health_addr() -> String { "0.0.0.0:8081".to_string() }
#[inline]
fn default_metrics_port() -> u16 { 9090 }
#[inline]
fn default_policy() -> String { "audit".to_string() }
#[inline]
fn default_allow_map_size() -> u32 { 1_048_576 } // 2^20
#[inline]
fn default_revocation_map_size() -> u32 { 65_536 } // 2^16
#[inline]
fn default_policy_map_size() -> u32 { 4_096 }

/// Load kanshi configuration.
#[must_use]
pub fn load() -> crate::Result<Config> {
    load_config("KANSHI", &["kanshi.yaml", "/etc/kanshi/config.yaml"])
        .map_err(|e| crate::Error::Config(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let config = Config::default();
        assert_eq!(config.health_addr, "0.0.0.0:8081");
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.default_policy, "audit");
        assert_eq!(config.map_config.allow_map_size, 1_048_576);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.health_addr, deserialized.health_addr);
        assert_eq!(config.metrics_port, deserialized.metrics_port);
    }

    #[test]
    fn map_config_defaults() {
        let mc = MapConfig::default();
        assert_eq!(mc.allow_map_size, 1_048_576);
        assert_eq!(mc.revocation_map_size, 65_536);
        assert_eq!(mc.policy_map_size, 4_096);
    }

    #[test]
    fn heartbeat_config_defaults() {
        let hb = HeartbeatConfig::default();
        assert!(!hb.enabled);
        assert_eq!(hb.emitter, "noop");
        assert_eq!(hb.file_path, "/var/log/kanshi/heartbeat.jsonl");
    }

    #[test]
    fn load_with_defaults() {
        // Should succeed with defaults when no YAML/env exists
        let config = load();
        assert!(config.is_ok());
    }

    #[test]
    fn validate_defaults_pass() {
        let config = Config::default();
        assert!(config.validate().is_empty());
    }

    #[test]
    fn validate_zero_map_size_fails() {
        let mut config = Config::default();
        config.map_config.allow_map_size = 0;
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors[0].contains("allow_map_size"));
    }

    #[test]
    fn validate_invalid_policy_fails() {
        let mut config = Config::default();
        config.default_policy = "invalid".to_string();
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors[0].contains("default_policy"));
    }
}
