use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main security configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SecurityConfig {
    /// What to do when a threat is detected
    #[serde(default = "default_threat_action")]
    pub on_threat: ThreatAction,

    /// What to do with PII
    #[serde(default = "default_pii_action")]
    pub pii_handling: PiiAction,

    /// Enable/disable specific scanners
    #[serde(default)]
    pub scanners: ScannerConfig,

    /// Allowlisted sender addresses (skip scanning)
    #[serde(default)]
    pub allowlisted_senders: Vec<String>,

    /// Custom rules file path (optional)
    #[serde(default)]
    pub rules_path: Option<PathBuf>,

    /// Risk score threshold for blocking (0.0 - 1.0)
    #[serde(default = "default_block_threshold")]
    pub block_threshold: f32,

    /// Risk score threshold for warnings (0.0 - 1.0)
    #[serde(default = "default_warn_threshold")]
    pub warn_threshold: f32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            on_threat: default_threat_action(),
            pii_handling: default_pii_action(),
            scanners: ScannerConfig::default(),
            allowlisted_senders: Vec::new(),
            rules_path: None,
            block_threshold: default_block_threshold(),
            warn_threshold: default_warn_threshold(),
        }
    }
}

impl SecurityConfig {
    /// Create a config that blocks high-risk messages
    pub fn default_blocking() -> Self {
        Self {
            on_threat: ThreatAction::Block,
            ..Default::default()
        }
    }

    /// Create a config that only logs threats
    pub fn default_logging() -> Self {
        Self {
            on_threat: ThreatAction::LogOnly,
            pii_handling: PiiAction::LogOnly,
            ..Default::default()
        }
    }

    /// Load config from TOML file
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, crate::error::SecurityError> {
        let path = path.into();
        let contents = std::fs::read_to_string(&path).map_err(|e| {
            crate::error::SecurityError::ConfigError(format!(
                "Failed to read config file {:?}: {}",
                path, e
            ))
        })?;

        toml::from_str(&contents).map_err(|e| {
            crate::error::SecurityError::ConfigError(format!("Failed to parse TOML: {}", e))
        })
    }

    /// Check if a sender is allowlisted
    ///
    /// Supports both exact match (sender == "user@example.com")
    /// and domain match (sender ends with "@example.com" if allowlist has "example.com")
    pub fn is_sender_allowlisted(&self, sender: &str) -> bool {
        self.allowlisted_senders.iter().any(|allowed| {
            // Exact match
            sender == allowed ||
            // Domain match: if allowed doesn't contain @, match as domain suffix
            (!allowed.contains('@') && sender.ends_with(&format!("@{}", allowed)))
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatAction {
    /// Log the threat and return the message with annotations
    Annotate,
    /// Redact the threatening content, return sanitized message
    Redact,
    /// Block the message entirely, return an error/placeholder
    Block,
    /// Log only — no modification
    LogOnly,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PiiAction {
    /// Replace PII with [REDACTED] placeholders
    Redact,
    /// Mask partially (e.g., ***-**-1234)
    Mask,
    /// Log presence but don't modify
    LogOnly,
    /// Do nothing
    Disabled,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScannerConfig {
    #[serde(default = "default_true")]
    pub prompt_injection: bool,

    #[serde(default = "default_true")]
    pub pii_detection: bool,

    #[serde(default = "default_true")]
    pub url_analysis: bool,

    #[serde(default = "default_true")]
    pub encoded_payload: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            prompt_injection: true,
            pii_detection: true,
            url_analysis: true,
            encoded_payload: true,
        }
    }
}

// Default value functions for serde
fn default_threat_action() -> ThreatAction {
    ThreatAction::Annotate
}

fn default_pii_action() -> PiiAction {
    PiiAction::Redact
}

fn default_block_threshold() -> f32 {
    0.8
}

fn default_warn_threshold() -> f32 {
    0.5
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::default();
        assert_eq!(config.on_threat, ThreatAction::Annotate);
        assert_eq!(config.pii_handling, PiiAction::Redact);
        assert!(config.scanners.prompt_injection);
    }

    #[test]
    fn test_parse_config_from_toml() {
        let toml = r#"
            on-threat = "block"
            pii-handling = "mask"
            block-threshold = 0.9
            allowlisted-senders = ["trusted@example.com"]

            [scanners]
            prompt-injection = true
            pii-detection = false
        "#;

        let config: SecurityConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.on_threat, ThreatAction::Block);
        assert_eq!(config.pii_handling, PiiAction::Mask);
        assert_eq!(config.block_threshold, 0.9);
        assert!(!config.scanners.pii_detection);
    }

    #[test]
    fn test_allowlist_matching() {
        let config = SecurityConfig {
            allowlisted_senders: vec!["trusted.com".to_string(), "noreply@github.com".to_string()],
            ..Default::default()
        };

        // Domain match
        assert!(config.is_sender_allowlisted("alice@trusted.com"));
        // Exact match
        assert!(config.is_sender_allowlisted("noreply@github.com"));
        // No match
        assert!(!config.is_sender_allowlisted("attacker@evil.com"));
    }
}
