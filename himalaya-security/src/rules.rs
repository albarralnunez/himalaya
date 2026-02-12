use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::error::{SecurityError, SecurityResult};

/// Custom detection rules that can be loaded from TOML
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CustomRules {
    /// Additional keywords for prompt injection detection
    #[serde(default)]
    pub additional_keywords: Vec<String>,

    /// Additional regex patterns for threat detection
    #[serde(default)]
    pub additional_patterns: Vec<String>,

    /// Additional PII patterns to detect
    #[serde(default)]
    pub additional_pii_patterns: Vec<PiiPatternRule>,

    /// Override default confidence thresholds
    #[serde(default)]
    pub confidence_overrides: Option<ConfidenceOverrides>,
}

/// PII pattern rule from custom rules
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PiiPatternRule {
    /// Name/description of this PII type
    pub name: String,

    /// Regex pattern to match
    pub pattern: String,

    /// Replacement text when redacting
    pub redaction_text: String,
}

/// Override default confidence thresholds
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfidenceOverrides {
    /// Minimum confidence to report a threat
    pub min_confidence: Option<f32>,

    /// Base confidence for keyword matches
    pub base_keyword_confidence: Option<f32>,

    /// Confidence boost for suspicious keywords
    pub suspicious_keyword_boost: Option<f32>,
}

impl CustomRules {
    /// Load custom rules from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> SecurityResult<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|e| {
            SecurityError::ConfigError(format!(
                "Failed to read custom rules file {:?}: {}",
                path, e
            ))
        })?;

        toml::from_str(&contents).map_err(|e| {
            SecurityError::ConfigError(format!("Failed to parse custom rules TOML: {}", e))
        })
    }

    /// Create empty custom rules
    pub fn empty() -> Self {
        Self {
            additional_keywords: Vec::new(),
            additional_patterns: Vec::new(),
            additional_pii_patterns: Vec::new(),
            confidence_overrides: None,
        }
    }

    /// Merge with another set of custom rules
    pub fn merge(&mut self, other: CustomRules) {
        self.additional_keywords.extend(other.additional_keywords);
        self.additional_patterns.extend(other.additional_patterns);
        self.additional_pii_patterns
            .extend(other.additional_pii_patterns);

        // Override takes precedence
        if other.confidence_overrides.is_some() {
            self.confidence_overrides = other.confidence_overrides;
        }
    }
}

impl Default for CustomRules {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_custom_rules_from_toml() {
        let toml_content = r#"
additional-keywords = ["custom-keyword", "another-pattern"]
additional-patterns = ["(?i)custom.*regex"]

[[additional-pii-patterns]]
name = "employee-id"
pattern = "EMP-\\d{6}"
redaction-text = "[EMPLOYEE_ID_REDACTED]"

[confidence-overrides]
min-confidence = 0.7
base-keyword-confidence = 0.8
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(toml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let rules = CustomRules::from_file(temp_file.path()).unwrap();

        assert_eq!(rules.additional_keywords.len(), 2);
        assert_eq!(rules.additional_patterns.len(), 1);
        assert_eq!(rules.additional_pii_patterns.len(), 1);
        assert_eq!(
            rules.additional_pii_patterns[0].name,
            "employee-id"
        );
        assert!(rules.confidence_overrides.is_some());
        assert_eq!(
            rules.confidence_overrides.as_ref().unwrap().min_confidence,
            Some(0.7)
        );
    }

    #[test]
    fn test_merge_custom_rules() {
        let mut rules1 = CustomRules {
            additional_keywords: vec!["keyword1".to_string()],
            additional_patterns: vec!["pattern1".to_string()],
            ..Default::default()
        };

        let rules2 = CustomRules {
            additional_keywords: vec!["keyword2".to_string()],
            additional_patterns: vec!["pattern2".to_string()],
            ..Default::default()
        };

        rules1.merge(rules2);

        assert_eq!(rules1.additional_keywords.len(), 2);
        assert_eq!(rules1.additional_patterns.len(), 2);
    }

    #[test]
    fn test_empty_custom_rules() {
        let rules = CustomRules::empty();

        assert!(rules.additional_keywords.is_empty());
        assert!(rules.additional_patterns.is_empty());
        assert!(rules.additional_pii_patterns.is_empty());
        assert!(rules.confidence_overrides.is_none());
    }
}
