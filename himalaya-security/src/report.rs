use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Result of scanning a message for security threats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Message identifier
    pub message_id: String,

    /// Detected threats
    pub threats: Vec<Threat>,

    /// PII findings
    pub pii_findings: Vec<PiiFinding>,

    /// Overall risk score (0.0 = clean, 1.0 = malicious)
    pub risk_score: f32,

    /// Action taken by the middleware
    pub action_taken: ActionTaken,

    /// Timestamp of the scan
    #[serde(default = "chrono_now")]
    pub scanned_at: String,

    /// Duration of the scan in microseconds
    #[serde(default)]
    pub scan_duration_us: u64,
}

impl ScanResult {
    pub fn new(message_id: impl Into<String>) -> Self {
        Self {
            message_id: message_id.into(),
            threats: Vec::new(),
            pii_findings: Vec::new(),
            risk_score: 0.0,
            action_taken: ActionTaken::Allowed,
            scanned_at: chrono_now(),
            scan_duration_us: 0,
        }
    }

    /// Set scan duration
    pub fn set_duration(&mut self, duration: Duration) {
        self.scan_duration_us = duration.as_micros() as u64;
    }

    /// Calculate risk score based on threats
    pub fn calculate_risk_score(&mut self) {
        if self.threats.is_empty() {
            self.risk_score = 0.0;
            return;
        }

        // Average of top 3 highest confidence threats
        let mut confidences: Vec<f32> = self.threats.iter().map(|t| t.confidence).collect();
        confidences.sort_by(|a, b| b.partial_cmp(a).unwrap());

        let top_threats = confidences.iter().take(3).copied().collect::<Vec<_>>();
        self.risk_score = top_threats.iter().sum::<f32>() / top_threats.len() as f32;

        // Boost score if multiple threat types detected
        let unique_types: std::collections::HashSet<_> =
            self.threats.iter().map(|t| &t.threat_type).collect();
        if unique_types.len() >= 3 {
            self.risk_score = (self.risk_score * 1.2).min(1.0);
        }
    }

    /// Check if this result indicates a high-risk message
    pub fn is_high_risk(&self, threshold: f32) -> bool {
        self.risk_score >= threshold
    }

    /// Get a human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "Message {}: {} threats, {} PII findings, risk score: {:.2}",
            self.message_id,
            self.threats.len(),
            self.pii_findings.len(),
            self.risk_score
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub threat_type: ThreatType,
    pub pattern_matched: String,
    pub location: ContentLocation,
    pub confidence: f32,
    pub context_snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    PromptInjection,
    SystemPromptOverride,
    InstructionHijacking,
    EncodedPayload,
    SuspiciousUrl,
    RoleManipulation,
    DataExfiltration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentLocation {
    Subject,
    Body { offset: usize },
    Header { name: String },
    Attachment { filename: String },
}

impl ContentLocation {
    pub fn offset(&self) -> usize {
        match self {
            ContentLocation::Body { offset } => *offset,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiFinding {
    pub pii_type: PiiType,
    pub location: ContentLocation,
    /// Original value (only if config allows storage)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_value: Option<String>,
    pub redacted_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    SocialSecurityNumber,
    CreditCard,
    PhoneNumber,
    EmailAddress,
    ApiKey,
    AwsAccessKey,
    PrivateKey,
    IpAddress,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionTaken {
    /// Message passed through unchanged
    Allowed,
    /// Threats were annotated in the message
    Annotated,
    /// Threatening content was redacted
    Redacted,
    /// Message was blocked
    Blocked,
    /// Only logged, no modification
    LoggedOnly,
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    format!("{:?}", SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_score_calculation() {
        let mut result = ScanResult::new("test-123");

        result.threats.push(Threat {
            threat_type: ThreatType::PromptInjection,
            pattern_matched: "ignore previous instructions".to_string(),
            location: ContentLocation::Body { offset: 0 },
            confidence: 0.9,
            context_snippet: "".to_string(),
        });

        result.threats.push(Threat {
            threat_type: ThreatType::SystemPromptOverride,
            pattern_matched: "system:".to_string(),
            location: ContentLocation::Body { offset: 50 },
            confidence: 0.8,
            context_snippet: "".to_string(),
        });

        result.calculate_risk_score();

        assert!(result.risk_score > 0.8);
        assert!(result.risk_score < 1.0);
    }

    #[test]
    fn test_high_risk_detection() {
        let mut result = ScanResult::new("test-456");
        result.risk_score = 0.85;

        assert!(result.is_high_risk(0.8));
        assert!(!result.is_high_risk(0.9));
    }
}
