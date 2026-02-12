use regex::Regex;

use crate::{
    config::PiiAction,
    report::{ContentLocation, PiiFinding, PiiType},
};

/// Detects and redacts PII (Personally Identifiable Information) from text
pub struct PiiRedactor {
    patterns: Vec<PiiPattern>,
}

/// Validate credit card number using Luhn algorithm (mod 10 check)
fn luhn_check(card_number: &str) -> bool {
    let digits: Vec<u32> = card_number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0;
    let mut double = false;

    // Process digits from right to left
    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum % 10 == 0
}

struct PiiPattern {
    pii_type: PiiType,
    regex: Regex,
    mask_fn: Box<dyn Fn(&str) -> String + Send + Sync>,
}

impl PiiRedactor {
    pub fn new() -> Self {
        let patterns = vec![
            // Social Security Numbers (US format: XXX-XX-XXXX)
            PiiPattern {
                pii_type: PiiType::SocialSecurityNumber,
                regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                mask_fn: Box::new(|_| "[SSN_REDACTED]".to_string()),
            },
            // Credit card numbers (various formats, with Luhn validation)
            PiiPattern {
                pii_type: PiiType::CreditCard,
                regex: Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap(),
                mask_fn: Box::new(|s| {
                    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
                    if digits.len() >= 13 && digits.len() <= 19 {
                        // Validate using Luhn algorithm to reduce false positives
                        if luhn_check(&digits) {
                            if digits.len() >= 4 {
                                format!("****-****-****-{}", &digits[digits.len()-4..])
                            } else {
                                "[CARD_REDACTED]".to_string()
                            }
                        } else {
                            s.to_string() // Failed Luhn check, not a valid card number
                        }
                    } else {
                        s.to_string() // Wrong length, not a card number
                    }
                }),
            },
            // Phone numbers (various formats)
            PiiPattern {
                pii_type: PiiType::PhoneNumber,
                regex: Regex::new(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap(),
                mask_fn: Box::new(|s| {
                    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
                    if digits.len() >= 4 {
                        format!("***-***-{}", &digits[digits.len()-4..])
                    } else {
                        "[PHONE_REDACTED]".to_string()
                    }
                }),
            },
            // Email addresses
            PiiPattern {
                pii_type: PiiType::EmailAddress,
                regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
                mask_fn: Box::new(|s| {
                    if let Some(at_pos) = s.find('@') {
                        let (local, domain) = s.split_at(at_pos);
                        if local.len() > 2 {
                            format!("{}***{}", &local[..1], domain)
                        } else {
                            format!("***{}", domain)
                        }
                    } else {
                        "[EMAIL_REDACTED]".to_string()
                    }
                }),
            },
            // API keys (generic pattern for key=value or key: value)
            PiiPattern {
                pii_type: PiiType::ApiKey,
                regex: Regex::new(
                    r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*([a-zA-Z0-9_\-.]{20,})"
                ).unwrap(),
                mask_fn: Box::new(|s| {
                    // Preserve the key name, redact the value
                    if let Some(pos) = s.find([':', '=']) {
                        format!("{}[API_KEY_REDACTED]", &s[..=pos])
                    } else {
                        "[API_KEY_REDACTED]".to_string()
                    }
                }),
            },
            // AWS Access Keys
            PiiPattern {
                pii_type: PiiType::AwsAccessKey,
                regex: Regex::new(r"(AKIA[0-9A-Z]{16})").unwrap(),
                mask_fn: Box::new(|_| "[AWS_ACCESS_KEY_REDACTED]".to_string()),
            },
            // AWS Secret Keys (look for context)
            PiiPattern {
                pii_type: PiiType::ApiKey,
                regex: Regex::new(r"(?i)(aws_secret_access_key|aws.?secret).{0,10}[:=]\s*([A-Za-z0-9/+=]{40})").unwrap(),
                mask_fn: Box::new(|_| "[AWS_SECRET_KEY_REDACTED]".to_string()),
            },
            // Private keys (PEM format)
            PiiPattern {
                pii_type: PiiType::PrivateKey,
                regex: Regex::new(
                    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----"
                ).unwrap(),
                mask_fn: Box::new(|_| "[PRIVATE_KEY_REDACTED]".to_string()),
            },
            // IPv4 addresses (with validation to exclude version numbers)
            PiiPattern {
                pii_type: PiiType::IpAddress,
                regex: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
                mask_fn: Box::new(|s| {
                    let parts: Vec<&str> = s.split('.').collect();
                    if parts.len() == 4 {
                        // Validate each octet is 0-255
                        let valid_ip = parts.iter().all(|&p| {
                            p.parse::<u8>().is_ok()
                        });

                        if valid_ip {
                            // Check if it looks like a version number (e.g., "1.2.3.4" in typical version context)
                            let all_small = parts.iter().all(|&p| {
                                p.parse::<u8>().map(|n| n < 20).unwrap_or(false)
                            });

                            if all_small && parts[0].parse::<u8>().unwrap() < 10 {
                                // Likely a version number like 1.2.3.4, don't redact
                                s.to_string()
                            } else {
                                // Looks like a real IP address
                                format!("{}.{}.***.***.***", parts[0], parts[1])
                            }
                        } else {
                            s.to_string() // Invalid IP, don't redact
                        }
                    } else {
                        "[IP_REDACTED]".to_string()
                    }
                }),
            },
            // GitHub tokens
            PiiPattern {
                pii_type: PiiType::ApiKey,
                regex: Regex::new(r"(gh[ps]_[a-zA-Z0-9]{36,})").unwrap(),
                mask_fn: Box::new(|_| "[GITHUB_TOKEN_REDACTED]".to_string()),
            },
            // Generic Bearer tokens
            PiiPattern {
                pii_type: PiiType::ApiKey,
                regex: Regex::new(r"(?i)bearer\s+([a-zA-Z0-9_\-.]{20,})").unwrap(),
                mask_fn: Box::new(|_| "Bearer [TOKEN_REDACTED]".to_string()),
            },
        ];

        Self { patterns }
    }

    /// Scan text for PII
    pub fn scan(&self, text: &str) -> Vec<PiiFinding> {
        let mut findings = Vec::new();

        for pattern in &self.patterns {
            for capture in pattern.regex.captures_iter(text) {
                let mat = capture.get(0).unwrap();
                let original = mat.as_str().to_string();

                // Apply the masking function
                let redacted = (pattern.mask_fn)(&original);

                // Only create a finding if redaction actually changed something
                if redacted != original {
                    findings.push(PiiFinding {
                        pii_type: pattern.pii_type.clone(),
                        location: ContentLocation::Body { offset: mat.start() },
                        original_value: None, // Don't store original by default for security
                        redacted_value: redacted,
                    });
                }
            }
        }

        findings
    }

    /// Redact PII from text based on action
    pub fn redact(&self, text: &str, action: PiiAction) -> String {
        match action {
            PiiAction::Disabled => text.to_string(),
            PiiAction::LogOnly => text.to_string(),
            PiiAction::Redact | PiiAction::Mask => {
                let mut result = text.to_string();
                let mut findings = self.scan(text);

                // Sort by offset in reverse order to preserve positions during replacement
                findings.sort_by(|a, b| {
                    let a_offset = if let ContentLocation::Body { offset } = a.location { offset } else { 0 };
                    let b_offset = if let ContentLocation::Body { offset } = b.location { offset } else { 0 };
                    b_offset.cmp(&a_offset)
                });

                // Apply redactions
                for finding in findings {
                    if let ContentLocation::Body { offset } = finding.location {
                        // Find the original value at this location
                        for pattern in &self.patterns {
                            if let Some(mat) = pattern.regex.find(&result[offset..]) {
                                if mat.start() == 0 {
                                    let end = offset + mat.end();
                                    result.replace_range(offset..end, &finding.redacted_value);
                                    break;
                                }
                            }
                        }
                    }
                }

                result
            }
        }
    }

    /// Check if text contains any PII
    pub fn contains_pii(&self, text: &str) -> bool {
        !self.scan(text).is_empty()
    }
}

impl Default for PiiRedactor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_detection() {
        let redactor = PiiRedactor::new();
        let text = "My SSN is 123-45-6789 for verification.";
        let findings = redactor.scan(text);

        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].pii_type, PiiType::SocialSecurityNumber));
    }

    #[test]
    fn test_credit_card_redaction() {
        let redactor = PiiRedactor::new();
        let text = "Card number: 4111-1111-1111-1111";
        let result = redactor.redact(text, PiiAction::Redact);

        assert!(result.contains("****-****-****-1111"));
        assert!(!result.contains("4111-1111-1111-1111"));
    }

    #[test]
    fn test_email_masking() {
        let redactor = PiiRedactor::new();
        let text = "Contact me at alice@example.com";
        let result = redactor.redact(text, PiiAction::Mask);

        assert!(result.contains("a***@example.com"));
        assert!(!result.contains("alice@example.com"));
    }

    #[test]
    fn test_api_key_detection() {
        let redactor = PiiRedactor::new();
        let text = "API_KEY=sk_test_fakekeyforunitesting1234567890abcdef";
        let findings = redactor.scan(text);

        assert!(!findings.is_empty());
        assert!(matches!(findings[0].pii_type, PiiType::ApiKey));
    }

    #[test]
    fn test_aws_key_detection() {
        let redactor = PiiRedactor::new();
        let text = "My access key is AKIAIOSFODNN7EXAMPLE";
        let result = redactor.redact(text, PiiAction::Redact);

        assert!(result.contains("[AWS_ACCESS_KEY_REDACTED]"));
        assert!(!result.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_private_key_detection() {
        let redactor = PiiRedactor::new();
        let text = r#"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
-----END PRIVATE KEY-----
        "#;
        let result = redactor.redact(text, PiiAction::Redact);

        assert!(result.contains("[PRIVATE_KEY_REDACTED]"));
        assert!(!result.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_phone_number_masking() {
        let redactor = PiiRedactor::new();
        let text = "Call me at (555) 123-4567";
        let result = redactor.redact(text, PiiAction::Mask);

        assert!(result.contains("***-***-4567"));
        assert!(!result.contains("555") || !result.contains("123"));
    }

    #[test]
    fn test_ip_address_masking() {
        let redactor = PiiRedactor::new();
        let text = "Server IP: 192.168.1.100";
        let result = redactor.redact(text, PiiAction::Mask);

        assert!(result.contains("192.168.***.***.***"));
        assert!(!result.contains("192.168.1.100"));
    }

    #[test]
    fn test_no_pii_in_clean_text() {
        let redactor = PiiRedactor::new();
        let text = "This is a normal message with no sensitive data.";
        let findings = redactor.scan(text);

        assert!(findings.is_empty());
        assert!(!redactor.contains_pii(text));
    }

    #[test]
    fn test_github_token_detection() {
        let redactor = PiiRedactor::new();
        let text = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let result = redactor.redact(text, PiiAction::Redact);

        assert!(result.contains("[GITHUB_TOKEN_REDACTED]"));
    }

    #[test]
    fn test_bearer_token_detection() {
        let redactor = PiiRedactor::new();
        let text = "Authorization: Bearer abc123def456ghi789jkl012mno345";
        let result = redactor.redact(text, PiiAction::Redact);

        assert!(result.contains("Bearer [TOKEN_REDACTED]"));
    }

    #[test]
    fn test_multiple_pii_types() {
        let redactor = PiiRedactor::new();
        let text = "SSN: 123-45-6789, Email: test@example.com, Phone: 555-1234";
        let findings = redactor.scan(text);

        assert!(findings.len() >= 2); // At least SSN and email
    }

    #[test]
    fn test_luhn_validation_valid_card() {
        // Valid test credit card (passes Luhn check)
        assert!(luhn_check("4111111111111111")); // Visa test card
        assert!(luhn_check("5555555555554444")); // Mastercard test card
    }

    #[test]
    fn test_luhn_validation_invalid_card() {
        // Invalid card number (fails Luhn check)
        assert!(!luhn_check("1234567890123456"));
        assert!(!luhn_check("1111111111111111"));
    }

    #[test]
    fn test_credit_card_false_positive_prevention() {
        let redactor = PiiRedactor::new();
        // Order number that looks like card but fails Luhn
        let text = "Order #1234-5678-9012-3456 has been shipped";
        let result = redactor.redact(text, PiiAction::Redact);

        // Should NOT be redacted because it fails Luhn check
        assert!(result.contains("1234-5678-9012-3456"));
    }

    #[test]
    fn test_version_number_not_redacted_as_ip() {
        let redactor = PiiRedactor::new();
        let text = "Software version 1.2.3.4 released";
        let result = redactor.redact(text, PiiAction::Redact);

        // Should NOT be redacted as IP address
        assert!(result.contains("1.2.3.4"));
    }

    #[test]
    fn test_actual_ip_address_redacted() {
        let redactor = PiiRedactor::new();
        let text = "Server IP: 192.168.1.100";
        let result = redactor.redact(text, PiiAction::Redact);

        // Should be redacted
        assert!(result.contains("192.168.***.***.***"));
        assert!(!result.contains("192.168.1.100"));
    }

    #[test]
    fn test_invalid_ip_not_redacted() {
        let redactor = PiiRedactor::new();
        let text = "Value: 999.888.777.666";
        let result = redactor.redact(text, PiiAction::Redact);

        // Invalid IP (octets > 255), should not be redacted
        assert!(result.contains("999.888.777.666"));
    }
}
