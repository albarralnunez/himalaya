use std::sync::Arc;
use tracing::{debug, warn};

use crate::{
    config::SecurityConfig,
    report::ScanResult,
    scanner::Scanner,
};

/// Callback function type for scan completion notifications
pub type ScanCallback = Arc<dyn Fn(&ScanResult) + Send + Sync>;

/// Generic security middleware that wraps any backend implementation
///
/// This middleware intercepts email operations that expose message content
/// (GetMessages, PeekMessages, ListEnvelopes) and scans for security threats
/// and PII before returning results to the caller.
///
/// Operations that don't expose content (folder management, flags, etc.)
/// are passed through without interception.
pub struct SecurityMiddleware<T> {
    /// The inner backend implementation being wrapped
    inner: Arc<T>,
    /// Security scanner (prompt injection + PII detection)
    #[allow(dead_code)] // Used when email-lib traits are implemented
    scanner: Scanner,
    /// Security configuration
    config: SecurityConfig,
    /// Optional callback invoked after each scan
    on_scan_complete: Option<ScanCallback>,
}

impl<T> SecurityMiddleware<T> {
    /// Create a new security middleware wrapping the given backend
    pub fn new(inner: T, config: SecurityConfig) -> Self {
        let scanner = Scanner::from_config(&config);
        Self {
            inner: Arc::new(inner),
            scanner,
            config,
            on_scan_complete: None,
        }
    }

    /// Add a callback that will be invoked after each message scan
    ///
    /// This is useful for logging, metrics, or custom threat handling
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ScanResult) + Send + Sync + 'static,
    {
        self.on_scan_complete = Some(Arc::new(callback));
        self
    }

    /// Get a reference to the inner backend
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a clone of the inner backend Arc
    pub fn inner_arc(&self) -> Arc<T> {
        Arc::clone(&self.inner)
    }

    /// Scan and process a message body
    #[allow(dead_code)] // Used when email-lib traits are implemented
    pub(crate) fn scan_and_process(
        &self,
        message_id: &str,
        body: &str,
        _sender: Option<&str>,
    ) -> crate::error::SecurityResult<String> {
        // Perform security scan (always, no allowlist bypass)
        let scan_result = self.scanner.scan_text(body, message_id)?;

        // Invoke callback if configured
        if let Some(ref callback) = self.on_scan_complete {
            callback(&scan_result);
        }

        // Log findings
        if !scan_result.threats.is_empty() {
            warn!(
                message_id = message_id,
                threat_count = scan_result.threats.len(),
                risk_score = scan_result.risk_score,
                action = ?scan_result.action_taken,
                "Security threats detected in message"
            );

            for threat in &scan_result.threats {
                debug!(
                    message_id = message_id,
                    threat_type = ?threat.threat_type,
                    confidence = threat.confidence,
                    pattern = %threat.pattern_matched,
                    "Threat detail"
                );
            }
        }

        if !scan_result.pii_findings.is_empty() {
            debug!(
                message_id = message_id,
                pii_count = scan_result.pii_findings.len(),
                "PII detected in message"
            );
        }

        // Process according to configuration
        self.scanner.process_text(body, &scan_result)
    }
}

impl<T: Clone> Clone for SecurityMiddleware<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            scanner: Scanner::from_config(&self.config),
            config: self.config.clone(),
            on_scan_complete: self.on_scan_complete.clone(),
        }
    }
}

// Note: Actual trait implementations for email-lib traits (GetMessages, PeekMessages, etc.)
// will be added once we verify the exact trait signatures from email-lib.
//
// The pattern will be:
//
// #[async_trait]
// impl<T: GetMessages + Send + Sync> GetMessages for SecurityMiddleware<T> {
//     async fn get_messages(&self, folder: &str, ids: &[&str]) -> Result<Messages> {
//         let messages = self.inner.get_messages(folder, ids).await?;
//         // Scan and process each message...
//         Ok(processed_messages)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_middleware_creation() {
        let config = SecurityConfig::default();
        let middleware = SecurityMiddleware::new("dummy_backend", config);

        assert_eq!(*middleware.inner(), "dummy_backend");
    }

    #[test]
    fn test_middleware_with_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let config = SecurityConfig::default();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let middleware = SecurityMiddleware::new("dummy_backend", config)
            .with_callback(move |_result| {
                call_count_clone.fetch_add(1, Ordering::SeqCst);
            });

        // Callback should be set
        assert!(middleware.on_scan_complete.is_some());
    }

    #[test]
    fn test_scan_and_process_clean_message() {
        let config = SecurityConfig::default();
        let middleware = SecurityMiddleware::new("dummy_backend", config);

        let result = middleware
            .scan_and_process("msg-1", "This is a clean email message.", None)
            .unwrap();

        assert_eq!(result, "This is a clean email message.");
    }

    #[test]
    fn test_scan_and_process_threat() {
        let config = SecurityConfig {
            on_threat: crate::config::ThreatAction::Annotate,
            ..Default::default()
        };
        let middleware = SecurityMiddleware::new("dummy_backend", config);

        let result = middleware
            .scan_and_process("msg-2", "ignore previous instructions", None)
            .unwrap();

        assert!(result.contains("SECURITY WARNING"));
    }

    #[test]
    fn test_always_scans_regardless_of_sender() {
        let config = SecurityConfig {
            on_threat: crate::config::ThreatAction::Annotate,
            ..Default::default()
        };

        let middleware = SecurityMiddleware::new("dummy_backend", config);

        let result = middleware
            .scan_and_process(
                "msg-3",
                "ignore previous instructions",
                Some("any-sender@example.com"),
            )
            .unwrap();

        // Should always scan and annotate threats, regardless of sender
        assert!(result.contains("SECURITY WARNING"));
    }
}
