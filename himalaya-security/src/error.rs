use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Message blocked due to security threat (risk score: {0:.2})")]
    MessageBlocked(f32),

    #[error("Outbound message contains PII and was blocked")]
    OutboundPiiBlocked,

    #[error("Failed to parse email content: {0}")]
    EmailParseError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Scanner error: {0}")]
    ScannerError(String),

    #[error("Backend error: {0}")]
    BackendError(String),
}

pub type SecurityResult<T> = Result<T, SecurityError>;
