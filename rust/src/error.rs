use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZentyError {
    #[error("HTTP transport failure: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("API rejected request — status {status}: {body}")]
    ApiError { status: u16, body: String },

    #[error("Consent not granted for target: {0}")]
    ConsentDenied(String),

    #[error("Scope violation: target '{0}' is outside authorized scope")]
    ScopeViolation(String),

    #[error("Serialization error: {0}")]
    SerializeError(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Air-gap synchronization error: {0}")]
    AirgapError(String),

    #[error("Agent role mismatch: this action requires role '{required}', current role is '{current}'")]
    RoleMismatch { required: String, current: String },
}
