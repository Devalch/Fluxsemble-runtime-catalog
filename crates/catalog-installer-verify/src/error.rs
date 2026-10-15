use std::fmt;

/// Stable, non-echoing acquisition failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    InvalidPolicy,
    RedirectDenied,
    TooManyRedirects,
    UnexpectedStatus,
    Transport,
    Timeout,
    Cancelled,
    SizeLimitExceeded,
    SizeMismatch,
    DigestMismatch,
    SriMismatch,
    TemporaryFile,
    CacheInvalid,
    Publication,
    Archive,
    Graph,
    Bundle,
    Input,
}

impl fmt::Display for AcquireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "invalid acquisition policy",
            Self::RedirectDenied => "redirect denied",
            Self::TooManyRedirects => "too many redirects",
            Self::UnexpectedStatus => "unexpected response status",
            Self::Transport => "acquisition transport failed",
            Self::Timeout => "acquisition timed out",
            Self::Cancelled => "acquisition cancelled",
            Self::SizeLimitExceeded => "acquisition size limit exceeded",
            Self::SizeMismatch => "acquisition size mismatch",
            Self::DigestMismatch => "acquisition digest mismatch",
            Self::SriMismatch => "acquisition integrity mismatch",
            Self::TemporaryFile => "acquisition temporary file rejected",
            Self::CacheInvalid => "acquisition cache object rejected",
            Self::Publication => "acquisition publication failed",
            Self::Archive => "acquisition archive rejected",
            Self::Graph => "acquisition graph rejected",
            Self::Bundle => "acquisition bundle rejected",
            Self::Input => "acquisition input rejected",
        })
    }
}

impl std::error::Error for AcquireError {}
