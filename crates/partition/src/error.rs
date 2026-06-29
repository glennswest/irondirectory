//! Error type for the partition model.

/// Errors produced while parsing DNs/ids or operating on the registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PartitionError {
    /// A distinguished name could not be parsed.
    #[error("invalid DN {input:?}: {reason}")]
    InvalidDn {
        /// The offending DN string.
        input: String,
        /// Why it failed to parse.
        reason: String,
    },

    /// A partition id violates the `[a-z0-9-]` (no leading/trailing `-`) rule.
    #[error("invalid partition id {0:?}: must be non-empty [a-z0-9-], no leading/trailing '-'")]
    InvalidId(String),

    /// A forest id violates the same rule as a partition id.
    #[error("invalid forest id {0:?}: must be non-empty [a-z0-9-], no leading/trailing '-'")]
    InvalidForestId(String),

    /// Lookup for a partition id that is not registered.
    #[error("unknown partition: {0}")]
    UnknownPartition(String),

    /// No naming context in the registry is a suffix of the given DN.
    #[error("no naming context owns DN: {0}")]
    NoOwningPartition(String),

    /// A partition id was inserted twice.
    #[error("duplicate partition id: {0}")]
    DuplicateId(String),
}

/// Convenience result alias for this crate.
pub type Result<T> = std::result::Result<T, PartitionError>;
