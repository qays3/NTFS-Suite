use std::fmt;

#[derive(Debug)]
pub enum VaultError {
    Database(rusqlite::Error),
    NotFound,
    AlreadyExists,
    Io(std::io::Error),
    Parse(crate::error::ParseError),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Database(e) => write!(f, "database error: {}", e),
            VaultError::NotFound => write!(f, "not found"),
            VaultError::AlreadyExists => write!(f, "already exists"),
            VaultError::Io(e) => write!(f, "io error: {}", e),
            VaultError::Parse(e) => write!(f, "parse error: {}", e),
        }
    }
}

impl From<crate::error::ParseError> for VaultError {
    fn from(e: crate::error::ParseError) -> Self {
        VaultError::Parse(e)
    }
}

impl std::error::Error for VaultError {}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Database(e)
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}
