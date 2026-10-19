use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    OutOfBounds { off: usize, len: usize, total: usize },
    BadSignature { found: [u8; 4] },
    FixupMismatch { sector: usize },
    ShortRecord { len: usize },
    BadAttribute { offset: usize },
    InvalidRunHeader { byte: u8 },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::OutOfBounds { off, len, total } => {
                write!(f, "read of {} bytes at offset {} exceeds buffer of {}", len, off, total)
            }
            ParseError::BadSignature { found } => {
                write!(f, "unexpected record signature {:02x?}", found)
            }
            ParseError::FixupMismatch { sector } => {
                write!(f, "fixup mismatch in sector {}", sector)
            }
            ParseError::ShortRecord { len } => {
                write!(f, "record length {} is too small", len)
            }
            ParseError::BadAttribute { offset } => {
                write!(f, "attribute at offset {} is malformed", offset)
            }
            ParseError::InvalidRunHeader { byte } => {
                write!(f, "invalid data run header byte {:#04x}", byte)
            }
        }
    }
}

impl std::error::Error for ParseError {}
