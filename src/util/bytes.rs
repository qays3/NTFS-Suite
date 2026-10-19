use crate::error::ParseError;

pub fn u16_le(buf: &[u8], off: usize) -> Result<u16, ParseError> {
    let end = off + 2;
    if end > buf.len() {
        return Err(ParseError::OutOfBounds { off, len: 2, total: buf.len() });
    }
    Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
}

pub fn u32_le(buf: &[u8], off: usize) -> Result<u32, ParseError> {
    let end = off + 4;
    if end > buf.len() {
        return Err(ParseError::OutOfBounds { off, len: 4, total: buf.len() });
    }
    Ok(u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]))
}

pub fn u64_le(buf: &[u8], off: usize) -> Result<u64, ParseError> {
    let end = off + 8;
    if end > buf.len() {
        return Err(ParseError::OutOfBounds { off, len: 8, total: buf.len() });
    }
    Ok(u64::from_le_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
        buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7],
    ]))
}

pub fn i64_le(buf: &[u8], off: usize) -> Result<i64, ParseError> {
    Ok(u64_le(buf, off)? as i64)
}

pub fn u48_le(buf: &[u8], off: usize) -> Result<u64, ParseError> {
    let end = off + 6;
    if end > buf.len() {
        return Err(ParseError::OutOfBounds { off, len: 6, total: buf.len() });
    }
    let mut v: u64 = 0;
    for i in 0..6 {
        v |= (buf[off + i] as u64) << (8 * i);
    }
    Ok(v)
}

pub fn utf16le_string(buf: &[u8], off: usize, char_count: usize) -> Result<String, ParseError> {
    let byte_len = char_count * 2;
    let end = off + byte_len;
    if end > buf.len() {
        return Err(ParseError::OutOfBounds { off, len: byte_len, total: buf.len() });
    }
    let mut units = Vec::with_capacity(char_count);
    let mut i = off;
    while i < end {
        units.push(u16::from_le_bytes([buf[i], buf[i + 1]]));
        i += 2;
    }
    Ok(String::from_utf16_lossy(&units))
}
