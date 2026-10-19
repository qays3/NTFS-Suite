use crate::error::ParseError;
use crate::util::bytes::u16_le;

pub const SECTOR_SIZE: usize = 512;

pub fn apply_fixup(
    record: &mut [u8],
    fixup_offset: usize,
    fixup_count: usize,
) -> Result<(), ParseError> {
    if fixup_count == 0 {
        return Ok(());
    }
    let usn = u16_le(record, fixup_offset)?;
    let sectors = fixup_count - 1;
    for sector in 0..sectors {
        let array_off = fixup_offset + 2 + sector * 2;
        let replacement = u16_le(record, array_off)?;
        let tail = (sector + 1) * SECTOR_SIZE - 2;
        if tail + 2 > record.len() {
            return Err(ParseError::OutOfBounds { off: tail, len: 2, total: record.len() });
        }
        let present = u16::from_le_bytes([record[tail], record[tail + 1]]);
        if present != usn {
            return Err(ParseError::FixupMismatch { sector });
        }
        let bytes = replacement.to_le_bytes();
        record[tail] = bytes[0];
        record[tail + 1] = bytes[1];
    }
    Ok(())
}
