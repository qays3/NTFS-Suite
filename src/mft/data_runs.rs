use crate::error::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRun {
    pub length_clusters: u64,
    pub start_lcn: Option<i64>,
}

pub fn parse_data_runs(buf: &[u8]) -> Result<Vec<DataRun>, ParseError> {
    let mut runs = Vec::new();
    let mut i = 0usize;
    let mut current_lcn: i64 = 0;
    while i < buf.len() {
        let header = buf[i];
        if header == 0x00 {
            break;
        }
        let length_size = (header & 0x0F) as usize;
        let offset_size = (header >> 4) as usize;
        if length_size == 0 || length_size > 8 || offset_size > 8 {
            return Err(ParseError::InvalidRunHeader { byte: header });
        }
        i += 1;
        if i + length_size + offset_size > buf.len() {
            return Err(ParseError::OutOfBounds {
                off: i,
                len: length_size + offset_size,
                total: buf.len(),
            });
        }
        let length = read_unsigned(&buf[i..i + length_size]);
        i += length_size;
        let start_lcn = if offset_size == 0 {
            None
        } else {
            let delta = read_signed(&buf[i..i + offset_size]);
            i += offset_size;
            current_lcn += delta;
            Some(current_lcn)
        };
        runs.push(DataRun { length_clusters: length, start_lcn });
    }
    Ok(runs)
}

fn read_unsigned(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for (i, b) in bytes.iter().enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    v
}

fn read_signed(bytes: &[u8]) -> i64 {
    let mut v: u64 = 0;
    for (i, b) in bytes.iter().enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    let bits = bytes.len() * 8;
    let sign_bit = 1u64 << (bits - 1);
    if v & sign_bit != 0 {
        let mask = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
        (v | !mask) as i64
    } else {
        v as i64
    }
}
