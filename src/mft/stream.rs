use std::io::{Read, Seek, SeekFrom};

use crate::error::ParseError;
use crate::mft::record::MftRecord;
use crate::mft::DEFAULT_RECORD_SIZE;

pub fn detect_record_size_reader<R: Read + Seek>(reader: &mut R) -> Result<usize, ParseError> {
    let mut probe = vec![0u8; 4100];
    let read = read_fill(reader, &mut probe);
    reader.seek(SeekFrom::Start(0)).ok();
    if read >= 4100 && &probe[4096..4100] == b"FILE" && &probe[1024..1028] != b"FILE" {
        Ok(4096)
    } else {
        Ok(DEFAULT_RECORD_SIZE)
    }
}

pub fn for_each_record<R, F>(
    reader: &mut R,
    record_size: usize,
    mut handler: F,
) -> Result<StreamStats, ParseError>
where
    R: Read,
    F: FnMut(u64, &MftRecord) -> bool,
{
    let mut stats = StreamStats::default();
    let mut buffer = vec![0u8; record_size];
    let mut index: u64 = 0;
    loop {
        let filled = read_fill(reader, &mut buffer);
        if filled == 0 {
            break;
        }
        if filled < record_size {
            break;
        }
        let signature = &buffer[0..4];
        if signature != b"FILE" && signature != b"BAAD" {
            index += 1;
            continue;
        }
        match MftRecord::parse(&buffer) {
            Ok(record) => {
                stats.parsed += 1;
                if record.header.is_baad() {
                    stats.baad += 1;
                }
                if !record.fixup_ok {
                    stats.fixup_failed += 1;
                }
                let number = if record.header.record_number != 0 {
                    record.header.record_number as u64
                } else {
                    index
                };
                if !handler(number, &record) {
                    stats.cancelled = true;
                    break;
                }
            }
            Err(_) => {
                stats.errors += 1;
            }
        }
        index += 1;
    }
    Ok(stats)
}

fn read_fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => break,
        }
    }
    filled
}

#[derive(Debug, Default, Clone, Copy)]
pub struct StreamStats {
    pub parsed: u64,
    pub baad: u64,
    pub fixup_failed: u64,
    pub errors: u64,
    pub cancelled: bool,
}
