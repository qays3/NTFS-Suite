pub mod attributes;
pub mod data_runs;
pub mod fixup;
pub mod header;
pub mod path_resolver;
pub mod record;
pub mod stream;

use std::collections::HashMap;

use crate::error::ParseError;
use header::RecordHeader;
use record::MftRecord;

pub const DEFAULT_RECORD_SIZE: usize = 1024;

pub struct MftTable {
    pub records: HashMap<u64, MftRecord>,
    pub record_size: usize,
    pub baad_count: usize,
    pub parse_errors: usize,
}

impl MftTable {
    pub fn parse(data: &[u8]) -> Result<MftTable, ParseError> {
        let record_size = detect_record_size(data);
        let mut records = HashMap::new();
        let mut baad_count = 0;
        let mut parse_errors = 0;
        let mut offset = 0;
        while offset + record_size <= data.len() {
            let slice = &data[offset..offset + record_size];
            if &slice[0..4] != b"FILE" && &slice[0..4] != b"BAAD" {
                offset += record_size;
                continue;
            }
            match MftRecord::parse(slice) {
                Ok(record) => {
                    if record.header.is_baad() {
                        baad_count += 1;
                    }
                    let number = resolve_record_number(&record.header, offset, record_size);
                    records.insert(number, record);
                }
                Err(_) => {
                    parse_errors += 1;
                }
            }
            offset += record_size;
        }
        Ok(MftTable { records, record_size, baad_count, parse_errors })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

fn resolve_record_number(header: &RecordHeader, offset: usize, record_size: usize) -> u64 {
    if header.record_number != 0 || offset == 0 {
        header.record_number as u64
    } else {
        (offset / record_size) as u64
    }
}

fn detect_record_size(data: &[u8]) -> usize {
    if data.len() >= 4096 + 4 && &data[4096..4100] == b"FILE" {
        if data.len() >= 1024 + 4 && &data[1024..1028] == b"FILE" {
            return DEFAULT_RECORD_SIZE;
        }
        return 4096;
    }
    DEFAULT_RECORD_SIZE
}
