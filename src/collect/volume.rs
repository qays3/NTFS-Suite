//! Volume enumeration and opening for live collection.
//!
//! The live read path is Windows only (raw `\\.\X:` device handles, which need
//! Administrator and the backup privilege). The code compiles on every platform
//! so the parsing logic in the parent module stays testable; on non-Windows
//! `list_volumes` returns an empty list and `open_volume` returns an error.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use super::{BlockReader, BootSector, Collector, CollectError};

/// Summary of a volume we could collect from.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VolumeInfo {
    pub letter: String,
    pub device_path: String,
    pub filesystem: String,
    pub bytes_per_sector: u32,
    pub cluster_size: u64,
    pub record_size: usize,
    pub total_bytes: u64,
    pub readable: bool,
}

/// A [`BlockReader`] that satisfies arbitrary offset/length reads from a raw
/// device handle by issuing sector-aligned reads underneath. Raw volume handles
/// on Windows only accept aligned I/O, so we round the window out to the sector
/// size and copy the requested slice back out.
pub struct AlignedReader<T: Read + Seek> {
    inner: T,
    block: u64,
}

impl<T: Read + Seek> AlignedReader<T> {
    pub fn new(inner: T, block: u64) -> AlignedReader<T> {
        let block = if block == 0 { 512 } else { block };
        AlignedReader { inner, block }
    }
}

impl<T: Read + Seek> BlockReader for AlignedReader<T> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let block = self.block;
        let start = (offset / block) * block;
        let end = offset + buf.len() as u64;
        let aligned_end = end.div_ceil(block) * block;
        let span = (aligned_end - start) as usize;
        let mut window = vec![0u8; span];
        self.inner.seek(SeekFrom::Start(start))?;
        self.inner.read_exact(&mut window)?;
        let inner_off = (offset - start) as usize;
        buf.copy_from_slice(&window[inner_off..inner_off + buf.len()]);
        Ok(())
    }
}

/// Enumerate NTFS volumes by probing drive letters A:..Z: and reading each boot
/// sector. Non-Windows targets return an empty list.
pub fn list_volumes() -> Vec<VolumeInfo> {
    if !cfg!(windows) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for c in b'A'..=b'Z' {
        let letter = format!("{}:", c as char);
        let device_path = format!("\\\\.\\{}:", c as char);
        match probe_volume(&device_path, &letter) {
            Some(info) => out.push(info),
            None => {}
        }
    }
    out
}

fn probe_volume(device_path: &str, letter: &str) -> Option<VolumeInfo> {
    let mut file = open_device(device_path).ok()?;
    let mut boot = [0u8; 512];
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_exact(&mut boot).ok()?;
    let bs = BootSector::parse(&boot).ok()?;
    // total sectors live at 0x28 (8 bytes)
    let total_sectors = u64::from_le_bytes([
        boot[0x28], boot[0x29], boot[0x2A], boot[0x2B], boot[0x2C], boot[0x2D], boot[0x2E],
        boot[0x2F],
    ]);
    Some(VolumeInfo {
        letter: letter.to_string(),
        device_path: device_path.to_string(),
        filesystem: "NTFS".to_string(),
        bytes_per_sector: bs.bytes_per_sector,
        cluster_size: bs.cluster_size(),
        record_size: bs.record_size,
        total_bytes: total_sectors * bs.bytes_per_sector as u64,
        readable: true,
    })
}

#[cfg(windows)]
fn open_device(path: &str) -> io::Result<File> {
    // std sets FILE_SHARE_READ|WRITE|DELETE, which is what a live volume needs.
    std::fs::OpenOptions::new().read(true).open(path)
}

#[cfg(not(windows))]
fn open_device(_path: &str) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "live volume collection is only supported on Windows",
    ))
}

/// Open a volume for collection given a drive letter like "C" or "C:".
pub fn open_volume(letter: &str) -> Result<Collector<AlignedReader<File>>, CollectError> {
    let c = letter.trim().trim_end_matches(':');
    if c.len() != 1 {
        return Err(CollectError::BadBootSector("drive letter"));
    }
    let device_path = format!("\\\\.\\{}:", c);
    let mut file = open_device(&device_path)?;
    // Determine sector size first for alignment.
    let mut boot = [0u8; 512];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut boot)?;
    let bs = BootSector::parse(&boot)?;
    // Reopen a fresh handle for the aligned reader so its cursor is clean.
    let handle = open_device(&device_path)?;
    let reader = AlignedReader::new(handle, bs.bytes_per_sector as u64);
    Collector::open(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn aligned_reader_services_unaligned_reads() {
        let mut data = vec![0u8; 2048];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut r = AlignedReader::new(Cursor::new(data.clone()), 512);
        // unaligned offset + unaligned length
        let mut buf = [0u8; 300];
        r.read_at(600, &mut buf).unwrap();
        assert_eq!(&buf[..], &data[600..900]);
        // exactly one record at a 1024 boundary
        let mut rec = [0u8; 1024];
        r.read_at(1024, &mut rec).unwrap();
        assert_eq!(&rec[..], &data[1024..2048]);
    }

    #[test]
    fn list_volumes_empty_off_windows() {
        if !cfg!(windows) {
            assert!(list_volumes().is_empty());
        }
    }
}
