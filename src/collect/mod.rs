//! Raw-volume NTFS collection.
//!
//! Reads the key NTFS metafiles ($MFT, $UsnJrnl:$J, $Secure:$SDS) straight
//! off a live volume by walking the boot sector and the $MFT's own data runs,
//! then writing each stream out to a folder (or into a case vault).
//!
//! All I/O goes through the [`BlockReader`] trait so the boot-sector parsing,
//! data-run mapping and stream extraction are unit-testable against an
//! in-memory synthetic volume. The live Windows path ([`VolumeReader`]) only
//! implements `read_at`; everything else is platform independent.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::mft::attributes::data::{DataAttr, DataContent};
use crate::mft::attributes::{TYPE_ATTRIBUTE_LIST, TYPE_DATA};
use crate::mft::data_runs::{parse_data_runs, DataRun};
use crate::mft::fixup::apply_fixup;
use crate::mft::header::{base_entry, RecordHeader};
use crate::mft::record::MftRecord;
use crate::util::bytes::{u16_le, u32_le, u64_le, utf16le_string};

pub mod volume;

/// Record numbers of the fixed NTFS metafiles.
pub const REC_MFT: u64 = 0;
pub const REC_SECURE: u64 = 9;
pub const REC_EXTEND: u64 = 11;

/// What a collect job can pull off a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Mft,
    UsnJrnl,
    Secure,
}

impl Target {
    pub fn id(self) -> &'static str {
        match self {
            Target::Mft => "mft",
            Target::UsnJrnl => "usnjrnl",
            Target::Secure => "secure",
        }
    }

    /// File name used when writing the stream to the output folder.
    pub fn out_name(self) -> &'static str {
        match self {
            Target::Mft => "$MFT",
            Target::UsnJrnl => "$UsnJrnl_$J",
            Target::Secure => "$Secure_$SDS",
        }
    }

    pub fn from_id(id: &str) -> Option<Target> {
        match id {
            "mft" => Some(Target::Mft),
            "usnjrnl" => Some(Target::UsnJrnl),
            "secure" => Some(Target::Secure),
            _ => None,
        }
    }

    pub fn all() -> [Target; 3] {
        [Target::Mft, Target::UsnJrnl, Target::Secure]
    }
}

#[derive(Debug)]
pub enum CollectError {
    Io(io::Error),
    BadBootSector(&'static str),
    Parse(crate::error::ParseError),
    NotFound(&'static str),
    NoRuns(&'static str),
}

impl std::fmt::Display for CollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectError::Io(e) => write!(f, "io error: {e}"),
            CollectError::BadBootSector(m) => write!(f, "bad boot sector: {m}"),
            CollectError::Parse(e) => write!(f, "parse error: {e}"),
            CollectError::NotFound(m) => write!(f, "metafile not found: {m}"),
            CollectError::NoRuns(m) => write!(f, "stream has no data runs: {m}"),
        }
    }
}

impl std::error::Error for CollectError {}

impl From<io::Error> for CollectError {
    fn from(e: io::Error) -> Self {
        CollectError::Io(e)
    }
}

impl From<crate::error::ParseError> for CollectError {
    fn from(e: crate::error::ParseError) -> Self {
        CollectError::Parse(e)
    }
}

/// Random-access read over a volume's byte space.
pub trait BlockReader {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

/// NTFS boot sector / BIOS parameter block, the fields we need.
#[derive(Debug, Clone, Copy)]
pub struct BootSector {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub mft_lcn: u64,
    pub record_size: usize,
}

impl BootSector {
    pub fn cluster_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    pub fn mft_offset(&self) -> u64 {
        self.mft_lcn * self.cluster_size()
    }

    /// Parse the first 512+ bytes of the volume.
    pub fn parse(boot: &[u8]) -> Result<BootSector, CollectError> {
        if boot.len() < 0x54 {
            return Err(CollectError::BadBootSector("short"));
        }
        if &boot[3..11] != b"NTFS    " {
            return Err(CollectError::BadBootSector("not NTFS (OEM id)"));
        }
        let bytes_per_sector = u16::from_le_bytes([boot[0x0B], boot[0x0C]]) as u32;
        if bytes_per_sector == 0 || bytes_per_sector % 512 != 0 {
            return Err(CollectError::BadBootSector("bytes per sector"));
        }
        let sectors_per_cluster = decode_power_byte(boot[0x0D]);
        if sectors_per_cluster == 0 {
            return Err(CollectError::BadBootSector("sectors per cluster"));
        }
        let mft_lcn = u64::from_le_bytes([
            boot[0x30], boot[0x31], boot[0x32], boot[0x33], boot[0x34], boot[0x35], boot[0x36],
            boot[0x37],
        ]);
        let cluster_size = bytes_per_sector as u64 * sectors_per_cluster as u64;
        let record_size = decode_record_size(boot[0x40] as i8, cluster_size);
        if record_size == 0 || record_size > 1 << 20 {
            return Err(CollectError::BadBootSector("record size"));
        }
        Ok(BootSector { bytes_per_sector, sectors_per_cluster, mft_lcn, record_size })
    }
}

/// NTFS "clusters-per-X" byte: positive is a literal count; a negative i8 `n`
/// means 2^(-n) bytes.
fn decode_record_size(raw: i8, cluster_size: u64) -> usize {
    if raw > 0 {
        (raw as u64 * cluster_size) as usize
    } else {
        let shift = (-(raw as i32)) as u32;
        if shift < 64 {
            (1u64 << shift) as usize
        } else {
            0
        }
    }
}

/// sectors-per-cluster byte: positive literal, or `2^(256-b)` for a large b.
fn decode_power_byte(b: u8) -> u32 {
    if b <= 0x80 {
        b as u32
    } else {
        let shift = 0x100u32 - b as u32;
        if shift < 32 {
            1u32 << shift
        } else {
            0
        }
    }
}

/// A resolved sequence of data runs plus the stream's real (logical) size.
#[derive(Debug, Clone)]
pub struct StreamMap {
    pub runs: Vec<DataRun>,
    pub real_size: u64,
    pub cluster_size: u64,
}

impl StreamMap {
    /// Total allocated byte length across all runs.
    pub fn allocated(&self) -> u64 {
        self.runs.iter().map(|r| r.length_clusters * self.cluster_size).sum()
    }

    /// Write the whole stream to `sink`, materialising sparse runs as zeros and
    /// truncating the output to `real_size`. Returns bytes written.
    pub fn extract<R: BlockReader, W: Write>(
        &self,
        reader: &mut R,
        sink: &mut W,
    ) -> Result<u64, CollectError> {
        let mut written: u64 = 0;
        let limit = self.real_size;
        let cs = self.cluster_size;
        let mut scratch = vec![0u8; cs as usize];
        for run in &self.runs {
            let run_bytes = run.length_clusters * cs;
            match run.start_lcn {
                Some(lcn) if lcn >= 0 => {
                    let mut phys = lcn as u64 * cs;
                    let mut remaining = run_bytes;
                    while remaining > 0 && written < limit {
                        let chunk = remaining.min(cs);
                        let take = chunk.min(limit - written) as usize;
                        let buf = &mut scratch[..chunk as usize];
                        reader.read_at(phys, buf)?;
                        sink.write_all(&buf[..take])?;
                        written += take as u64;
                        phys += chunk;
                        remaining -= chunk;
                    }
                }
                _ => {
                    // sparse / unallocated: emit zeros so stream offsets stay aligned
                    let mut remaining = run_bytes;
                    for b in scratch.iter_mut() {
                        *b = 0;
                    }
                    while remaining > 0 && written < limit {
                        let chunk = remaining.min(cs);
                        let take = chunk.min(limit - written) as usize;
                        sink.write_all(&scratch[..take])?;
                        written += take as u64;
                        remaining -= chunk;
                    }
                }
            }
            if written >= limit {
                break;
            }
        }
        Ok(written)
    }

    /// Read `len` bytes starting at logical offset `off` within the stream.
    fn read_logical<R: BlockReader>(
        &self,
        reader: &mut R,
        off: u64,
        len: usize,
    ) -> Result<Vec<u8>, CollectError> {
        let mut out = vec![0u8; len];
        let cs = self.cluster_size;
        let mut filled = 0usize;
        let mut cursor = 0u64; // logical byte position at start of current run
        for run in &self.runs {
            let run_bytes = run.length_clusters * cs;
            let run_end = cursor + run_bytes;
            if off + len as u64 <= cursor {
                break;
            }
            if off < run_end {
                // overlap region
                let region_start = off.max(cursor);
                let region_end = (off + len as u64).min(run_end);
                let within = region_start - cursor; // offset within run
                let count = (region_end - region_start) as usize;
                match run.start_lcn {
                    Some(lcn) if lcn >= 0 => {
                        let phys = lcn as u64 * cs + within;
                        reader.read_at(phys, &mut out[filled..filled + count])?;
                    }
                    _ => {
                        for b in &mut out[filled..filled + count] {
                            *b = 0;
                        }
                    }
                }
                filled += count;
                if filled >= len {
                    break;
                }
            }
            cursor = run_end;
        }
        Ok(out)
    }
}

/// Build a [`StreamMap`] from an unnamed or named $DATA attribute.
pub fn stream_map_from_data(
    data: &DataAttr,
    cluster_size: u64,
) -> Result<StreamMap, CollectError> {
    match &data.content {
        DataContent::NonResident { real_size, runs, .. } => Ok(StreamMap {
            runs: runs.clone(),
            real_size: *real_size,
            cluster_size,
        }),
        DataContent::Resident(bytes) => Ok(StreamMap {
            // represent a resident stream as a single inline run we can't map;
            // callers handle resident separately, but keep real_size for info.
            runs: Vec::new(),
            real_size: bytes.len() as u64,
            cluster_size,
        }),
    }
}

/// The collect engine: reads the boot sector and the $MFT run list, then can
/// extract the requested metafiles.
pub struct Collector<R: BlockReader> {
    reader: R,
    boot: BootSector,
    mft_map: StreamMap,
}

impl<R: BlockReader> Collector<R> {
    /// Open a volume: parse its boot sector, then self-reference $MFT record 0
    /// to learn the full $MFT layout.
    pub fn open(mut reader: R) -> Result<Collector<R>, CollectError> {
        let mut boot_buf = vec![0u8; 512];
        reader.read_at(0, &mut boot_buf)?;
        let boot = BootSector::parse(&boot_buf)?;

        // Read $MFT record 0 at mft_lcn.
        let mut rec0 = vec![0u8; boot.record_size];
        reader.read_at(boot.mft_offset(), &mut rec0)?;
        let record = MftRecord::parse(&rec0)?;
        let unnamed = unnamed_data(&record)
            .ok_or(CollectError::NoRuns("$MFT record 0 has no unnamed $DATA"))?;
        let mft_map = stream_map_from_data(unnamed, boot.cluster_size())?;
        if mft_map.runs.is_empty() {
            return Err(CollectError::NoRuns("$MFT is resident?!"));
        }
        Ok(Collector { reader, boot, mft_map })
    }

    pub fn boot(&self) -> &BootSector {
        &self.boot
    }

    pub fn mft_map(&self) -> &StreamMap {
        &self.mft_map
    }

    /// Read MFT record `n` by mapping its logical offset through the $MFT runs.
    pub fn read_record(&mut self, n: u64) -> Result<MftRecord, CollectError> {
        let size = self.boot.record_size;
        let off = n * size as u64;
        let raw = self.mft_map.read_logical(&mut self.reader, off, size)?;
        let record = MftRecord::parse(&raw)?;
        Ok(record)
    }

    /// Extract the $MFT itself to `sink`.
    pub fn extract_mft<W: Write>(&mut self, sink: &mut W) -> Result<u64, CollectError> {
        let map = self.mft_map.clone();
        map.extract(&mut self.reader, sink)
    }

    /// Extract $Secure's $SDS named $DATA stream.
    pub fn extract_secure<W: Write>(&mut self, sink: &mut W) -> Result<u64, CollectError> {
        self.extract_named_data(REC_SECURE, "$SDS", "$Secure:$SDS", sink)
    }

    /// Locate the $UsnJrnl record (child of $Extend) and extract its $J stream.
    pub fn extract_usnjrnl<W: Write>(&mut self, sink: &mut W) -> Result<u64, CollectError> {
        let rec_num = self
            .find_usnjrnl_record()?
            .ok_or(CollectError::NotFound("$UsnJrnl (change journal not present)"))?;
        self.extract_named_data(rec_num, "$J", "$UsnJrnl:$J", sink)
    }

    /// Extract a named $DATA stream from a record, following its $ATTRIBUTE_LIST
    /// into extension records when the stream's runs are spread across several
    /// MFT records (common for a large $Secure:$SDS or $UsnJrnl:$J).
    fn extract_named_data<W: Write>(
        &mut self,
        base_rec: u64,
        name: &str,
        label: &'static str,
        sink: &mut W,
    ) -> Result<u64, CollectError> {
        let frags = self.data_fragments(base_rec, name)?;
        if frags.is_empty() {
            return Err(CollectError::NotFound(label));
        }
        // A single resident fragment (tiny volume): write its bytes directly.
        if frags.len() == 1 {
            if let Some(bytes) = &frags[0].resident {
                sink.write_all(bytes)?;
                return Ok(bytes.len() as u64);
            }
        }
        let mut ordered = frags;
        ordered.sort_by_key(|f| f.start_vcn);
        let real_size = ordered.iter().map(|f| f.real_size).max().unwrap_or(0);
        let mut runs = Vec::new();
        for f in &ordered {
            runs.extend(f.runs.iter().cloned());
        }
        if runs.is_empty() {
            return Err(CollectError::NoRuns(label));
        }
        let map = StreamMap { runs, real_size, cluster_size: self.boot.cluster_size() };
        map.extract(&mut self.reader, sink)
    }

    /// Read record `n`, apply its fixups, and return the header plus fixed bytes.
    fn read_record_fixed(&mut self, n: u64) -> Result<(RecordHeader, Vec<u8>), CollectError> {
        let size = self.boot.record_size;
        let off = n * size as u64;
        let mut raw = self.mft_map.read_logical(&mut self.reader, off, size)?;
        let header = RecordHeader::parse(&raw)?;
        let _ = apply_fixup(&mut raw, header.fixup_offset as usize, header.fixup_count as usize);
        Ok((header, raw))
    }

    /// Gather every fragment of a named $DATA stream, following an attribute list.
    fn data_fragments(&mut self, base_rec: u64, want_name: &str) -> Result<Vec<Frag>, CollectError> {
        let (header, rec) = self.read_record_fixed(base_rec)?;
        let first = header.first_attribute_offset as usize;
        let mut frags = Vec::new();
        let mut attr_list: Option<(usize, bool)> = None;
        collect_data_frags(&rec, first, want_name, &mut frags, &mut attr_list);

        if let Some((aoff, anon)) = attr_list {
            let bytes = self.read_attr_list_bytes(&rec, aoff, anon)?;
            for rn in attr_list_refs(&bytes, TYPE_DATA, want_name, base_rec) {
                if let Ok((h2, erec)) = self.read_record_fixed(rn) {
                    let f2 = h2.first_attribute_offset as usize;
                    let mut ignore = None;
                    collect_data_frags(&erec, f2, want_name, &mut frags, &mut ignore);
                }
            }
        }
        Ok(frags)
    }

    /// Return the raw bytes of an $ATTRIBUTE_LIST attribute, resident or not.
    fn read_attr_list_bytes(
        &mut self,
        rec: &[u8],
        off: usize,
        non_resident: bool,
    ) -> Result<Vec<u8>, CollectError> {
        if !non_resident {
            let clen = u32_le(rec, off + 0x10)? as usize;
            let coff = u16_le(rec, off + 0x14)? as usize;
            let s = off + coff;
            let e = s + clen;
            return Ok(if e <= rec.len() { rec[s..e].to_vec() } else { Vec::new() });
        }
        let real_size = u64_le(rec, off + 0x30)?;
        let runs_off = u16_le(rec, off + 0x20)? as usize;
        let total = u32_le(rec, off + 4)? as usize;
        let rs = off + runs_off;
        let re = off + total;
        let runs = if rs < re && re <= rec.len() {
            parse_data_runs(&rec[rs..re])?
        } else {
            Vec::new()
        };
        let map = StreamMap { runs, real_size, cluster_size: self.boot.cluster_size() };
        let mut buf = Vec::new();
        map.extract(&mut self.reader, &mut buf)?;
        Ok(buf)
    }

    /// Scan the low MFT records for a file named "$UsnJrnl" whose parent is
    /// $Extend (record 11). The journal lives in \$Extend\$UsnJrnl.
    pub fn find_usnjrnl_record(&mut self) -> Result<Option<u64>, CollectError> {
        // $UsnJrnl is one of the first few user/system records; scan a bounded
        // window so a damaged volume can't make us walk millions of entries.
        for n in 12..64u64 {
            let rec = match self.read_record(n) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if !rec.in_use() {
                continue;
            }
            // Match on the file name and $Extend parent. The $J data stream may
            // live in extension records (attribute list), so don't require it in
            // the base record here; data_fragments resolves it later.
            let is_usn = rec.file_names().iter().any(|fnm| {
                fnm.name.eq_ignore_ascii_case("$UsnJrnl")
                    && fnm.parent_entry == REC_EXTEND
            });
            if is_usn {
                return Ok(Some(n));
            }
        }
        Ok(None)
    }
}

/// First unnamed $DATA attribute of a record.
fn unnamed_data(record: &MftRecord) -> Option<&DataAttr> {
    record.data_streams().into_iter().find(|d| d.name.is_none())
}

/// One fragment of a (possibly split) named $DATA stream.
struct Frag {
    start_vcn: u64,
    real_size: u64,
    runs: Vec<DataRun>,
    resident: Option<Vec<u8>>,
}

/// Walk a fixed record's attributes, pushing every $DATA fragment whose name
/// matches `want_name`, and noting the first $ATTRIBUTE_LIST location.
fn collect_data_frags(
    rec: &[u8],
    first: usize,
    want_name: &str,
    frags: &mut Vec<Frag>,
    attr_list: &mut Option<(usize, bool)>,
) {
    let mut off = first;
    loop {
        if off + 4 > rec.len() {
            break;
        }
        let type_id = match u32_le(rec, off) {
            Ok(v) => v,
            Err(_) => break,
        };
        if type_id == 0xFFFF_FFFF {
            break;
        }
        if off + 16 > rec.len() {
            break;
        }
        let total = match u32_le(rec, off + 4) {
            Ok(v) => v as usize,
            Err(_) => break,
        };
        if total < 16 || off + total > rec.len() {
            break;
        }
        let non_res = rec[off + 8] != 0;
        let name_len = rec[off + 9] as usize;
        let name_off = u16_le(rec, off + 10).unwrap_or(0) as usize;
        let name = if name_len > 0 {
            utf16le_string(rec, off + name_off, name_len).ok()
        } else {
            None
        };
        if type_id == TYPE_DATA
            && name
                .as_deref()
                .map(|n| n.eq_ignore_ascii_case(want_name))
                .unwrap_or(false)
        {
            if let Some(f) = frag_from_attr(rec, off, non_res) {
                frags.push(f);
            }
        }
        if type_id == TYPE_ATTRIBUTE_LIST && attr_list.is_none() {
            *attr_list = Some((off, non_res));
        }
        off += total;
    }
}

/// Build a fragment from a $DATA attribute at `off`.
fn frag_from_attr(rec: &[u8], off: usize, non_resident: bool) -> Option<Frag> {
    if non_resident {
        let start_vcn = u64_le(rec, off + 0x10).ok()?;
        let real_size = u64_le(rec, off + 0x30).ok()?;
        let runs_off = u16_le(rec, off + 0x20).ok()? as usize;
        let total = u32_le(rec, off + 4).ok()? as usize;
        let rs = off + runs_off;
        let re = off + total;
        let runs = if rs < re && re <= rec.len() {
            parse_data_runs(&rec[rs..re]).ok()?
        } else {
            Vec::new()
        };
        Some(Frag { start_vcn, real_size, runs, resident: None })
    } else {
        let clen = u32_le(rec, off + 0x10).ok()? as usize;
        let coff = u16_le(rec, off + 0x14).ok()? as usize;
        let s = off + coff;
        let e = s + clen;
        let bytes = if e <= rec.len() { rec[s..e].to_vec() } else { Vec::new() };
        let len = bytes.len() as u64;
        Some(Frag { start_vcn: 0, real_size: len, runs: Vec::new(), resident: Some(bytes) })
    }
}

/// Parse $ATTRIBUTE_LIST entries, returning the distinct extension record
/// numbers that hold the wanted attribute (type + name), skipping `skip`.
fn attr_list_refs(bytes: &[u8], want_type: u32, want_name: &str, skip: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 26 <= bytes.len() {
        let type_id = match u32_le(bytes, i) {
            Ok(v) => v,
            Err(_) => break,
        };
        if type_id == 0xFFFF_FFFF {
            break;
        }
        let rec_len = u16_le(bytes, i + 4).unwrap_or(0) as usize;
        if rec_len < 26 {
            break;
        }
        let name_len = bytes[i + 6] as usize;
        let name_off = bytes[i + 7] as usize;
        let base_ref = u64_le(bytes, i + 16).unwrap_or(0);
        let name = if name_len > 0 {
            utf16le_string(bytes, i + name_off, name_len).ok()
        } else {
            None
        };
        if type_id == want_type
            && name
                .as_deref()
                .map(|n| n.eq_ignore_ascii_case(want_name))
                .unwrap_or(false)
        {
            let rn = base_entry(base_ref);
            if rn != skip && !out.contains(&rn) {
                out.push(rn);
            }
        }
        i += rec_len;
    }
    out
}

/// A [`BlockReader`] backed by a file/device handle (the live Windows path and
/// also any seekable file, used in tests via a temp file).
pub struct HandleReader<T: Read + Seek> {
    inner: T,
}

impl<T: Read + Seek> HandleReader<T> {
    pub fn new(inner: T) -> HandleReader<T> {
        HandleReader { inner }
    }
}

impl<T: Read + Seek> BlockReader for HandleReader<T> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner.read_exact(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_record_size_byte() {
        // negative i8 -> 2^(-n)
        assert_eq!(decode_record_size(-10, 4096), 1024);
        assert_eq!(decode_record_size(-12, 65536), 4096);
        // positive -> clusters * cluster_size
        assert_eq!(decode_record_size(1, 1024), 1024);
        assert_eq!(decode_record_size(2, 512), 1024);
    }

    #[test]
    fn decodes_sectors_per_cluster() {
        assert_eq!(decode_power_byte(8), 8);
        assert_eq!(decode_power_byte(0x80), 0x80);
        // 0xF4 = -12 -> 2^12
        assert_eq!(decode_power_byte(0xF4), 4096);
    }

    /// In-memory volume for round-trip tests.
    struct MemVol {
        bytes: Vec<u8>,
    }
    impl BlockReader for MemVol {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.bytes.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "past end"));
            }
            buf.copy_from_slice(&self.bytes[start..end]);
            Ok(())
        }
    }

    #[test]
    fn stream_map_extracts_contiguous_and_sparse() {
        let cs = 4u64; // tiny 4-byte clusters for the test
        // volume: cluster 0 = boot-ish, clusters 2..4 hold "ABCDEFGH"
        let mut vol = vec![0u8; 64];
        vol[8..16].copy_from_slice(b"ABCDEFGH"); // physical bytes at lcn 2 (2*4=8)
        let mut reader = MemVol { bytes: vol };

        // one data run: 2 clusters at lcn 2 (8 real bytes), then skip
        let map = StreamMap {
            runs: vec![DataRun { length_clusters: 2, start_lcn: Some(2) }],
            real_size: 8,
            cluster_size: cs,
        };
        let mut out = Vec::new();
        let n = map.extract(&mut reader, &mut out).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&out, b"ABCDEFGH");

        // sparse leading run of 1 cluster (zeros) then real data, real_size 6
        let map2 = StreamMap {
            runs: vec![
                DataRun { length_clusters: 1, start_lcn: None },
                DataRun { length_clusters: 2, start_lcn: Some(2) },
            ],
            real_size: 6,
            cluster_size: cs,
        };
        let mut out2 = Vec::new();
        let n2 = map2.extract(&mut reader, &mut out2).unwrap();
        assert_eq!(n2, 6);
        assert_eq!(&out2, &[0, 0, 0, 0, b'A', b'B']);
    }

    fn al_entry(type_id: u32, name: &str, rec_ref: u64) -> Vec<u8> {
        let name_u16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let name_off = 0x1Au8;
        let mut e = vec![0u8; 0x1A];
        e[0..4].copy_from_slice(&type_id.to_le_bytes());
        e[6] = name.chars().count() as u8;
        e[7] = name_off;
        e[16..24].copy_from_slice(&rec_ref.to_le_bytes());
        e.extend_from_slice(&name_u16);
        while e.len() % 8 != 0 {
            e.push(0);
        }
        let len = e.len() as u16;
        e[4..6].copy_from_slice(&len.to_le_bytes());
        e
    }

    #[test]
    fn attr_list_refs_finds_named_data_extension() {
        let mut buf = Vec::new();
        buf.extend(al_entry(0x10, "", 9)); // $STANDARD_INFORMATION in base
        buf.extend(al_entry(0x80, "$SDS", 20)); // $DATA:$SDS in record 20
        buf.extend(al_entry(0x80, "$SDS", 20)); // second fragment, same record
        buf.extend(al_entry(0x80, "$SII", 21)); // index, different name
        let refs = attr_list_refs(&buf, TYPE_DATA, "$SDS", 9);
        assert_eq!(refs, vec![20]);
        // skip filters out the base record
        let refs2 = attr_list_refs(&buf, TYPE_DATA, "$SDS", 20);
        assert!(refs2.is_empty());
    }

    #[test]
    fn read_logical_spans_runs() {
        let cs = 4u64;
        let mut vol = vec![0u8; 64];
        vol[8..12].copy_from_slice(b"WXYZ"); // lcn 2
        vol[20..24].copy_from_slice(b"1234"); // lcn 5
        let mut reader = MemVol { bytes: vol };
        let map = StreamMap {
            runs: vec![
                DataRun { length_clusters: 1, start_lcn: Some(2) },
                DataRun { length_clusters: 1, start_lcn: Some(5) },
            ],
            real_size: 8,
            cluster_size: cs,
        };
        // read across the run boundary: last 2 of run0 + first 2 of run1
        let got = map.read_logical(&mut reader, 2, 4).unwrap();
        assert_eq!(&got, b"YZ12");
    }
}
