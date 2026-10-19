pub const RECORD_SIZE: usize = 1024;
pub const FIXUP_OFFSET: usize = 0x30;
pub const FIRST_ATTR_OFFSET: usize = 0x38;
pub const USN: u16 = 0xABCD;

pub struct RecordBuilder {
    buf: Vec<u8>,
    attr_cursor: usize,
    next_attr_id: u16,
}

impl RecordBuilder {
    pub fn new(record_number: u32, sequence: u16, flags: u16) -> RecordBuilder {
        let mut buf = vec![0u8; RECORD_SIZE];
        buf[0..4].copy_from_slice(b"FILE");
        write_u16(&mut buf, 0x04, FIXUP_OFFSET as u16);
        write_u16(&mut buf, 0x06, 3);
        write_u64(&mut buf, 0x08, 0);
        write_u16(&mut buf, 0x10, sequence);
        write_u16(&mut buf, 0x12, 1);
        write_u16(&mut buf, 0x14, FIRST_ATTR_OFFSET as u16);
        write_u16(&mut buf, 0x16, flags);
        write_u32(&mut buf, 0x18, 0);
        write_u32(&mut buf, 0x1C, RECORD_SIZE as u32);
        write_u64(&mut buf, 0x20, 0);
        write_u16(&mut buf, 0x28, 0);
        write_u32(&mut buf, 0x2C, record_number);
        RecordBuilder { buf, attr_cursor: FIRST_ATTR_OFFSET, next_attr_id: 0 }
    }

    pub fn add_standard_information(
        mut self,
        created: u64,
        modified: u64,
        mft_modified: u64,
        accessed: u64,
        flags: u32,
    ) -> Self {
        let mut content = vec![0u8; 72];
        write_u64(&mut content, 0x00, created);
        write_u64(&mut content, 0x08, modified);
        write_u64(&mut content, 0x10, mft_modified);
        write_u64(&mut content, 0x18, accessed);
        write_u32(&mut content, 0x20, flags);
        self.write_resident(0x10, None, &content);
        self
    }

    pub fn add_file_name(
        mut self,
        parent_entry: u64,
        parent_sequence: u16,
        created: u64,
        modified: u64,
        mft_modified: u64,
        accessed: u64,
        real_size: u64,
        namespace: u8,
        name: &str,
    ) -> Self {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut content = vec![0u8; 0x42 + units.len() * 2];
        let parent_ref = (parent_entry & 0x0000_FFFF_FFFF_FFFF) | ((parent_sequence as u64) << 48);
        write_u64(&mut content, 0x00, parent_ref);
        write_u64(&mut content, 0x08, created);
        write_u64(&mut content, 0x10, modified);
        write_u64(&mut content, 0x18, mft_modified);
        write_u64(&mut content, 0x20, accessed);
        write_u64(&mut content, 0x28, real_size);
        write_u64(&mut content, 0x30, real_size);
        write_u32(&mut content, 0x38, 0);
        content[0x40] = units.len() as u8;
        content[0x41] = namespace;
        for (i, u) in units.iter().enumerate() {
            let b = u.to_le_bytes();
            content[0x42 + i * 2] = b[0];
            content[0x42 + i * 2 + 1] = b[1];
        }
        self.write_resident(0x30, None, &content);
        self
    }

    pub fn add_resident_data(mut self, name: Option<&str>, content: &[u8]) -> Self {
        self.write_resident(0x80, name, content);
        self
    }

    fn write_resident(&mut self, type_id: u32, name: Option<&str>, content: &[u8]) {
        let name_units: Vec<u16> = name.map(|n| n.encode_utf16().collect()).unwrap_or_default();
        let name_bytes = name_units.len() * 2;
        let header_len = 0x18;
        let name_off = if name_bytes > 0 { header_len } else { 0 };
        let content_off = round_up8(header_len + name_bytes);
        let total = round_up8(content_off + content.len());
        let off = self.attr_cursor;
        write_u32(&mut self.buf, off + 0x00, type_id);
        write_u32(&mut self.buf, off + 0x04, total as u32);
        self.buf[off + 0x08] = 0;
        self.buf[off + 0x09] = name_units.len() as u8;
        write_u16(&mut self.buf, off + 0x0A, name_off as u16);
        write_u16(&mut self.buf, off + 0x0C, 0);
        write_u16(&mut self.buf, off + 0x0E, self.next_attr_id);
        write_u32(&mut self.buf, off + 0x10, content.len() as u32);
        write_u16(&mut self.buf, off + 0x14, content_off as u16);
        for (i, u) in name_units.iter().enumerate() {
            let b = u.to_le_bytes();
            self.buf[off + name_off + i * 2] = b[0];
            self.buf[off + name_off + i * 2 + 1] = b[1];
        }
        self.buf[off + content_off..off + content_off + content.len()].copy_from_slice(content);
        self.attr_cursor = off + total;
        self.next_attr_id += 1;
    }

    pub fn build(mut self) -> Vec<u8> {
        write_u32(&mut self.buf, self.attr_cursor, 0xFFFF_FFFF);
        let used = round_up8(self.attr_cursor + 8);
        write_u32(&mut self.buf, 0x18, used as u32);
        apply_builder_fixup(&mut self.buf);
        self.buf
    }
}

fn apply_builder_fixup(buf: &mut [u8]) {
    let usn = USN.to_le_bytes();
    let real0 = [0x11u8, 0x22];
    let real1 = [0x33u8, 0x44];
    write_u16(buf, FIXUP_OFFSET, USN);
    buf[FIXUP_OFFSET + 2] = real0[0];
    buf[FIXUP_OFFSET + 3] = real0[1];
    buf[FIXUP_OFFSET + 4] = real1[0];
    buf[FIXUP_OFFSET + 5] = real1[1];
    buf[510] = usn[0];
    buf[511] = usn[1];
    buf[1022] = usn[0];
    buf[1023] = usn[1];
}

pub fn round_up8(v: usize) -> usize {
    (v + 7) & !7
}

pub fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    let b = v.to_le_bytes();
    buf[off] = b[0];
    buf[off + 1] = b[1];
}

pub fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    let b = v.to_le_bytes();
    buf[off..off + 4].copy_from_slice(&b);
}

pub fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    let b = v.to_le_bytes();
    buf[off..off + 8].copy_from_slice(&b);
}
