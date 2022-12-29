use std::fs;
use std::io::{Error, ErrorKind};
use std::string::FromUtf8Error;
use binary_reader::{BinaryReader, Endian};
use crate::dcx::DCX;
use crate::error::DantelionFormatsError;
use crate::util;
use crate::util::Validate;

#[repr(C)]
pub struct BND4 {
    pub header: BND4Header,
    pub files: Vec<File>,
    pub buckets: Option<BND4BucketHeader>,
}

#[repr(C)]
pub struct BND4Header {
    pub magic: String,
    pub unk04: u8,
    pub unk05: u8,
    pub unk06: u8,
    pub unk07: u8,
    pub unk08: u8,
    pub big_endian: bool,
    pub unk0a: u8,
    pub unk0b: u8,
    pub file_count: u32,
    pub header_size: u64,
    pub version: String,
    pub file_header_size: u64,
    pub file_headers_end: u64,
    // Includes hash table
    pub unicode: bool,
    pub raw_format: u8,
    pub extended: u8,
    pub unk33: u8,
    pub unk34: u32,
    pub buckets_offset: u64,
}

#[repr(C)]
pub struct File {
    pub raw_flags: u8,
    pub unk01: u8,
    pub unk02: u8,
    pub unk03: u8,
    pub unk04: i32,
    pub compressed_size: u64,
    pub uncompressed_size: Option<u64>,
    pub data_offset: u32,
    pub id: Option<i32>,
    pub name_offset: Option<u32>,
    pub zero: Option<u32>,
    pub name: Option<String>,
    pub data: Option<Vec<u8>>,
}

#[repr(C)]
pub struct BND4BucketHeader {
    pub hashes_offset: usize,
    pub bucket_count: u32,
    pub buckets_header_size: u8,
    pub bucket_size: u8,
    pub hash_size: u8,
    pub unk0f: u8,
    pub buckets: Vec<BND4Bucket>,
    pub hashes: Vec<BND4Hash>,
}

#[repr(C)]
pub struct BND4Bucket {
    pub count: u32,
    pub index: u32,
}

#[repr(C)]
pub struct BND4Hash {
    pub hash: u32,
    pub index: u32,
}

impl BND4 {
    const MAGIC_SIZE: usize = 4;
    const VERSION_SIZE: usize = 8;
    const ENDIANNESS_OFFSET: usize = 9;
    const AES_KEY_SIZE: usize = 16;

    pub fn from_path(path: &str) -> Result<BND4, DantelionFormatsError> {
        let file = fs::read(path)?;

        Ok(BND4::from_bytes(&file)?)
    }

    pub fn from_bytes(file: &[u8]) -> Result<BND4, DantelionFormatsError> {
        let mut bytes;


        if DCX::is(file) {
            let dcx = DCX::from_bytes(file)?;
            bytes = dcx.decompress()?;
        } else {
            bytes = file.to_vec();
        }
        let mut br = BinaryReader::from_vec(&bytes);

        // IDK if I should peek and check first, or just read up until BE and then do the rest of the parsing in the header declaration
        let magic = util::read_fixed_string(&mut br, BND4::MAGIC_SIZE)?;
        let unk04 = br.read_u8()?;
        let unk05 = br.read_u8()?;
        let unk06 = br.read_u8()?;
        let unk07 = br.read_u8()?;
        let unk08 = br.read_u8()?;
        let big_endian = br.read_bool()?;

        if big_endian { br.set_endian(Endian::Big) } else { br.set_endian(Endian::Little) };

        let mut header = BND4Header {
            magic,
            unk04,
            unk05,
            unk06,
            unk07,
            unk08,
            big_endian,
            unk0a: br.read_u8()?,
            unk0b: br.read_u8()?,
            file_count: br.read_u32()?,
            header_size: br.read_u64()?,
            version: util::read_fixed_string(&mut br, BND4::VERSION_SIZE)?,
            file_header_size: br.read_u64()?,
            file_headers_end: br.read_u64()?,
            unicode: br.read_bool()?,
            raw_format: br.read_u8()?,
            extended: br.read_u8()?,
            unk33: br.read_u8()?,
            unk34: br.read_u32()?,
            buckets_offset: br.read_u64()?,
        };

        header.validate();

        let files = read_bnd4_files(&mut br, &header)?;

        let buckets: Option<BND4BucketHeader> = if header.buckets_offset != 0 { Some(read_bnd4_bucket_header(&mut br, &header)?) } else { None };

        Ok(BND4 {
            header,
            files,
            buckets,
        })
    }
}

fn read_bnd4_bucket_header(br: &mut BinaryReader, header: &BND4Header) -> Result<BND4BucketHeader, DantelionFormatsError> {
    let start = br.pos;
    br.jmp(header.buckets_offset as usize);
    let hashes_offset = br.read_u64()? as usize;
    let bucket_count = br.read_u32()?;
    let buckets_header_size = br.read_u8()?;
    let bucket_size = br.read_u8()?;
    let hash_size = br.read_u8()?;
    let unk0f = br.read_u8()?;
    let buckets = read_bnd4_buckets(br, bucket_count as usize)?;
    let hashes = read_bnd4_hashes(br, header, hashes_offset)?;
    let buckets = BND4BucketHeader {
        hashes_offset,
        bucket_count,
        buckets_header_size,
        bucket_size,
        hash_size,
        unk0f,
        buckets,
        hashes,
    };

    br.jmp(start);
    Ok(buckets)
}

fn read_bnd4_hashes(br: &mut BinaryReader, header: &BND4Header, hashes_offset: usize) -> Result<Vec<BND4Hash>, DantelionFormatsError> {
    let mut hashes = Vec::with_capacity(header.file_count as usize);
    for i in 0..header.file_count {
        hashes.push(BND4Hash {
            hash: br.read_u32()?,
            index: br.read_u32()?,
        })
    }

    Ok(hashes)
}

fn read_bnd4_buckets(br: &mut BinaryReader, count: usize) -> Result<Vec<BND4Bucket>, DantelionFormatsError> {
    let mut buckets = Vec::with_capacity(count);
    for i in 0..count {
        buckets.push(BND4Bucket {
            count: br.read_u32()?,
            index: br.read_u32()?,
        })
    }

    Ok(buckets)
}

fn read_bnd4_files(br: &mut BinaryReader, header: &BND4Header) -> Result<Vec<File>, DantelionFormatsError> {
    let format = if header.big_endian { header.raw_format } else { util::reverse_bits(header.raw_format) };
    let mut files: Vec<File> = Vec::with_capacity(header.file_count as usize);
    for i in 0..header.file_count {
        let raw_flags = br.read_u8()?;
        let unk01 = br.read_u8()?;
        let unk02 = br.read_u8()?;
        let unk03 = br.read_u8()?;
        let unk04 = br.read_i32()?;
        let compressed_size = br.read_u64()?;
        let uncompressed_size = if format & 0b00100000 != 0 { Some(br.read_u64()?) } else { None };
        let data_offset = br.read_u32()?;
        let end = if br.endian == Endian::Big { 1 } else { 0 };
        let mut id = if format & 0b00000010 != 0 { Some(br.read_i32()?) } else { None };
        let name_offset = if format & 0b00000100 != 0 || format & 0b00001000 != 0 { Some(br.read_u32()?) } else { None };
        let mut zero = None;
        if format == 0b00000100 {
            id = Some(br.read_i32()?);
            zero = Some(br.read_u32()?);
        }

        let name = match name_offset {
            None => None,
            Some(offset) => Some(get_file_name(br, offset, header)?)
        };

        let data: Option<Vec<u8>> = Some(vec![]);
        let file = File {
            raw_flags,
            unk01,
            unk02,
            unk03,
            unk04,
            compressed_size,
            uncompressed_size,
            data_offset,
            id,
            name_offset,
            zero,
            name,
            data,
        };

        file.validate();
        files.push(file);
    }

    Ok(files)
}

fn get_file_name(br: &mut BinaryReader, offset: u32, header: &BND4Header) -> Result<String, DantelionFormatsError> {
    let start = br.pos;
    br.jmp(offset as usize);
    let name: String;
    if header.unicode {
        name = util::read_utf16_string(br)?;
    } else {
        name = br.read_cstr()?;
    }

    br.jmp(start);
    return Ok(name);
}

impl Validate for BND4Header {

    fn validate(&self) {
        assert_eq!(self.magic, "BND4", "Magic was {}", self.magic);
        assert!(self.unk04 == 0 || self.unk04 == 1, "unk04 was {}", self.unk04);
        assert!(self.unk05 == 0 || self.unk05 == 1, "unk05 was {}", self.unk05);
        assert_eq!(self.unk06, 0, "unk06 was {}", self.unk06);
        assert_eq!(self.unk07, 0, "unk07 was {}", self.unk07);
        assert_eq!(self.unk08, 0, "unk08 was {}", self.unk08);
        assert!(self.unk0a == 0 || self.unk0a == 1, "unk0A was {}", self.unk0a);
        assert_eq!(self.unk0b, 0, "unk0B was {}", self.unk0b);
        assert_eq!(self.header_size, 0x40, "self_size was {}", self.header_size);
        assert!(self.unicode == false || self.unicode == true, "unicode was {}", self.unicode);
        assert!(self.extended == 0 || self.extended == 4, "extended was {}", self.extended);
        assert_eq!(self.unk33, 0, "unk33 was {}", self.unk33);
        assert_eq!(self.unk34, 0, "unk34 was {}", self.unk34);
    }
}


impl Validate for File {
    fn validate(&self) {
        assert_eq!(self.unk01, 0, "unk01 was {}", self.unk01);
        assert_eq!(self.unk02, 0, "unk02 was {}", self.unk02);
        assert_eq!(self.unk03, 0, "unk03 was {}", self.unk03);
        assert_eq!(self.unk04, -1, "unk04 was {}", self.unk04);
    }
}



