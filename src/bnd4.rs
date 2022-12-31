use std::fs;
use std::io::{Cursor};
use binary_interpreter::binary_reader::{BinaryPeeker, BinaryReader};
use byteorder::{BE, LE, ByteOrder, ReadBytesExt};
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
    pub hashes_offset: u64,
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

    pub fn from_path(path: &str) -> Result<BND4, DantelionFormatsError> {
        let file = fs::read(path)?;

        BND4::from_bytes(&file)
    }

    pub fn from_bytes(file: &[u8]) -> Result<BND4, DantelionFormatsError> {
        let bytes = if DCX::is(file) {
            let dcx = DCX::from_bytes(file)?;
            dcx.decompress()?
        } else {
            file.to_vec()
        };
        let mut c = Cursor::new(&bytes[..]);

        let be = c.peek_u8(BND4::ENDIANNESS_OFFSET)? != 0;
        let header = if be { BND4::read_bnd4_header::<BE>(&mut c)? } else { BND4::read_bnd4_header::<LE>(&mut c)? };
        let files = if be { BND4::read_bnd4_files::<BE>(&mut c, &header)? } else { BND4::read_bnd4_files::<LE>(&mut c, &header)? };
        let buckets: Option<BND4BucketHeader> = if header.buckets_offset != 0 {
            Some(if be { BND4::read_bnd4_bucket_header::<BE>(&mut c, &header)?} else {BND4::read_bnd4_bucket_header::<LE>(&mut c, &header)?})
        } else {
            None
        };

        Ok(BND4 {
            header,
            files,
            buckets,
        })
    }

    fn read_bnd4_header<T: ByteOrder>(c: &mut Cursor<&[u8]>) -> Result<BND4Header, DantelionFormatsError> {

        let header = BND4Header {
            magic: c.read_fixed_cstr(BND4::MAGIC_SIZE)?,
            unk04: c.read_u8()?,
            unk05: c.read_u8()?,
            unk06: c.read_u8()?,
            unk07: c.read_u8()?,
            unk08: c.read_u8()?,
            big_endian: c.read_u8()? != 0,
            unk0a: c.read_u8()?,
            unk0b: c.read_u8()?,
            file_count: c.read_u32::<T>()?,
            header_size: c.read_u64::<T>()?,
            version: c.read_fixed_cstr(BND4::VERSION_SIZE)?,
            file_header_size: c.read_u64::<T>()?,
            file_headers_end: c.read_u64::<T>()?,
            unicode: c.read_u8()? != 0,
            raw_format: c.read_u8()?,
            extended: c.read_u8()?,
            unk33: c.read_u8()?,
            unk34: c.read_u32::<T>()?,
            buckets_offset: c.read_u64::<T>()?,
        };

        header.validate();

        Ok(header)

    }

    fn read_bnd4_bucket_header<T: ByteOrder>(c: &mut Cursor<&[u8]>, header: &BND4Header) -> Result<BND4BucketHeader, DantelionFormatsError> {
        let start = c.position();
        c.set_position(header.buckets_offset);
        let hashes_offset = c.read_u64::<T>()?;
        let bucket_count = c.read_u32::<T>()?;
        let buckets_header_size = c.read_u8()?;
        let bucket_size = c.read_u8()?;
        let hash_size = c.read_u8()?;
        let unk0f = c.read_u8()?;
        let buckets = BND4::read_bnd4_buckets::<T>(c, bucket_count as usize)?;
        let hashes = BND4::read_bnd4_hashes::<T>(c, header, hashes_offset)?;
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

        c.set_position(start);
        Ok(buckets)
    }

    fn read_bnd4_hashes<T: ByteOrder>(c: &mut Cursor<&[u8]>, header: &BND4Header, hashes_offset: u64) -> Result<Vec<BND4Hash>, DantelionFormatsError> {
        c.set_position(hashes_offset);
        let mut hashes = Vec::with_capacity(header.file_count as usize);
        for _ in 0..header.file_count {
            hashes.push(BND4Hash {
                hash: c.read_u32::<T>()?,
                index: c.read_u32::<T>()?,
            })
        }

        Ok(hashes)
    }

    fn read_bnd4_buckets<T: ByteOrder>(c: &mut Cursor<&[u8]>, count: usize) -> Result<Vec<BND4Bucket>, DantelionFormatsError> {
        let mut buckets = Vec::with_capacity(count);
        for _ in 0..count {
            buckets.push(BND4Bucket {
                count: c.read_u32::<T>()?,
                index: c.read_u32::<T>()?,
            })
        }

        Ok(buckets)
    }

    fn read_bnd4_files<T: ByteOrder>(c: &mut Cursor<&[u8]>, header: &BND4Header) -> Result<Vec<File>, DantelionFormatsError> {
        let format = if header.big_endian { header.raw_format } else { util::reverse_bits(header.raw_format) };
        let mut files: Vec<File> = Vec::with_capacity(header.file_count as usize);
        for _ in 0..header.file_count {
            let raw_flags = c.read_u8()?;
            let unk01 = c.read_u8()?;
            let unk02 = c.read_u8()?;
            let unk03 = c.read_u8()?;
            let unk04 = c.read_i32::<T>()?;
            let compressed_size = c.read_u64::<T>()?;
            let uncompressed_size = if format & 0b00100000 != 0 { Some(c.read_u64::<T>()?) } else { None };
            let data_offset = c.read_u32::<T>()?;
            let mut id = if format & 0b00000010 != 0 { Some(c.read_i32::<T>()?) } else { None };
            let name_offset = if format & 0b00000100 != 0 || format & 0b00001000 != 0 { Some(c.read_u32::<T>()?) } else { None };
            let mut zero = None;
            if format == 0b00000100 {
                id = Some(c.read_i32::<T>()?);
                zero = Some(c.read_u32::<T>()?);
            }

            let name = match name_offset {
                None => None,
                Some(offset) => Some(BND4::get_file_name(c, offset as u64, header)?)
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

    fn get_file_name(c: &mut Cursor<&[u8]>, offset: u64, header: &BND4Header) -> Result<String, DantelionFormatsError> {
        let start = c.position();
        c.set_position(offset);
        let name: String;
        if header.unicode {
            name = c.read_wcstr()?;
        } else {
            name = c.read_cstr()?;
        }

        c.set_position(start);
        return Ok(name);
    }
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



