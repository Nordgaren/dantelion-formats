use std::fs;
use std::io::Result;
use binary_reader::{BinaryReader, Endian};
use crate::dcx::DCX;
use crate::util;

pub struct BND4 {
    pub header: BND4Header,
    pub files: Vec<File>,
    pub buckets: Option<BND4BucketHeader>,
}

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

pub struct File {
    raw_flags: u8,
    unk01: u8,
    unk02: u8,
    unk03: u8,
    unk04: i32,
    compressed_size: u64,
    uncompressed_size: Option<u64>,
    data_offset: u32,
    id: Option<i32>,
    name_offset: Option<u32>,
    zero: Option<u32>,
    name: Option<String>,
    data: Option<Vec<u8>>,
}

pub struct BND4BucketHeader {
    hashes_offset: u64,
    bucket_count: u32,
    buckets_header_size: u8,
    buckets: Vec<BND4Bucket>,
    hashes: Vec<BND4Hash>
}

pub struct BND4Bucket {
    count: u32,
    index: u32
}

pub struct BND4Hash {
    hash: u32,
    index: u32
}

impl BND4 {
    const MAGIC_SIZE: usize = 4;
    const VERSION_SIZE: usize = 8;
    const ENDIANNESS_OFFSET: usize = 9;
    const AES_KEY_SIZE: usize = 16;

    pub fn from_path(path: &str) -> Result<BND4> {
        let file = fs::read(path)?;

        Ok(BND4::from_bytes(&file)?)
    }


    pub fn from_bytes(file: &[u8]) -> Result<BND4> {
        let dcx = DCX::from_bytes(file)?;
        let bytes = dcx.decompress()?;
        let mut br = BinaryReader::from_vec(&bytes);

        // IDK if I should peek and check first, or just read up until BE and then do the rest of the parsing in the header declaration
        //if util::peek_byte(&mut br, ENDIANNESS_OFFSET)? { br.set_endian(Endian::Big) } else { br.set_endian(Endian::Little) };
        let magic = util::read_fixed_string(&mut br, BND4::MAGIC_SIZE)?;
        let unk04 = br.read_u8()?;
        let unk05 = br.read_u8()?;
        let unk06 = br.read_u8()?;
        let unk07 = br.read_u8()?;
        let unk08 = br.read_u8()?;
        let bigEndian = br.read_bool()?;

        if bigEndian { br.set_endian(Endian::Big) } else { br.set_endian(Endian::Little) };

        let mut header = BND4Header {
            magic,
            unk04,
            unk05,
            unk06,
            unk07,
            unk08,
            big_endian: bigEndian,
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

        verify_bnd4_header(&header);

        let files = read_bnd4_files(&mut br, &header)?;

        let buckets: Option<BND4BucketHeader> = if header.buckets_offset != 0 { Some(read_bnd4_bucket_header(&mut br, &header)?) } else {None};

        Ok(BND4{
            header,
            files,
            buckets,
        })

    }
}

fn read_bnd4_bucket_header(br: &mut BinaryReader, header: &BND4Header) -> Result<BND4BucketHeader> {
    let hashes_offset =  br.read_u64()?;
    let bucket_count =  br.read_u32()?;
    let buckets_header_size =  br.read_u8()?;
    let buckets =  read_bnd4_buckets(br, bucket_count)?;
    let hashes =  read_bnd4_hashes(br, header);
    let buckets = BND4BucketHeader {
        hashes_offset,
        bucket_count,
        buckets_header_size,
        buckets: buckets,
        hashes: vec![],
    };

    Ok(buckets)

}

fn read_bnd4_hashes(br: &mut BinaryReader, header: &BND4Header) -> Result<Vec<BND4Hash>> {
    let mut hashes = Vec::with_capacity(header.file_count as usize);
    for i in 0..header.file_count {
        hashes.push(BND4Hash{
            hash: br.read_u32()?,
            index:  br.read_u32()?
        })
    }

    Ok(hashes)
}

fn read_bnd4_buckets(br: &mut BinaryReader, count: u32) -> Result<Vec<BND4Bucket>> {
    let mut buckets = Vec::with_capacity(count as usize);
    for i in 0..count {
        buckets.push(BND4Bucket{
            count: br.read_u32()?,
            index:  br.read_u32()?
        })
    }

    Ok(buckets)
}

fn read_bnd4_files(br: &mut BinaryReader, header: &BND4Header) -> Result<Vec<File>> {
    let format = if header.big_endian { header.raw_format } else { util::reverse_bits(header.raw_format)? };
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
        let end = if br.endian == Endian::Big {1} else {0};
        let mut id = if format & 0b00000010 != 0 { Some(br.read_i32()?) } else { None };
        let name_offset = if format & 0b00000100 != 0 || format & 0b00001000 != 0 { Some(br.read_u32()?) } else { None };
        let mut zero = None;
        if format == 0b00000100 {
            id = Some(br.read_i32()?);
            zero = Some(br.read_u32()?);
        }

        let name = match name_offset {
            None => { None }
            Some(offset) => {
                Some(get_file_name(br, offset, header)?)
            }
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

        verify_file(&file);
        files.push(file);
    }

    Ok(files)
}

fn get_file_name(br: &mut BinaryReader, offset: u32, header: &BND4Header) -> Result<String> {
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

fn verify_bnd4_header(header: &BND4Header) {
    assert_eq!(header.magic, "BND4", "Magic was {}", header.magic);
    assert!(header.unk04 == 0 || header.unk04 == 1, "unk04 was {}", header.unk04);
    assert!(header.unk05 == 0 || header.unk05 == 1, "unk05 was {}", header.unk05);
    assert_eq!(header.unk06, 0, "unk06 was {}", header.unk06);
    assert_eq!(header.unk07, 0, "unk07 was {}", header.unk07);
    assert_eq!(header.unk08, 0, "unk08 was {}", header.unk08);
    assert!(header.unk0a == 0 || header.unk0a == 1, "unk0A was {}", header.unk0a);
    assert_eq!(header.unk0b, 0, "unk0B was {}", header.unk0b);
    assert_eq!(header.header_size, 0x40, "header_size was {}", header.header_size);
    assert!(header.unicode == false || header.unicode == true, "unicode was {}", header.unicode);
    assert!(header.extended == 0 || header.extended == 4, "extended was {}", header.extended);
    assert_eq!(header.unk33, 0, "unk33 was {}", header.unk33);
    assert_eq!(header.unk34, 0, "unk34 was {}", header.unk34);
}


fn verify_file(file: &File) {
    assert_eq!(file.unk01, 0, "unk01 was {}", file.unk01);
    assert_eq!(file.unk02, 0, "unk02 was {}", file.unk02);
    assert_eq!(file.unk03, 0, "unk03 was {}", file.unk03);
    assert_eq!(file.unk04, -1, "unk04 was {}", file.unk04);
}
