use std::io::Cursor;
use std::fs;
use crate::{crypto_util, util};
use crate::error::DantelionFormatsError;
use crate::util::Validate;
use byteorder::{LE, BE, ReadBytesExt};
use binary_interpreter::binary_reader::BinaryReader;
use binary_interpreter::Endian;
//Idk how necessary this is. Might need it for DS1, idk.
pub(crate) enum GameType {
    DemonSouls,
    DarkSouls,
    DarkSoulsII,
    DarkSoulsIISotFS,
    DarkSoulsRemastered,
    DarkSoulsIII,
    Sekiro,
    EldenRing,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum BHD5Format {
    DarkSoulsII,
    DarkSoulsIII,
    EldenRing,
}

#[repr(C)]
pub(crate) struct BHD5 {
    pub format: BHD5Format,
    pub bhd5_header: BHD5Header,
    pub buckets: Vec<BHD5Bucket>,
}

#[repr(C)]
pub(crate) struct BHD5Header {
    pub magic: String,
    pub unk04: u8,
    pub unk05: u8,
    pub unk06: u8,
    pub unk07: u8,
    pub unk08: u32,
    pub file_size: u32,
    pub bucket_count: u32,
    pub buckets_offset: u32,
    pub salt_len: u32,
    pub salt: Vec<u8>
}

#[repr(C)]
pub(crate) struct BHD5Bucket {
    pub file_header_count: u32,
    pub file_headers_offset: u32,
    pub file_headers: Vec<FileHeader>,
}

#[repr(C)]
pub(crate) struct FileHeader {
    pub file_path_hash: u64,
    pub padded_file_size: u32,
    pub file_size: u64,
    pub file_offset: u64,
    pub salted_hash_offset: u64,
    pub aes_key_offset: u64,
    pub salted_hash: Option<SaltedHash>,
    pub aes_key: Option<AESKey>,
}

#[repr(C)]
pub(crate) struct SaltedHash {
    pub hash: Vec<u8>,
    pub range_count: u32,
    pub ranges: Vec<Range>,
}

#[repr(C)]
pub(crate) struct AESKey {
    pub key: Vec<u8>,
    pub range_count: u32,
    pub ranges: Vec<Range>,
}

#[repr(C)]
pub(crate) struct Range {
    pub begin: u64,
    pub end: u64,
}

impl BHD5 {
    const MAGIC_SIZE: usize = 4;
    const SALTED_HASH_SIZE: usize = 32;
    const AES_KEY_SIZE: usize = 16;

    pub fn from_path(path: &str) -> Result<BHD5, DantelionFormatsError> {
        let file = fs::read(path)?;

        let key = crypto_util::get_elden_ring_bhd5_key(path)?;
        let decrypted = crypto_util::decrypt_bhd5_file(file.as_slice(), key)?;
        BHD5::from_bytes(&decrypted)
    }

    pub fn from_bytes(file: &[u8]) -> Result<BHD5, DantelionFormatsError> {
        let mut c = Cursor::new(file);
        println!("{:02x}", file.len());
        let header = BHD5::read_bhd5_header(&mut c)?;
        let format = BHD5::get_bhd5_format(&header.salt);

        let mut buckets: Vec<BHD5Bucket> = Vec::with_capacity(header.bucket_count as usize);

        for _ in 0..header.bucket_count {
            let file_header_count = c.read_u32::<LE>()?;
            let file_headers_offset = c.read_u32::<LE>()?;
            let file_headers = BHD5::read_file_headers(&mut c, file_header_count as u64, file_headers_offset as u64, format)?;
            buckets.push(BHD5Bucket {
                file_header_count,
                file_headers_offset,
                file_headers,
            });
        }

        Ok(BHD5 {
            format,
            bhd5_header: header,
            buckets,
        })
    }
    fn read_bhd5_header(c: &mut Cursor<&[u8]>) -> Result<BHD5Header, DantelionFormatsError> {

        let magic=  c.read_fixed_cstr(BHD5::MAGIC_SIZE)?;
        let unk04=  c.read_u8()?;
        let unk05=  c.read_u8()?;
        let unk06=  c.read_u8()?;
        let unk07=  c.read_u8()?;
        let unk08=  c.read_u32::<LE>()?;
        let file_size=  c.read_u32::<LE>()?;
        let bucket_count=  c.read_u32::<LE>()?;
        let buckets_offset=  c.read_u32::<LE>()?;
        let salt_len=  c.read_u32::<LE>()?;
        let salt=  c.read_bytes(salt_len as usize)?;
        let mut header = BHD5Header {
            magic,
            unk04,
            unk05,
            unk06,
            unk07,
            unk08,
            file_size,
            bucket_count,
            buckets_offset,
            salt_len,
            salt,
        };

        header.validate();

        Ok(header)
    }

    fn get_bhd5_format(salt: &[u8]) -> BHD5Format {
        if &salt[..3] == b"GR_" {
            return BHD5Format::EldenRing;
        } else if &salt[..4] == b"FDP_" || &salt[..4] == b"NTC_" {
            return BHD5Format::DarkSoulsIII;
        }
        BHD5Format::DarkSoulsII
    }

    fn read_file_headers(c: &mut Cursor<&[u8]>, file_header_count: u64, file_headers_offset: u64, format: BHD5Format) -> Result<Vec<FileHeader>, DantelionFormatsError> {
        let mut headers: Vec<FileHeader> = Vec::with_capacity(file_header_count as usize);
        let start = c.position();
        c.set_position(file_headers_offset);
        for _ in 0..file_header_count {
            if format == BHD5Format::EldenRing {
                let file_path_hash = c.read_u64::<LE>()?;
                let padded_file_size = c.read_u32::<LE>()?;
                let file_size = c.read_u32::<LE>()? as u64; //Read a 32 bit file size, but store it in a 64 bit field
                let file_offset = c.read_u64::<LE>()?;
                let salted_hash_offset = c.read_u64::<LE>()?;
                let aes_key_offset = c.read_u64::<LE>()?;
                let salted_hash = if salted_hash_offset == 0 { None } else { Some(BHD5::read_salted_hash(c, salted_hash_offset)?) };
                let aes_key = if aes_key_offset == 0 { None } else { Some(BHD5::read_aes_key(c, aes_key_offset)?) };
                headers.push(FileHeader { file_path_hash, padded_file_size, file_size, file_offset, salted_hash_offset, aes_key_offset, salted_hash, aes_key })
            } else {
                let file_path_hash = c.read_u32::<LE>()? as u64; //Read a 32 bit hash, but store it in a 64 bit field
                let padded_file_size = c.read_u32::<LE>()?;
                let file_offset = c.read_u64::<LE>()?;
                let salted_hash_offset = c.read_u64::<LE>()?;
                let aes_key_offset = c.read_u64::<LE>()?;
                let salted_hash = if salted_hash_offset == 0 { None } else { Some(BHD5::read_salted_hash(c, salted_hash_offset)?) };
                let aes_key = if aes_key_offset == 0 { None } else { Some(BHD5::read_aes_key(c, aes_key_offset)?) };
                let mut file_size = 0;
                if format == BHD5Format::DarkSoulsIII {
                    file_size = c.read_u64::<LE>()?;
                }
                headers.push(FileHeader { file_path_hash, padded_file_size, file_size, file_offset, salted_hash_offset, aes_key_offset, salted_hash, aes_key })
            }
        }
        c.set_position(start);
        return Ok(headers);
    }

    fn read_salted_hash(c: &mut Cursor<&[u8]>, salted_hash_offset: u64) -> Result<SaltedHash, DantelionFormatsError> {
        let start = c.position();
        c.set_position(salted_hash_offset);

        let hash = c.read_bytes(BHD5::SALTED_HASH_SIZE)?;
        let range_count = c.read_u32::<LE>()?;
        let ranges = BHD5::read_ranges(c, range_count)?;

        c.set_position(start);

        Ok(SaltedHash {
            hash,
            range_count,
            ranges,
        }
        )
    }

    fn read_aes_key(c: &mut Cursor<&[u8]>, aes_key_offset: u64) -> Result<AESKey, DantelionFormatsError> {
        let start = c.position();
        c.set_position(aes_key_offset);

        let key = c.read_bytes(BHD5::AES_KEY_SIZE)?;
        let range_count = c.read_u32::<LE>()?;
        let ranges = BHD5::read_ranges(c, range_count)?;
        c.set_position(start);

        Ok(AESKey {
            key,
            range_count,
            ranges,
        }
        )
    }

    fn read_ranges(br: &mut Cursor<&[u8]>, range_count: u32) -> Result<Vec<Range>, DantelionFormatsError> {
        let mut ranges: Vec<Range> = Vec::with_capacity(range_count as usize);
        for _ in 0..range_count {
            let begin = br.read_u64::<LE>()?;
            let end = br.read_u64::<LE>()?;
            ranges.push(Range { begin, end })
        }
        return Ok(ranges);
    }
}



impl Validate for BHD5Header {
    fn validate(&self) {
        assert_eq!(self.magic, "BHD5");
        assert_eq!(self.unk04, u8::MAX, "header.unk04: {}", self.unk04);
        assert!(self.unk05 == 0 || self.unk05 == 1, "header.unk05: {}", self.unk05);
        assert_eq!(self.unk06, 0, "header.unk06: {}", self.unk06);
        assert_eq!(self.unk07, 0, "header.unk07: {}", self.unk07);
        assert_eq!(self.unk08, 1, "header.unk08: {}", self.unk08);
    }
}


