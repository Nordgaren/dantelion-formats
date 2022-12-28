use std::fs;
use binary_reader::{BinaryReader, Endian};
use crate::{crypto_util, util};
use crate::error::DantelionFormatError;
use crate::util::Validate;

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

    pub fn from_path(path: &str) -> Result<BHD5, DantelionFormatError> {
        let file = fs::read(path)?;

        let key = crypto_util::get_elden_ring_bhd5_key(path)?;
        let decrypted = crypto_util::decrypt_bhd5_file(file.as_slice(), key)?;
        Ok(BHD5::from_bytes(&decrypted)?)
    }

    pub fn from_bytes(file: &[u8]) -> Result<BHD5, DantelionFormatError> {
        let mut br = BinaryReader::from_u8(file);
        br.set_endian(Endian::Little);

        // Get BHD5Header
        let magic=  util::read_fixed_string(&mut br, BHD5::MAGIC_SIZE)?;
        let unk04=  br.read_u8()?;
        let unk05=  br.read_u8()?;
        let unk06=  br.read_u8()?;
        let unk07=  br.read_u8()?;
        let unk08=  br.read_u32()?;
        let file_size=  br.read_u32()?;
        let bucket_count=  br.read_u32()?;
        let buckets_offset=  br.read_u32()?;
        let salt_len=  br.read_u32()?;
        let salt=  br.read_bytes(salt_len as usize)?.to_vec();
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

        let format: BHD5Format = get_bhd5_format(&header.salt);

        // Get buckets
        let mut buckets: Vec<BHD5Bucket> = Vec::with_capacity(header.bucket_count as usize);

        for _ in 0..header.bucket_count {
            let file_header_count = br.read_u32()?;
            let file_headers_offset = br.read_u32()?;
            let file_headers = BHD5::read_file_headers(&mut br, file_header_count, file_headers_offset, format)?;
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

    fn read_file_headers(br: &mut BinaryReader, file_header_count: u32, file_headers_offset: u32, format: BHD5Format) -> Result<Vec<FileHeader>, DantelionFormatError> {
        let mut headers: Vec<FileHeader> = Vec::with_capacity(file_header_count as usize);
        let start = br.pos;
        br.jmp(file_headers_offset as usize);
        for _ in 0..file_header_count {
            if format == BHD5Format::EldenRing {
                let file_path_hash = br.read_u64()?;
                let padded_file_size = br.read_u32()?;
                let file_size = br.read_u32()? as u64; //Read a 32 bit file size, but store it in a 64 bit field
                let file_offset = br.read_u64()?;
                let salted_hash_offset = br.read_u64()?;
                let aes_key_offset = br.read_u64()?;
                let salted_hash = if salted_hash_offset == 0 { None } else { Some(BHD5::read_salted_hash(br, salted_hash_offset)?) };
                let aes_key = if aes_key_offset == 0 { None } else { Some(BHD5::read_aes_key(br, aes_key_offset)?) };
                headers.push(FileHeader { file_path_hash, padded_file_size, file_size, file_offset, salted_hash_offset, aes_key_offset, salted_hash, aes_key })
            } else {
                let file_path_hash = br.read_u32()? as u64; //Read a 32 bit hash, but store it in a 64 bit field
                let padded_file_size = br.read_u32()?;
                let file_offset = br.read_u64()?;
                let salted_hash_offset = br.read_u64()?;
                let aes_key_offset = br.read_u64()?;
                let salted_hash = if salted_hash_offset == 0 { None } else { Some(BHD5::read_salted_hash(br, salted_hash_offset)?) };
                let aes_key = if aes_key_offset == 0 { None } else { Some(BHD5::read_aes_key(br, aes_key_offset)?) };
                let mut file_size = 0;
                if format == BHD5Format::DarkSoulsIII {
                    file_size = br.read_u64()?;
                }
                headers.push(FileHeader { file_path_hash, padded_file_size, file_size, file_offset, salted_hash_offset, aes_key_offset, salted_hash, aes_key })
            }
        }
        br.jmp(start);
        return Ok(headers);
    }

    fn read_salted_hash(br: &mut BinaryReader, salted_hash_offset: u64) -> Result<SaltedHash, DantelionFormatError> {
        let start = br.pos;
        br.jmp(salted_hash_offset as usize);

        let hash = br.read_bytes(BHD5::SALTED_HASH_SIZE)?.to_vec();
        let range_count = br.read_u32()?;
        let ranges = BHD5::read_ranges(br, range_count)?;

        br.jmp(start);

        Ok(SaltedHash {
            hash,
            range_count,
            ranges,
        }
        )
    }

    fn read_aes_key(br: &mut BinaryReader, aes_key_offset: u64) -> Result<AESKey, DantelionFormatError> {
        let start = br.pos;
        br.jmp(aes_key_offset as usize);

        let key = br.read_bytes(BHD5::AES_KEY_SIZE)?.to_vec();
        let range_count = br.read_u32()?;
        let ranges = BHD5::read_ranges(br, range_count)?;
        br.jmp(start);

        Ok(AESKey {
            key,
            range_count,
            ranges,
        }
        )
    }

    fn read_ranges(br: &mut BinaryReader, range_count: u32) -> Result<Vec<Range>, DantelionFormatError> {
        let mut ranges: Vec<Range> = Vec::with_capacity(range_count as usize);
        for _ in 0..range_count {
            let begin = br.read_u64()?;
            let end = br.read_u64()?;
            ranges.push(Range { begin, end })
        }
        return Ok(ranges);
    }
}

fn get_bhd5_format(salt: &[u8]) -> BHD5Format {
    if &salt[..3] == b"GR_" {
        return BHD5Format::EldenRing;
    } else if &salt[..4] == b"FDP_" || &salt[..4] == b"NTC_" {
        return BHD5Format::DarkSoulsIII;
    }
    BHD5Format::DarkSoulsII
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


