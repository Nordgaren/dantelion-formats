use std::fs;
use std::io::Error;
use binary_reader::{BinaryReader, Endian};
use crate::{crypto_util, util};

//Idk how necessary this is. Might need it for DS1, idk.
pub(crate) enum GameType {
    DemonSouls,
    DarkSouls,
    DarkSoulsII,
    DarkSoulsIISotFS,
    DarkSoulsRemastered,
    DarkSoulsIII,
    Sekiro,
    EldenRing
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum BHD5Format {
    DarkSoulsII,
    DarkSoulsIII,
    EldenRing
}

pub(crate) struct BHD5 {
    pub format: BHD5Format,
    pub bhd5_header: BHD5Header,
    pub buckets: Vec<BHD5Bucket>,
}

pub(crate) struct BHD5Header {
    pub magic: String,
    pub unk04: i8,
    pub unk05: u8,
    pub unk06: u8,
    pub unk07: u8,
    pub unk08: i32,
    pub file_size: i32,
    pub bucket_count: i32,
    pub buckets_offset: i32,
    pub salt_len: i32,
    pub salt: String,
}

pub(crate) struct BHD5Bucket {
    pub file_header_count: i32,
    pub file_headers_offset: i32,
    pub file_headers: Vec<FileHeader>,
}

pub(crate) struct FileHeader {
    pub file_path_hash: i64,
    pub padded_file_size: i32,
    pub file_size: i64,
    pub file_offset: i64,
    pub salted_hash_offset: i64,
    pub aes_key_offset: i64,
    pub salted_hash: Option<SaltedHash>,
    pub aes_key: Option<AESKey>,
}

pub(crate) struct SaltedHash {
    pub hash: Vec<u8>,
    pub range_count: i32,
    pub ranges: Vec<Range>,
}

pub(crate) struct AESKey {
    pub key: Vec<u8>,
    pub range_count: i32,
    pub ranges: Vec<Range>,
}

pub(crate) struct Range {
    pub begin: i64,
    pub end: i64,
}

impl BHD5 {
    const MAGIC_SIZE: usize = 4;
    const SALTED_HASH_SIZE: usize = 32;
    const AES_KEY_SIZE: usize = 16;

    pub fn from_path(path: &str) -> Result<BHD5, Error> {
        let file = fs::read(path)
            .expect(&format!("Could not read file: {path}"));

        let key = crypto_util::get_elden_ring_bhd5_key(path);
        let decrypted = crypto_util::decrypt_bhd5_file(file.as_slice(), key)
            .expect("Unable to decrypt BHD5!");

        Ok(BHD5::from_bytes(&decrypted).expect(&format!("Could not parse decrypted bhd5: {path}!")))
    }

    pub fn from_bytes(file: &[u8]) -> Result<BHD5, Error> {
        let mut br = BinaryReader::from_u8(file);
        br.set_endian(Endian::Little);

        // Get BHD5Header
        let mut header = BHD5Header {
            magic: util::read_fixed_string(&mut br, BHD5::MAGIC_SIZE).expect("Could not parse BHD5Header.magic"),
            unk04: br.read_i8().expect("Could not read BHD5Header.unk04!"),
            unk05: br.read_u8().expect("Could not read BHD5Header.unk05!"),
            unk06: br.read_u8().expect("Could not read BHD5Header.unk06!"),
            unk07: br.read_u8().expect("Could not read BHD5Header.unk07!"),
            unk08: br.read_i32().expect("Could not read BHD5Header.unk08!"),
            file_size: br.read_i32().expect("Could not read BHD5Header.file_size!"),
            bucket_count: br.read_i32().expect("Could not read BHD5Header.bucket_count!"),
            buckets_offset: br.read_i32().expect("Could not read BHD5Header.buckets_offset!"),
            salt_len: br.read_i32().expect("Could not read BHD5Header.salt_len!"),
            salt: String::new(),
        };

        check_bhd5_header(&header);

        header.salt = util::read_fixed_string(&mut br, header.salt_len as usize).expect("Could not parse BHD5Header.magic");
        let format: BHD5Format = get_bhd5_format(&header.salt);

        // Get buckets
        let mut buckets: Vec<BHD5Bucket> = Vec::with_capacity(header.bucket_count as usize);

        for _ in 0..header.bucket_count {
            let file_header_count = br.read_i32().expect("Unable to read Bucket.file_header_count!");
            let file_headers_offset = br.read_i32().expect("Unable to read Bucket.file_headers_offset!");
            let file_headers = BHD5::read_file_headers(&mut br, file_header_count, file_headers_offset, format).expect("Could not read Bucket.file_headers!");
            buckets.push(BHD5Bucket {
                file_header_count,
                file_headers_offset,
                file_headers,
            });
        }

        Ok(BHD5 {
            format,
            bhd5_header: header,
            buckets
        })
    }

    fn read_file_headers(br: &mut BinaryReader, file_header_count: i32, file_headers_offset: i32, format: BHD5Format) -> Result<Vec<FileHeader>, Error> {
        let mut headers: Vec<FileHeader> = Vec::with_capacity(file_header_count as usize);
        let pos = br.pos;
        br.jmp(file_headers_offset as usize);
        for _ in 0..file_header_count {
            if format == BHD5Format::EldenRing {
                let file_path_hash = br.read_i64().expect("Unable to read FileHeader.file_path_hash!");
                let padded_file_size = br.read_i32().expect("Unable to read FileHeader.padded_file_size!");
                let file_size = br.read_i32().expect("Unable to read FileHeader.file_size!") as i64;
                let file_offset = br.read_i64().expect("Unable to read FileHeader.file_offset!");
                let salted_hash_offset = br.read_i64().expect("Unable to read FileHeader.salted_hash_offset!");
                let aes_key_offset = br.read_i64().expect("Unable to read FileHeader.aes_key_offset!");
                let salted_hash = BHD5::read_salted_hash(br, salted_hash_offset);
                let aes_key = BHD5::read_aes_key(br, aes_key_offset);
                headers.push(FileHeader { file_path_hash, padded_file_size, file_size, file_offset, salted_hash_offset, aes_key_offset, salted_hash, aes_key })
            } else {
                let file_path_hash = br.read_i32().expect("Unable to read FileHeader.file_path_hash!") as i64; //Read a 32 bit hash but store it in a 64 bit field
                let padded_file_size = br.read_i32().expect("Unable to read FileHeader.padded_file_size!");
                let file_offset = br.read_i64().expect("Unable to read FileHeader.file_offset!");
                let salted_hash_offset = br.read_i64().expect("Unable to read FileHeader.salted_hash_offset!");
                let aes_key_offset = br.read_i64().expect("Unable to read FileHeader.aes_key_offset!");
                let salted_hash = BHD5::read_salted_hash(br, salted_hash_offset);
                let aes_key = BHD5::read_aes_key(br, aes_key_offset);
                let mut file_size = -1;
                if format == BHD5Format::DarkSoulsIII {
                    file_size = br.read_i64().expect("Unable to read FileHeader.file_size!");
                }
                headers.push(FileHeader { file_path_hash, padded_file_size, file_size, file_offset, salted_hash_offset, aes_key_offset, salted_hash, aes_key })
            }

        }
        br.jmp(pos);
        return Ok(headers);
    }

    fn read_salted_hash(br: &mut BinaryReader, salted_hash_offset: i64) -> Option<SaltedHash> {
        if salted_hash_offset < 1 {
            return None;
        }

        let pos = br.pos;
        br.jmp(salted_hash_offset as usize);

        let hash = br.read_bytes(BHD5::SALTED_HASH_SIZE).expect("Could not read SaltedHash.hash!").to_vec();
        let range_count = br.read_i32().expect("Could not read SaltedHash.range_count!");
        let ranges = BHD5::read_ranges(br, range_count).expect("Could not parse SaltedHash.ranges!");;

        br.jmp(pos);

        Some(SaltedHash {
            hash,
            range_count,
            ranges,
            }
        )
    }

    fn read_aes_key(br: &mut BinaryReader, aes_key_offset: i64) -> Option<AESKey> {
        if aes_key_offset < 1 {
            return None;
        }

        let pos = br.pos;
        br.jmp(aes_key_offset as usize);

        let key = br.read_bytes(BHD5::AES_KEY_SIZE).expect("Could not read AESKey.key!").to_vec();
        let range_count = br.read_i32().expect("Could not read AESKey.range_count!");
        let ranges = BHD5::read_ranges(br, range_count).expect("Could not parse AESKey.ranges!");
        br.jmp(pos);

       Some(AESKey {
            key,
            range_count,
            ranges,
            }
       )
    }

    fn read_ranges(br: &mut BinaryReader, range_count: i32) -> Result<Vec<Range>, Error> {
        let mut ranges: Vec<Range> = Vec::with_capacity(range_count as usize);
        for _ in 0..range_count {
            let begin = br.read_i64().expect("Could not read Range.begin!");
            let end = br.read_i64().expect("Could not read Range.end!");
            ranges.push(Range { begin, end })
        }
        return Ok(ranges);
    }
}

fn check_bhd5_header(header: &BHD5Header) {
    assert_eq!(header.magic, "BHD5");
    assert_eq!(header.unk04, -1, "header.unk04: {}", header.unk04);
    assert!(header.unk05 == 0 || header.unk05 == 1, "header.unk05: {}", header.unk05);
    assert_eq!(header.unk06, 0, "header.unk06: {}", header.unk06);
    assert_eq!(header.unk07, 0, "header.unk07: {}", header.unk07);
    assert_eq!(header.unk08, 1, "header.unk08: {}", header.unk08);
}

fn get_bhd5_format(salt: &str) -> BHD5Format {
    if salt[..3].eq("GR_") {
        return BHD5Format::EldenRing;
    } else if salt[..4].eq("FDP_") || salt[..4].eq("NTC_") {
        return BHD5Format::DarkSoulsIII;
    }
    BHD5Format::DarkSoulsII
}


