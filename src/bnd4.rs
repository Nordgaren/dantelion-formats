struct BND4 {
    pub header: BND4Header,
    pub files: Vec<File>,
    pub buckets: BND4Bucket,
}

struct BND4Header {
    magic: String,
    unk04: u8,
    unk05: u8,
    unk06: u8,
    unk07: u8,
    unk08: u8,
    bigEndian: u8,
    unk0A: u8,
    unk0B: u8,
    fileCount: u32,
    headerSize: u64,
    version: String,
    fileHeaderSize: u64,
    fileHeadersEnd: u64,
    // Includes hash table
    unicode: u8,
    rawFormat: u8,
    extended: u8,
    unk33: u8,
    unk34: u32,
    bucketsOffset: u64,
    format: u8,
}

struct File {

}

struct BND4Bucket {

}

impl BND4 {
    const MAGIC_SIZE: usize = 4;
    const SALTED_HASH_SIZE: usize = 32;
    const AES_KEY_SIZE: usize = 16;

    pub fn from_path(path: &str) -> Result<BND4, std::io::Error> {


        todo!()
    }
}