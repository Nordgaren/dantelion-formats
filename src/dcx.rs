struct DCX {
    header: DCXHeader,
    content: Vec<u8>
}

struct DCXHeader {
    magic: String,
    unk04: u32,
    dcsOffset: u32,
    dcpOffset: u32,
    unk10: u32,
    unk14: u32, // In EDGE, size from 0x20 to end of block headers
    dcs: String,
    uncompressedSize: u32,
    compressedSize: u32,
    dcp: String,
    format: String,
    unk2C: u32,
    unk30: u8,
    unk31: u8,
    unk32: u8,
    unk33: u8,
    unk34: u32,
    unk38: u32,
    unk3C: u32,
    unk40: u32,
    dca: String,
    dcaSize: u32,// From before "DCA" to dca end
    egdt: String,
    unk50: u32,
    unk54: u32,
    unk58: u32,
    unk5C: u32,
    lastBlockUncompressedSize: u32,
    egdtSize: u32,
    blockCount: u32,
    unk6C: u32,
}

impl DCX {
    const MAGIC_SIZE: usize = 4;
    const DCS_SIZE: usize = 4;
    const DCP_SIZE: usize = 4;
    const FORMAT_SIZE: usize = 4;
    const DCA_SIZE: usize = 4;
    const EGDT_SIZE: usize = 4;

    fn read_dcx_header() -> Result<DCX, std::io::Error> {
        todo!()
    }

    fn decompress(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut br = BinaryReader::from_u8(file);
        br.set_endian(Endian::Little);

        let magic_bytes = br.read_bytes(DCX::MAGIC_SIZE).expect("Could not read magic bytes");
        let magic = String::from_utf8(magic_bytes.to_vec()).expect("Could not parse DCXHeader.magic");

        let mut header = DCXHeader {
            magic,
            unk04: 0,
            dcsOffset: 0,
            dcpOffset: 0,
            unk10: 0,
            unk14: 0,
            dcs: "".to_string(),
            uncompressedSize: 0,
            compressedSize: 0,
            dcp: "".to_string(),
            format: "".to_string(),
            unk2C: 0,
            unk30: 0,
            unk31: 0,
            unk32: 0,
            unk33: 0,
            unk34: 0,
            unk38: 0,
            unk3C: 0,
            unk40: 0,
            dca: "".to_string(),
            dcaSize: 0,
            egdt: "".to_string(),
            unk50: 0,
            unk54: 0,
            unk58: 0,
            unk5C: 0,
            lastBlockUncompressedSize: 0,
            egdtSize: 0,
            blockCount: 0,
            unk6C: 0,
        };

        todo!()
    }

}