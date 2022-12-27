use std::fs;
use std::io::Error;
use binary_reader::{BinaryReader, Endian};
use crate::util;

pub struct DCX {
    pub header: DCXHeader,
    pub content: Vec<u8>,
}

pub struct DCXHeader {
    pub magic: String,
    pub unk04: u32,
    pub dcsOffset: u32,
    pub dcpOffset: u32,
    pub unk10: u32,
    pub unk14: u32,
    // In EDGE, size from 0x20 to end of block headers
    pub dcs: String,
    pub uncompressedSize: u32,
    pub compressedSize: u32,
    pub dcp: String,
    pub format: String,
    pub unk2C: u32,
    pub unk30: u8,
    pub unk31: u8,
    pub unk32: u8,
    pub unk33: u8,
    pub unk34: u32,
    pub unk38: u32,
    pub unk3C: u32,
    pub unk40: u32,
    pub dca: String,
    pub dcaSize: u32,
    // From before "DCA" to dca end
    pub egdt: Option<String>,
    pub unk50: Option<u32>,
    pub unk54: Option<u32>,
    pub unk58: Option<u32>,
    pub unk5C: Option<u32>,
    pub lastBlockUncompressedSize: Option<u32>,
    pub egdtSize: Option<u32>,
    pub blockCount: Option<u32>,
    pub unk6C: Option<u32>,
    pub blocks: Option<Vec<Block>>,
}
#[derive(Clone)]
pub struct Block {
    pub unk00: u32,
    pub dataOffset: u32,
    pub dataLength: u32,
    pub unk0C: u32,
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

    fn decompress_bytes(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let dcx = DCX::from_bytes(bytes);

        todo!()
    }

    pub fn from_path(path: &str) -> Result<DCX, Error> {
        let file = fs::read(path)
            .expect(&format!("Could not read file: {path}"));

        Ok(DCX::from_bytes(&file).expect(&format!("Could not parse DCX file: {path}!")))
    }


    pub fn from_bytes(file: &[u8]) -> Result<DCX, Error> {
        let mut br = BinaryReader::from_u8(file);
        br.set_endian(Endian::Big);

        let mut header = DCXHeader {
            magic: util::read_fixed_string(&mut br, DCX::MAGIC_SIZE).expect("Could not parse DCXHeader.magic"),
            unk04: br.read_u32().expect("Could not parse DCXHeader.unk04"),
            dcsOffset: br.read_u32().expect("Could not parse DCXHeader.dcsOffset"),
            dcpOffset: br.read_u32().expect("Could not parse DCXHeader.dcpOffset"),
            unk10: br.read_u32().expect("Could not parse DCXHeader.unk10"),
            unk14: br.read_u32().expect("Could not parse DCXHeader.unk14"),
            dcs: util::read_fixed_string(&mut br, DCX::DCS_SIZE).expect("Could not parse DCXHeader.dcs"),
            uncompressedSize: br.read_u32().expect("Could not parse DCXHeader.uncompressedSize"),
            compressedSize: br.read_u32().expect("Could not parse DCXHeader.compressedSize"),
            dcp: util::read_fixed_string(&mut br, DCX::DCP_SIZE).expect("Could not parse DCXHeader.dcp"),
            format: util::read_fixed_string(&mut br, DCX::FORMAT_SIZE).expect("Could not parse DCXHeader.format"),
            unk2C: br.read_u32().expect("Could not parse DCXHeader.unk2C"),
            unk30: br.read_u8().expect("Could not parse DCXHeader.unk30"),
            unk31: br.read_u8().expect("Could not parse DCXHeader.unk31"),
            unk32: br.read_u8().expect("Could not parse DCXHeader.unk32"),
            unk33: br.read_u8().expect("Could not parse DCXHeader.unk33"),
            unk34: br.read_u32().expect("Could not parse DCXHeader.unk34"),
            unk38: br.read_u32().expect("Could not parse DCXHeader.unk38"),
            unk3C: br.read_u32().expect("Could not parse DCXHeader.unk3C"),
            unk40: br.read_u32().expect("Could not parse DCXHeader.unk40"),
            dca: util::read_fixed_string(&mut br, DCX::DCA_SIZE).expect("Could not parse DCXHeader.dca"),
            dcaSize: br.read_u32().expect("Could not parse DCXHeader.dcaSize"),
            egdt: None,
            unk50: None,
            unk54: None,
            unk58: None,
            unk5C: None,
            lastBlockUncompressedSize: None,
            egdtSize: None,
            blockCount: None,
            unk6C: None,
            blocks: None,
        };

        if header.format == "EDGE" {
            header.egdt = Some(util::read_fixed_string(&mut br, DCX::EGDT_SIZE).expect("Could not parse DCXHeader.egdt"));
            header.unk50 = Some(br.read_u32().expect("Could not parse DCXHeader.unk50"));
            header.unk54 = Some(br.read_u32().expect("Could not parse DCXHeader.unk54"));
            header.unk58 = Some(br.read_u32().expect("Could not parse DCXHeader.unk58"));
            header.unk5C = Some(br.read_u32().expect("Could not parse DCXHeader.unk5C"));
            header.lastBlockUncompressedSize = Some(br.read_u32().expect("Could not parse DCXHeader.lastBlockUncompressedSize"));
            header.egdtSize = Some(br.read_u32().expect("Could not parse DCXHeader.egdtSize"));
            header.blockCount = Some(br.read_u32().expect("Could not parse DCXHeader.blockCount"));
            header.unk6C = Some(br.read_u32().expect("Could not parse DCXHeader.unk6C"));
            header.blocks = read_blocks(&mut br, header.blockCount.unwrap());
        }

        validate_dcx_header(&header);

        let content = read_content(&mut br, &header).expect("Could not parse DCX.content");

        Ok(DCX {
            header,
            content,
        })
    }
}

fn read_content(br: &mut BinaryReader, header: &DCXHeader) -> Result<Vec<u8>, Error> {
    // Will have to look at a file.
    // if header.format == "EDGE" {
    //     let dataPos = br.pos;
    //     for block in header.blocks.unwrap() {
    //         br.pos = dataPos + block.dataOffset;
    //
    //     }
    // }

    Ok(br.read_bytes(header.compressedSize as usize)?.to_vec())
}

fn read_blocks(br: &mut BinaryReader, count: u32) -> Option<Vec<Block>> {
    let mut blocks = Vec::with_capacity(count as usize);
    for i in 0..count {
        let block = Block {
            unk00: br.read_u32().expect("Could not parse Block.unk00"),
            dataOffset: br.read_u32().expect("Could not parse Block.dataOffset"),
            dataLength: br.read_u32().expect("Could not parse Block.dataLength"),
            unk0C: br.read_u32().expect("Could not parse Block.unk0C"),
        };
        blocks.push(block);
    }

    Some(blocks)
}

fn validate_dcx_header(header: &DCXHeader) {
    assert_eq!(header.magic, "DCX\0", "Magic was {}", header.magic);
    assert!(header.unk04 == 0x10000 || header.unk04 == 0x11000, "DCXHeader.unk04 was {}", header.unk04);
    assert_eq!(header.dcsOffset, 0x18, "header.dcsOffset was {}", header.dcsOffset);
    assert_eq!(header.dcpOffset, 0x24, "header.dcpOffset was {}", header.dcpOffset);
    assert!(header.unk10 == 0x24 || header.unk10 == 0x44, "header.unk10 was {}", header.unk10);
    assert_eq!(header.dcs, "DCS\0", "header.dcs was {}", header.dcs);
    assert_eq!(header.dcp, "DCP\0", "header.dcp was {}", header.dcp);
    assert!(header.format == "DFLT" || header.format == "EDGE" || header.format == "KRAK", "header.format was {}", header.format);
    assert_eq!(header.unk2C, 0x20, "header.unk2C was {}", header.unk2C);
    assert!(header.unk30 == 6 || header.unk30 == 8 || header.unk30 == 9, "header.unk30 was {}", header.unk30);
    assert_eq!(header.unk31, 0, "header.unk31 was {}", header.unk31);
    assert_eq!(header.unk32, 0, "header.unk32 was {}", header.unk32);
    assert_eq!(header.unk33, 0, "header.unk33 was {}", header.unk33);
    assert!(header.unk34 == 0 || header.unk34 == 0x10000, "header.dcxOffset was {}", header.unk34);
    assert_eq!(header.unk38, 0, "header.unk38 was {}", header.unk38);
    assert_eq!(header.unk3C, 0, "header.unk3C was {}", header.unk3C);
    assert_eq!(header.dca, "DCA\0", "header.dca was {}", header.dca);

    if header.format == "EDGE" {
        let egdt = header.egdt.clone().unwrap();
        assert_eq!(egdt, "EgdT", "header.egdt was {}", egdt);
        let unk50 = header.unk50.clone().unwrap();
        assert_eq!(unk50, 0x10100, "header.unk3C was {}", unk50);
        let unk54 = header.unk54.clone().unwrap();
        assert_eq!(unk54, 0x24, "header.unk54 was {}", unk54);
        let unk58 = header.unk58.clone().unwrap();
        assert_eq!(unk58, 0x10, "header.unk58 was {}", unk58);
        let unk5C = header.unk5C.clone().unwrap();
        assert_eq!(unk5C, 0x10000, "header.unk5C was {}", unk5C);
        let unk6C = header.unk6C.clone().unwrap();
        assert_eq!(unk6C, 0x100000, "header.unk6C was {}", unk6C);

        for block in header.blocks.clone().unwrap() {
            assert_eq!(block.unk00, 0, "block.unk00 was {}", block.unk00);
            assert_eq!(block.unk0C, 1, "block.unk0C was {}", block.unk0C);
        }
    }
}