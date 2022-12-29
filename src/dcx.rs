use std::fs;
use std::io::{Error, ErrorKind};
use std::string::FromUtf8Error;
use binary_reader::{BinaryReader, Endian};
use miniz_oxide::inflate::core::decompress;
use miniz_oxide::inflate::decompress_to_vec;
use crate::{oodle, util};
use crate::error::DantelionFormatsError;
use crate::util::Validate;

#[repr(C)]
pub struct DCX {
    pub header: DCXHeader,
    pub content: Vec<u8>,
}

#[repr(C)]
pub struct DCXHeader {
    pub magic: String,
    pub unk04: u32,
    pub dcs_offset: u32,
    pub dcp_offset: u32,
    pub unk10: u32,
    pub unk14: u32,
    // In EDGE, size from 0x20 to end of block headers
    pub dcs: String,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
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
    pub dca_size: u32,
    // From before "DCA" to dca end
    pub egdt: Option<String>,
    pub unk50: Option<u32>,
    pub unk54: Option<u32>,
    pub unk58: Option<u32>,
    pub unk5C: Option<u32>,
    pub last_block_uncompressed_size: Option<u32>,
    pub egdt_size: Option<u32>,
    pub block_count: Option<u32>,
    pub unk6C: Option<u32>,
    pub blocks: Option<Vec<Block>>,
}

#[derive(Clone)]
#[repr(C)]
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

    pub(crate) fn is(bytes: &[u8]) -> bool {
        &bytes[..4] == b"DCX\0"
    }

    pub fn decompress_bytes(bytes: &[u8]) -> Result<Vec<u8>, DantelionFormatsError> {
        let dcx = DCX::from_bytes(bytes)?;
        dcx.decompress()
    }

    pub fn decompress(&self) -> Result<Vec<u8>, DantelionFormatsError> {
        if self.header.format == "KRAK" {
            unsafe {
                    return Ok(oodle::decompress(&self.content[..], self.header.uncompressed_size as usize)?)
            }
        }

        assert_eq!(self.content[0], 0x78);
        assert!(self.content[1] == 0x01 || self.content[1] == 0x05E || self.content[1] == 0x9C || self.content[1] == 0xDA);
        Ok(decompress_to_vec(&self.content[2..])?)
    }

    pub fn from_path(path: &str) -> Result<DCX, DantelionFormatsError> {
        let file = fs::read(path)?;

        DCX::from_bytes(&file)
    }


    pub fn from_bytes(file: &[u8]) -> Result<DCX, DantelionFormatsError> {
        let mut br = BinaryReader::from_u8(file);
        br.set_endian(Endian::Big);

        let mut header = DCXHeader {
            magic: util::read_fixed_string(&mut br, DCX::MAGIC_SIZE)?,
            unk04: br.read_u32()?,
            dcs_offset: br.read_u32()?,
            dcp_offset: br.read_u32()?,
            unk10: br.read_u32()?,
            unk14: br.read_u32()?,
            dcs: util::read_fixed_string(&mut br, DCX::DCS_SIZE)?,
            uncompressed_size: br.read_u32()?,
            compressed_size: br.read_u32()?,
            dcp: util::read_fixed_string(&mut br, DCX::DCP_SIZE)?,
            format: util::read_fixed_string(&mut br, DCX::FORMAT_SIZE)?,
            unk2C: br.read_u32()?,
            unk30: br.read_u8()?,
            unk31: br.read_u8()?,
            unk32: br.read_u8()?,
            unk33: br.read_u8()?,
            unk34: br.read_u32()?,
            unk38: br.read_u32()?,
            unk3C: br.read_u32()?,
            unk40: br.read_u32()?,
            dca: util::read_fixed_string(&mut br, DCX::DCA_SIZE)?,
            dca_size: br.read_u32()?,
            egdt: None,
            unk50: None,
            unk54: None,
            unk58: None,
            unk5C: None,
            last_block_uncompressed_size: None,
            egdt_size: None,
            block_count: None,
            unk6C: None,
            blocks: None,
        };

        if header.format == "EDGE" {
            header.egdt = Some(util::read_fixed_string(&mut br, DCX::EGDT_SIZE)?);
            header.unk50 = Some(br.read_u32()?);
            header.unk54 = Some(br.read_u32()?);
            header.unk58 = Some(br.read_u32()?);
            header.unk5C = Some(br.read_u32()?);
            header.last_block_uncompressed_size = Some(br.read_u32()?);
            header.egdt_size = Some(br.read_u32()?);
            header.block_count = Some(br.read_u32()?);
            header.unk6C = Some(br.read_u32()?);
            header.blocks = Some(read_blocks(&mut br, header.block_count.unwrap())?);
        }

        header.validate();

        let content = read_content(&mut br, &header)?;

        Ok(DCX {
            header,
            content,
        })
    }
}

impl Validate for DCXHeader {
    fn validate(&self) {
        assert_eq!(self.magic, "DCX\0", "Magic was {}", self.magic);
        assert!(self.unk04 == 0x10000 || self.unk04 == 0x11000, "DCXself.unk04 was {}", self.unk04);
        assert_eq!(self.dcs_offset, 0x18, "self.dcs_offset was {}", self.dcs_offset);
        assert_eq!(self.dcp_offset, 0x24, "self.dcp_offset was {}", self.dcp_offset);
        assert!(self.unk10 == 0x24 || self.unk10 == 0x44, "self.unk10 was {}", self.unk10);
        assert_eq!(self.dcs, "DCS\0", "self.dcs was {}", self.dcs);
        assert_eq!(self.dcp, "DCP\0", "self.dcp was {}", self.dcp);
        assert!(self.format == "DFLT" || self.format == "EDGE" || self.format == "KRAK", "self.format was {}", self.format);
        assert_eq!(self.unk2C, 0x20, "self.unk2C was {}", self.unk2C);
        assert!(self.unk30 == 6 || self.unk30 == 8 || self.unk30 == 9, "self.unk30 was {}", self.unk30);
        assert_eq!(self.unk31, 0, "self.unk31 was {}", self.unk31);
        assert_eq!(self.unk32, 0, "self.unk32 was {}", self.unk32);
        assert_eq!(self.unk33, 0, "self.unk33 was {}", self.unk33);
        assert!(self.unk34 == 0 || self.unk34 == 0x10000, "self.dcxOffset was {}", self.unk34);
        assert!(self.unk38 == 0 || self.unk38 == 0xF000000, "self.dcxOffset was {}", self.unk38);
        assert_eq!(self.unk3C, 0, "self.unk3C was {}", self.unk3C);
        assert_eq!(self.dca, "DCA\0", "self.dca was {}", self.dca);

        if self.format == "EDGE" {
            let egdt = self.egdt.clone().unwrap();
            assert_eq!(egdt, "EgdT", "self.egdt was {}", egdt);
            let unk50 = self.unk50.clone().unwrap();
            assert_eq!(unk50, 0x10100, "self.unk3C was {}", unk50);
            let unk54 = self.unk54.clone().unwrap();
            assert_eq!(unk54, 0x24, "self.unk54 was {}", unk54);
            let unk58 = self.unk58.clone().unwrap();
            assert_eq!(unk58, 0x10, "self.unk58 was {}", unk58);
            let unk5c = self.unk5C.clone().unwrap();
            assert_eq!(unk5c, 0x10000, "self.unk5C was {}", unk5c);
            let unk6c = self.unk6C.clone().unwrap();
            assert_eq!(unk6c, 0x100000, "self.unk6C was {}", unk6c);

            for block in self.blocks.clone().unwrap() {
                assert_eq!(block.unk00, 0, "block.unk00 was {}", block.unk00);
                assert_eq!(block.unk0C, 1, "block.unk0C was {}", block.unk0C);
            }
        }
    }
}

fn read_content(br: &mut BinaryReader, header: &DCXHeader) -> Result<Vec<u8>, DantelionFormatsError> {
    // Will have to look at a file.
    // if header.format == "EDGE" {
    //     let start = br.pos;
    //     for block in header.blocks.unwrap() {
    //         br.pos = start + block.dataOffset;
    //
    //     }
    // }

    Ok(br.read_bytes(header.compressed_size as usize)?.to_vec())
}

fn read_blocks(br: &mut BinaryReader, count: u32) -> Result<Vec<Block>, DantelionFormatsError> {
    let mut blocks = Vec::with_capacity(count as usize);
    for i in 0..count {
        let block = Block {
            unk00: br.read_u32()?,
            dataOffset: br.read_u32()?,
            dataLength: br.read_u32()?,
            unk0C: br.read_u32()?,
        };
        blocks.push(block);
    }

    Ok(blocks)
}

