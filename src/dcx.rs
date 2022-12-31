use std::fs;
use std::io::{Cursor, Error, ErrorKind};
use std::string::FromUtf8Error;
use binary_interpreter::binary_reader::BinaryReader;
use byteorder::{BE, ReadBytesExt};
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
    pub egdt: Option<EGDTHeader>
}
#[derive(Clone)]
#[repr(C)]
pub struct EGDTHeader {
    pub egdt: String,
    pub unk50: u32,
    pub unk54: u32,
    pub unk58: u32,
    pub unk5c: u32,
    pub last_block_uncompressed_size: u32,
    pub egdt_size: u32,
    pub block_count: u32,
    pub unk6c: u32,
    pub blocks: Vec<Block>,
}

#[derive(Clone)]
#[repr(C)]
pub struct Block {
    pub unk00: u32,
    pub data_offset: u32,
    pub data_length: u32,
    pub unk0c: u32,
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
        let mut c = Cursor::new(file);

        let mut header = DCX::read_dcx_header(&mut c)?;

        let content = DCX::read_content(&mut c, &header)?;

        Ok(DCX {
            header,
            content,
        })
    }

    fn read_dcx_header(c: &mut Cursor<&[u8]>) -> Result<DCXHeader, DantelionFormatsError>  {

        let mut header = DCXHeader {
            magic: c.read_fixed_cstr( DCX::MAGIC_SIZE)?,
            unk04: c.read_u32::<BE>()?,
            dcs_offset: c.read_u32::<BE>()?,
            dcp_offset: c.read_u32::<BE>()?,
            unk10: c.read_u32::<BE>()?,
            unk14: c.read_u32::<BE>()?,
            dcs: c.read_fixed_cstr(DCX::DCS_SIZE)?,
            uncompressed_size: c.read_u32::<BE>()?,
            compressed_size: c.read_u32::<BE>()?,
            dcp: c.read_fixed_cstr(DCX::DCP_SIZE)?,
            format: c.read_fixed_cstr(DCX::FORMAT_SIZE)?,
            unk2C: c.read_u32::<BE>()?,
            unk30: c.read_u8()?,
            unk31: c.read_u8()?,
            unk32: c.read_u8()?,
            unk33: c.read_u8()?,
            unk34: c.read_u32::<BE>()?,
            unk38: c.read_u32::<BE>()?,
            unk3C: c.read_u32::<BE>()?,
            unk40: c.read_u32::<BE>()?,
            dca: c.read_fixed_cstr(DCX::DCA_SIZE)?,
            dca_size: c.read_u32::<BE>()?,
            egdt: None,

        };

        if header.format == "EDGE" {
            header.egdt = Some(DCX::read_egdt_header(c)?);
        }

        header.validate();

        Ok(header)
    }

    fn read_egdt_header(c: &mut Cursor<&[u8]>) -> Result<EGDTHeader, DantelionFormatsError> {
        let egdt =  c.read_fixed_cstr(DCX::EGDT_SIZE)?;
        let unk50 =  c.read_u32::<BE>()?;
        let unk54 =  c.read_u32::<BE>()?;
        let unk58 =  c.read_u32::<BE>()?;
        let unk5c =  c.read_u32::<BE>()?;
        let last_block_uncompressed_size =  c.read_u32::<BE>()?;
        let egdt_size =  c.read_u32::<BE>()?;
        let block_count =  c.read_u32::<BE>()?;
        let unk6c =  c.read_u32::<BE>()?;
        let blocks =  DCX::read_blocks(c, block_count)?;

        let egdt = EGDTHeader {
            egdt: egdt,
            unk50,
            unk54,
            unk58,
            unk5c,
            last_block_uncompressed_size,
            egdt_size,
            block_count,
            unk6c,
            blocks,
        };

        Ok(egdt)
    }

    fn read_content(c: &mut Cursor<&[u8]>, header: &DCXHeader) -> Result<Vec<u8>, DantelionFormatsError> {
        // Will have to look at a file.
        // if header.format == "EDGE" {
        //     let start = br.pos;
        //     for block in header.blocks.unwrap() {
        //         br.pos = start + block.data_offset;
        //
        //     }
        // }

        Ok(c.read_bytes(header.compressed_size as usize)?)
    }

    fn read_blocks(c: &mut Cursor<&[u8]>, count: u32) -> Result<Vec<Block>, DantelionFormatsError> {
        let mut blocks = Vec::with_capacity(count as usize);
        for i in 0..count {
            let block = Block {
                unk00: c.read_u32::<BE>()?,
                data_offset: c.read_u32::<BE>()?,
                data_length: c.read_u32::<BE>()?,
                unk0c: c.read_u32::<BE>()?,
            };
            blocks.push(block);
        }

        Ok(blocks)
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
            assert_eq!(egdt.egdt, "EgdT", "self.egdt was {}", egdt.egdt);
            assert_eq!(egdt.unk50, 0x10100, "self.unk3C was {}", egdt.unk50);
            assert_eq!(egdt.unk54, 0x24, "self.unk54 was {}", egdt.unk54);
            assert_eq!(egdt.unk58, 0x10, "self.unk58 was {}", egdt.unk58);
            assert_eq!(egdt.unk5c, 0x10000, "self.unk5C was {}", egdt.unk5c);
            assert_eq!(egdt.unk6c, 0x100000, "self.unk6C was {}", egdt.unk6c);

            for block in egdt.blocks {
                assert_eq!(block.unk00, 0, "block.unk00 was {}", block.unk00);
                assert_eq!(block.unk0c, 1, "block.unk0c was {}", block.unk0c);
            }
        }
    }
}
