extern crate core;

mod crypto_util;
mod bhd5;
mod dcx;
mod bnd4;
mod util;
mod oodle;


const TEST_DECRYPT_PATH: &str = ".decrypted";
const TEST_DECOMPRESSED_PATH: &str = ".decompressed";
const TEST_BHD5_PATH: &str = r"G:\Steam\steamapps\common\ELDEN RING\\Game\\Data0.bhd";
const TEST_KRAKEN_PATH: &str = r"G:\Steam\steamapps\common\ELDEN RING\Game\parts\am_m_1600_l.partsbnd.dcx";
const TEST_BND4_PATH: &str = r"G:\Steam\steamapps\common\DARK SOULS III - Copy\\Game\parts\am_m_6200.partsbnd.dcx";
const ER_REGULATION_PATH: &str = r"G:\Steam\steamapps\common\ELDEN RING\Game\regulation.bin";

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use openssl::rsa::Rsa;
    use crate::bhd5::{BHD5, BHD5Format};
    use super::*;
    use crate::dcx::*;
    use crate::bnd4::*;

    #[test]
    fn read_bhd5() {
        let file = fs::read(TEST_BHD5_PATH)
            .expect(&format!("Could not read file: {TEST_BHD5_PATH}"));

        let key = crypto_util::get_elden_ring_bhd5_key(TEST_BHD5_PATH);
        let decrypted = crypto_util::decrypt_bhd5_file(file.as_slice(), key)
            .expect("Unable to decrypt BHD5!");

        let magic = String::from_utf8(Vec::from(&decrypted[..4]))
            .expect("Could not parse string");

        assert_eq!(magic, "BHD5")
    }

    #[test]
    fn decrypt_regulation() {
        let file = fs::read(ER_REGULATION_PATH)
            .expect(&format!("Could not read file: {ER_REGULATION_PATH}"));

        let decrypted = crypto_util::decrypt_regulation(file.as_slice(), &crypto_util::ER_REGULATION_KEY)
            .expect("Unable to decrypt regulation!");

        let dcx = DCX::from_bytes(&decrypted).expect("Could not parse DCX");
        assert_eq!(dcx.header.magic, "DCX\0");

        let bnd = BND4::from_bytes(&dcx.decompress().expect("Could not decompress DCX")).expect("Could not parse BND4");

        for file in bnd.files {
            println!("{}", file.name.unwrap());
        }

        assert_eq!(bnd.header.magic, "BND4");
    }

    #[test]
    fn parse_bhd5()
    {
        let bhd5 = BHD5::from_path(&TEST_BHD5_PATH).expect("Could not parse BHD5");
        assert!(bhd5.format == BHD5Format::EldenRing);
    }

    #[test]
    fn read_bnd4() {
        let bnd4 = BND4::from_path(TEST_BND4_PATH).unwrap();
    }

    #[test]
    fn read_oodle_compressed_bnd4() {
        let bnd4 = BND4::from_path(TEST_KRAKEN_PATH).expect("Could not read oodle compressed BND4");
        for file  in bnd4.files {
            println!("{}", file.name.unwrap());
        }
    }

    #[test]
    fn read_dflt_dcx() {
        let file = fs::read(TEST_BND4_PATH)
            .expect(&format!("Could not read file: {TEST_BND4_PATH}"));

        let dcx = DCX::from_bytes(file.as_slice()).expect("Could not get DCX from Bytes");

        //fs::write(&format!("{}{}",TEST_BND4_PATH, TEST_DECOMPRESSED_PATH), dcx.decompress().unwrap()).expect("Could not write decompress video");
        assert_eq!(dcx.header.format, "DFLT");
    }

    #[test]
    fn read_krak_dcx() {
        let file = fs::read(TEST_KRAKEN_PATH)
            .expect(&format!("Could not read file: {TEST_KRAKEN_PATH}"));

        let dcx = DCX::from_bytes(file.as_slice()).expect("Could not get DCX from Bytes");

        //fs::write(&format!("{}{}",TEST_KRAKEN_PATH, TEST_DECOMPRESSED_PATH), dcx.decompress().unwrap()).expect("Could not write decompress video");
        assert_eq!(dcx.header.format, "KRAK");
    }

    #[test]
    fn oodle_install_path() {
        let path = util::get_oodle_install_path();
        assert!( Path::new(&path).exists())
    }
}
