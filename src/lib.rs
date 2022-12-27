extern crate core;

mod crypto_util;
mod bhd5;
mod dcx;
mod bnd4;
mod util;


const TEST_DECRYPT_PATH: &str = ".decrypted";
const TEST_BHD5_PATH: &str = "G:\\Steam\\steamapps\\common\\ELDEN RING\\Game\\Data0.bhd";
const TEST_BND4_PATH: &str = "G:\\Steam\\steamapps\\common\\DARK SOULS III - Copy\\Game\\parts\\am_m_6200.partsbnd.dcx";

#[cfg(test)]
mod tests {
    use std::fs;
    use openssl::rsa::Rsa;
    use crate::bhd5::{BHD5, BHD5Format};
    use super::*;
    use crate::dcx::*;

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
    fn parse_bhd5()
    {
        let bhd5 = BHD5::from_path(&TEST_BHD5_PATH).expect("Could not parse BHD5");
        assert!(bhd5.format == BHD5Format::EldenRing);
    }

    #[test]
    fn read_bnd4() {
        let file = fs::read(TEST_BND4_PATH)
            .expect(&format!("Could not read file: {TEST_BND4_PATH}"));
    }

    #[test]
    fn read_dcx() {
        let file = fs::read(TEST_BND4_PATH)
            .expect(&format!("Could not read file: {TEST_BND4_PATH}"));

        let dcx = DCX::from_bytes(file.as_slice()).expect("Could not get DCX from Bytes");

        assert_eq!(dcx.header.format, "DFLT");
    }

    #[test]
    fn oodle_install_path() {
        let path = util::get_oodle_install_path();
    }
}
