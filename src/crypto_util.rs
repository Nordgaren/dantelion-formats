use std::{fs, io};
use std::io::{Result, Read, Error, ErrorKind};
use std::path::Path;
use openssl::symm::*;
use openssl::rsa::{Padding, Rsa};

pub(crate) fn decrypt_regulation(file: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let iv = &file[..16];
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
    crypter.pad(false);
    let encypted = &file[16..];
    let mut out = vec![0; file.len() + cipher.block_size()];
    let count = crypter.update(encypted, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;
    out.truncate(count + rest);
    Ok(out)
}

pub(crate) fn decrypt_bhd5_file(file: &[u8], key: &[u8]) -> Result<Vec<u8>> {

    // Read the private key from a PEM file
    let public_key = Rsa::public_key_from_pem_pkcs1(key)?;

    // Decrypt the data using the private key
    let key_size = public_key.size() as usize;
    let mut len = 0;
    let mut decrypted_data: Vec<u8> = vec!();

    while len < file.len() {
        let mut decrypted_block = vec![0; key_size];
        let next_block: usize = (len + key_size);
        let block_data = &file[len..next_block];
        len += public_key.public_decrypt(block_data, &mut decrypted_block, Padding::NONE)?;
        decrypted_data.extend_from_slice(&decrypted_block[1..]);
    }

    // Trim the decrypted data to the actual length
    decrypted_data.truncate(len as usize);

    return Ok(decrypted_data);
}

pub(crate) fn get_elden_ring_bhd5_key(path: &str) -> Result<&[u8]> {
    let file_name = Path::new(path)
        .file_stem().unwrap().to_str().unwrap();
    for key in ELDEN_RING_KEYS {
        if key.0 == file_name {
            return Ok(key.1.as_bytes());
        }
    }

    Err(Error::new(ErrorKind::NotFound, format!("Could not find key for {}", file_name)))
}

pub(crate) const ER_REGULATION_KEY: [u8; 0x20] = [0x99, 0xBF, 0xFC, 0x36, 0x6A, 0x6B, 0xC8, 0xC6, 0xF5,
    0x82, 0x7D, 0x09, 0x36, 0x02, 0xD6, 0x76, 0xC4, 0x28, 0x92, 0xA0, 0x1C, 0x20, 0x7F, 0xB0, 0x24,
    0xD3, 0xAF, 0x4E, 0x49, 0x3F, 0xEF, 0x99];

pub(crate) static ELDEN_RING_KEYS: [(&str, &str); 5] = [
    ("Data0",
     "-----BEGIN RSA PUBLIC KEY-----
MIIBCwKCAQEA9Rju2whruXDVQZpfylVEPeNxm7XgMHcDyaaRUIpXQE0qEo+6Y36L
P0xpFvL0H0kKxHwpuISsdgrnMHJ/yj4S61MWzhO8y4BQbw/zJehhDSRCecFJmFBz
3I2JC5FCjoK+82xd9xM5XXdfsdBzRiSghuIHL4qk2WZ/0f/nK5VygeWXn/oLeYBL
jX1S8wSSASza64JXjt0bP/i6mpV2SLZqKRxo7x2bIQrR1yHNekSF2jBhZIgcbtMB
xjCywn+7p954wjcfjxB5VWaZ4hGbKhi1bhYPccht4XnGhcUTWO3NmJWslwccjQ4k
sutLq3uRjLMM0IeTkQO6Pv8/R7UNFtdCWwIERzH8IQ==
-----END RSA PUBLIC KEY-----"),
    ("Data1",
     "-----BEGIN RSA PUBLIC KEY-----
MIIBCwKCAQEAxaBCHQJrtLJiJNdG9nq3deA9sY4YCZ4dbTOHO+v+YgWRMcE6iK6o
ZIJq+nBMUNBbGPmbRrEjkkH9M7LAypAFOPKC6wMHzqIMBsUMuYffulBuOqtEBD11
CAwfx37rjwJ+/1tnEqtJjYkrK9yyrIN6Y+jy4ftymQtjk83+L89pvMMmkNeZaPON
4O9q5M9PnFoKvK8eY45ZV/Jyk+Pe+xc6+e4h4cx8ML5U2kMM3VDAJush4z/05hS3
/bC4B6K9+7dPwgqZgKx1J7DBtLdHSAgwRPpijPeOjKcAa2BDaNp9Cfon70oC+ZCB
+HkQ7FjJcF7KaHsH5oHvuI7EZAl2XTsLEQIENa/2JQ==
-----END RSA PUBLIC KEY-----"),
    ("Data2",
     "-----BEGIN RSA PUBLIC KEY-----
MIIBDAKCAQEA0iDVVQ230RgrkIHJNDgxE7I/2AaH6Li1Eu9mtpfrrfhfoK2e7y4O
WU+lj7AGI4GIgkWpPw8JHaV970Cr6+sTG4Tr5eMQPxrCIH7BJAPCloypxcs2BNfT
GXzm6veUfrGzLIDp7wy24lIA8r9ZwUvpKlN28kxBDGeCbGCkYeSVNuF+R9rN4OAM
RYh0r1Q950xc2qSNloNsjpDoSKoYN0T7u5rnMn/4mtclnWPVRWU940zr1rymv4Jc
3umNf6cT1XqrS1gSaK1JWZfsSeD6Dwk3uvquvfY6YlGRygIlVEMAvKrDRMHylsLt
qqhYkZNXMdy0NXopf1rEHKy9poaHEmJldwIFAP////8=
-----END RSA PUBLIC KEY-----"),
    ("Data3",
     "-----BEGIN RSA PUBLIC KEY-----
MIIBCwKCAQEAvRRNBnVq3WknCNHrJRelcEA2v/OzKlQkxZw1yKll0Y2Kn6G9ts94
SfgZYbdFCnIXy5NEuyHRKrxXz5vurjhrcuoYAI2ZUhXPXZJdgHywac/i3S/IY0V/
eDbqepyJWHpP6I565ySqlol1p/BScVjbEsVyvZGtWIXLPDbx4EYFKA5B52uK6Gdz
4qcyVFtVEhNoMvg+EoWnyLD7EUzuB2Khl46CuNictyWrLlIHgpKJr1QD8a0ld0PD
PHDZn03q6QDvZd23UW2d9J+/HeBt52j08+qoBXPwhndZsmPMWngQDaik6FM7EVRQ
etKPi6h5uprVmMAS5wR/jQIVTMpTj/zJdwIEXszeQw==
-----END RSA PUBLIC KEY-----"),
    ("sd\\sd",
     "-----BEGIN RSA PUBLIC KEY-----
MIIBCwKCAQEAmYJ/5GJU4boJSvZ81BFOHYTGdBWPHnWYly3yWo01BYjGRnz8NTkz
DHUxsbjIgtG5XqsQfZstZILQ97hgSI5AaAoCGrT8sn0PeXg2i0mKwL21gRjRUdvP
Dp1Y+7hgrGwuTkjycqqsQ/qILm4NvJHvGRd7xLOJ9rs2zwYhceRVrq9XU2AXbdY4
pdCQ3+HuoaFiJ0dW0ly5qdEXjbSv2QEYe36nWCtsd6hEY9LjbBX8D1fK3D2c6C0g
NdHJGH2iEONUN6DMK9t0v2JBnwCOZQ7W+Gt7SpNNrkx8xKEM8gH9na10g9ne11Mi
O1FnLm8i4zOxVdPHQBKICkKcGS1o3C2dfwIEXw/f3w==
-----END RSA PUBLIC KEY-----")
];
