use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, ErrorKind};
use std::mem::size_of;
use std::path::Path;
use std::string::FromUtf8Error;
use binary_reader::{BinaryReader, Endian};
use winreg;
use winreg::enums::*;
use winreg::{HKEY, RegKey};
use crate::error::DantelionFormatsError;

pub trait Validate {
    fn validate(&self);
}

pub(crate) static STEAM_REGISTRY_LOCATIONS: [(&str, &str, &str); 4] = [
    ("HKCU", r"SOFTWARE\Valve\Steam", "SteamPath"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Valve\Steam", "InstallPath"),
    ("HKLM", r"SOFTWARE\Valve\Steam", "InstallPath"),
    ("HKCU", r"SOFTWARE\Wow6432Node\Valve\Steam", "SteamPath"),
];

// Works, for now...
pub fn get_oodle_path() -> Option<String> {
    if Path::new("oo2core_6_win64.dll").exists() {
        return Some("oo2core_6_win64.dll".to_string());
    }

    let steam_path = get_steam_install_path();
    match steam_path {
        None => return None,
        Some(path) => {
            return Some(search_steam_for_oodle(path)?);
        }
    }

}

fn search_steam_for_oodle(steam_path: String) -> Option<String> {
    let vdf = match File::open(format!(r"{steam_path}/SteamApps/libraryfolders.vdf")) {
        Ok(vdf) => vdf,
        Err(_) => return None
    };

    let library_folders = BufReader::new(vdf);

    for line in library_folders.lines().map(|x| x.unwrap()).skip_while(|p| p.contains("\"path\"")) {
        let split: Vec<&str> = line.split("\t").skip_while(|&x| !x.to_lowercase().contains("steam")).collect();
        if (split.len() < 1) { continue; }

        let steam_path = split[0].replace("\"", "");
        let elden_path = format!("{}\\steamapps\\common\\ELDEN RING\\Game\\oo2core_6_win64.dll", steam_path);
        if Path::new(&elden_path).exists() {
            return Some(elden_path.replace("\\\\", "\\"));
        }

        let sekiro_path = format!("{}\\steamapps\\common\\Sekiro\\Game\\oo2core_6_win64.dll", steam_path);
        if Path::new(&sekiro_path).exists() {
            return Some(sekiro_path.replace("\\\\", "\\"));
        }
    }

    None
}

fn get_steam_install_path() -> Option<String> {
    for REGISTRY_LOCATION in STEAM_REGISTRY_LOCATIONS {
        let hkey = if REGISTRY_LOCATION.0 == "HKCU" { HKEY_CURRENT_USER } //I hate this :(
        else if REGISTRY_LOCATION.0 == "HKLM" { HKEY_LOCAL_MACHINE } else { return None; };

        let reg_key = RegKey::predef(hkey)
            .open_subkey(REGISTRY_LOCATION.1);

        match reg_key {
            Ok(key) => return Some(key.get_value(REGISTRY_LOCATION.2).unwrap()),
            Err(_) => {}
        }
    }

    None
}

// pub fn read_fixed_string(br: &mut BinaryReader, size: usize) -> Result<String, DantelionFormatsError> {
//     let string_bytes = br.read_bytes(size)?;
//     Ok(String::from_utf8(string_bytes.to_vec())?)
// }

pub fn reverse_bits(byte: u8) -> u8 {
    let mut val = 0;
    let mut tmp = 0;
    let mut rev = 0;
    while val < 8
    {
        tmp = byte & (1 << val);
        if tmp > 0
        {
            rev = rev | (1 << ((8 - 1) - val));
        }
        val = val + 1;
    }

    return rev;
}

// pub(crate) fn read_utf16_string(br: &mut BinaryReader) -> Result<String, DantelionFormatsError> {
//     let mut chrs = Vec::new();
//     while let chr = br.read_u16()? {
//         if chr == 0 {
//             break;
//         }
//         chrs.push(chr);
//     }
//
//     Ok(String::from_utf16(chrs.as_slice())?)
// }

// pub fn read_as_type<T>(reader: &mut impl Read) -> Result<T>
//     where
//         T: Default,
// {
//     let result = T::default();
//
//     unsafe {
//         let buffer: &mut [u8] = std::slice::from_raw_parts_mut(
//             &result as *const T as *const u8 as *mut u8,
//             size_of::<T>(),
//         );
//
//         reader.read_exact(buffer)?;
//     }
//
//     Ok(result)
// }

// pub fn peek_byte(br: &mut BinaryReader, position: usize) -> Result<u8, DantelionFormatsError> {
//     let start = br.pos;
//     br.jmp(position);
//     let byte = br.read_u8()?;
//     br.jmp(start);
//     Ok(byte)
// }
