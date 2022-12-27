use std::fs::File;
use std::io::{BufRead, BufReader, Error, Read};
use std::mem::size_of;
use std::path::Path;
use binary_reader::BinaryReader;
use winreg;
use winreg::enums::*;
use winreg::{HKEY, RegKey};

// usize :(
pub(crate) static STEAM_REGISTRY_LOCATIONS: [(&str, &str, &str); 4] = [
    ("HKCU", r"SOFTWARE\Valve\Steam", "SteamPath"),
    ("HKLM", r"SOFTWARE\Wow6432Node\Valve\Steam", "InstallPath"),
    ("HKLM", r"SOFTWARE\Valve\Steam", "InstallPath"),
    ("HKCU", r"SOFTWARE\Wow6432Node\Valve\Steam", "SteamPath"),
];

// Works, for now...
pub fn get_oodle_install_path() -> String {
    let steam_path = get_steam_install_path();

    let library_folders = BufReader::new(File::open(format!(r"{steam_path}/SteamApps/libraryfolders.vdf")).expect(&format!("Could not open steam path:\n{steam_path}")));

    for line in library_folders.lines().map(|x| x.expect("")).skip_while(|p| p.contains("\"path\"")) {
        let split: Vec<&str> = line.split("\t").skip_while(|&x| !x.to_lowercase().contains("steam")).collect();
        if (split.len() < 1) { continue; }

        let steam_path = split[0].replace("\"", "");
        let elden_path = format!("{}\\steamapps\\common\\ELDEN RING\\Game\\oo2core_6_win64.dll", steam_path);
        if Path::new(&elden_path).exists() {
            return elden_path.replace("\\\\", "\\");
        }

        let sekiro_path = format!("{}\\steamapps\\common\\Sekiro\\Game\\oo2core_6_win64.dll", steam_path);
        if Path::new(&sekiro_path).exists() {
            return sekiro_path.replace("\\\\", "\\");
        }

    }
    "".to_string()
}

fn get_steam_install_path() -> String {
    for REGISTRY_LOCATION in STEAM_REGISTRY_LOCATIONS {
        let hkey = if REGISTRY_LOCATION.0 == "HKCU" { HKEY_CURRENT_USER } //I hate this :(
        else if REGISTRY_LOCATION.0 == "HKLM" { HKEY_LOCAL_MACHINE } else { panic!("Wrong input string for HKEY") };

        let reg_key = RegKey::predef(hkey)
            .open_subkey(REGISTRY_LOCATION.1);

        match reg_key {
            Ok(key) => {
                return key.get_value(REGISTRY_LOCATION.2).unwrap();
            }
            Err(_) => {}
        }
    }

    "".to_string()
}

pub fn read_fixed_string(br: &mut BinaryReader, size: usize) -> Result<String, Error> {
    let string_bytes = br.read_bytes(size)?;
    Ok(String::from_utf8(string_bytes.to_vec()).expect(&format!("Could not read fixed string of size: {size}")))
}

pub fn read_as_type<T>(reader: &mut impl Read) -> Result<T, Error>
    where
        T: Default,
{
    let result = T::default();

    unsafe {
        let buffer: &mut [u8] = std::slice::from_raw_parts_mut(
            &result as *const T as *const u8 as *mut u8,
            size_of::<T>(),
        );

        reader.read_exact(buffer)?;
    }

    return Ok(result);
}