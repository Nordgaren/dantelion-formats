use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use winreg;
use winreg::enums::*;
use winreg::{RegKey};

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
        if split.len() < 1 { continue; }

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
    for location in STEAM_REGISTRY_LOCATIONS {
        let hkey = if location.0 == "HKCU" { HKEY_CURRENT_USER } //I hate this :(
        else if location.0 == "HKLM" { HKEY_LOCAL_MACHINE } else { return None; };

        let reg_key = RegKey::predef(hkey)
            .open_subkey(location.1);

        match reg_key {
            Ok(key) => return Some(key.get_value(location.2).unwrap()),
            Err(_) => {}
        }
    }

    None
}

pub fn reverse_bits(byte: u8) -> u8 {
    let mut val = 0;
    let mut rev = 0;
    while val < 8
    {
        let tmp = byte & (1 << val);
        if tmp > 0
        {
            rev = rev | (1 << ((8 - 1) - val));
        }
        val = val + 1;
    }

    return rev;
}

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

