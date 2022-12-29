use std::borrow::Borrow;
use std::io::{Error, ErrorKind};
use libloading::os::windows::{Library, Symbol};
use crate::error::DantelionFormatsError;
use crate::oodle::CheckCRC::No;
use crate::oodle::Decode_ThreadPhase::ThreadPhaseAll;
use crate::oodle::FuzzSafe::Yes;
use crate::util::get_oodle_path;

#[repr(u32)]
enum FuzzSafe {
No = 0,
Yes = 1
}
#[repr(u32)]
enum CheckCRC {
No = 0,
Yes = 1,
Force32 = 0x40000000
}
#[repr(u32)]
enum Verbosity {
None = 0,
Minimal = 1,
Some = 2,
Lots = 3,
Force32 = 0x40000000
}
#[repr(u32)]
enum Decode_ThreadPhase
{
ThreadPhase1 = 1,
ThreadPhase2 = 2,
ThreadPhaseAll = 3
}

// #[link(name = "oo2core_6_win64")]
// extern {
//     fn OodleLZ_Decompress(comp_buf: &[u8], comp_buf_size: usize, raw_buf: &[u8], raw_len: usize,
//                           fuzz_safe: FuzzSafe, check_CRC: CheckCRC, verbosity: Verbosity,
//                           dec_buf_base: usize, dec_buf_size: usize, fp_callback: usize, callback_user_data: usize,
//                           decoder_memory: usize, decoder_memory_size: usize, thread_phase: Decode_ThreadPhase) -> usize;
//
//     fn OodleLZ_GetDecodeBufferSize(raw_size: usize, corruption_possible: bool) -> usize;
// }

pub unsafe fn decompress(data: &[u8], uncompressed_size: usize) -> Result<Vec<u8>, DantelionFormatsError> {

    let oodle_path = match get_oodle_path() {
        None => return
            Err(DantelionFormatsError::IoError(
                Error::new(
                    ErrorKind::NotFound,
                    "Oodle path not found. Please move a copy of oo2core_6_win64.dll into the working directory")
                )
            ),
        Some(path) => path
    };

    let oodle = Library::new(&oodle_path)?;
    let oodle_lz_get_decode_buffer_size: Symbol<unsafe extern fn(usize, bool) -> usize> =
        oodle.get(b"OodleLZ_GetDecodeBufferSize")?;

    let oodle_lz_decompress :Symbol<unsafe extern fn(*const u8, usize, *mut u8, usize,
                                                     FuzzSafe, CheckCRC, Verbosity,
                                                      usize, usize, usize, usize,
                                                      usize, usize, Decode_ThreadPhase) -> usize> =
        oodle.get(b"OodleLZ_Decompress")?;


    let decoded_buffer_size = oodle_lz_get_decode_buffer_size(uncompressed_size, true);

    let mut raw_buf = Vec::with_capacity(decoded_buffer_size);
    raw_buf.set_len(decoded_buffer_size);

    let raw_len = oodle_lz_decompress(data.as_ptr(), data.len(), raw_buf.as_mut_ptr(), uncompressed_size,
                                               Yes, No, Verbosity::None, 0, 0, 0, 0, 0, 0, ThreadPhaseAll);

    oodle.close();
    raw_buf.truncate(raw_len);

    Ok(raw_buf)
}
