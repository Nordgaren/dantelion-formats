


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