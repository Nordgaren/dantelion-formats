use std::string::{FromUtf16Error, FromUtf8Error};
use openssl::error::ErrorStack;
use crate::error::DantelionFormatError::*;

#[derive(Debug)]
pub enum DantelionFormatError {
    IoError(std::io::Error),
    LibLoading(libloading::Error),
    Utf8Error(FromUtf8Error),
    Utf16Error(FromUtf16Error),
    OpenSSLErrorStack(ErrorStack),
}

impl From<std::io::Error> for DantelionFormatError {
    fn from(e: std::io::Error) -> Self {
        IoError(e)
    }
}

impl From<libloading::Error> for DantelionFormatError {
    fn from(e: libloading::Error) -> Self {
        LibLoading(e)
    }
}

impl From<FromUtf8Error> for DantelionFormatError {
    fn from(e: FromUtf8Error) -> Self {
        Utf8Error(e)
    }
}

impl From<FromUtf16Error> for DantelionFormatError {
    fn from(e: FromUtf16Error) -> Self {
        Utf16Error(e)
    }
}

impl From<ErrorStack> for DantelionFormatError {
    fn from(e: ErrorStack) -> Self {
        OpenSSLErrorStack(e)
    }
}