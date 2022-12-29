use std::fmt::{Debug, Display, Formatter};
use std::string::{FromUtf16Error, FromUtf8Error};
use miniz_oxide::inflate::DecompressError;
use openssl::error::ErrorStack;
use crate::error::DantelionFormatsError::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DantelionFormatsError {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    LibLoading(#[from] libloading::Error),
    #[error(transparent)]
    Utf8Error(#[from] FromUtf8Error),
    #[error(transparent)]
    Utf16Error(#[from] FromUtf16Error),
    #[error(transparent)]
    OpenSSLErrorStack(#[from] ErrorStack),
    DecompressionError(DecompressError),
}

impl From<DecompressError> for DantelionFormatsError {
    fn from(e: DecompressError) -> Self {
        DecompressionError(e)
    }
}

impl Display for DantelionFormatsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}