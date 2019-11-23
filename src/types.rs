use crate::consts::*;

use mbedtls::Error as MbedtlsError;
use std::result::Result as StdResult;

#[derive(Debug)]
pub enum Error {
    DecryptionFailed,
    InvalidKey,
    Custom(String),
    Mbedtls(mbedtls::Error),
}

impl From<MbedtlsError> for Error {
    fn from(error: MbedtlsError) -> Error {
        Error::Mbedtls(error)
    }
}

pub type Result<T> = StdResult<T, Error>;

pub type DIGIT = u64;

#[derive(Copy, Clone)]
pub struct LedaPrivateKey {
    pub prng_seed: [u8; 32],
    pub rejections: u8,
    pub secondIterThreshold: u8,
}

#[derive(Copy, Clone)]
pub struct LedaExpandedPrivateKey {
    pub prng_seed: [u8; 32],
    pub rejections: u8,
    pub secondIterThreshold: u8,

    pub HPosOnes: [[u32; DV]; N0],
    pub QPosOnes: [[u32; DV]; N0],
    pub LPosOnes: [[u32; DV*M]; N0],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct LedaPublicKey {
    pub Mtr: [DIGIT; crate::consts::NUM_DIGITS_GF2X_ELEMENT],
}

pub struct AES_XOF_struct {
    pub ctr: Box<mbedtls::cipher::raw::Cipher>,
}

pub struct AES256_CTR_DRBG_struct {
    pub key: [u8; 32],
    pub v: [u8; 16],
    pub reseed_counter: i32,
}
