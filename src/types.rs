use std::result::Result as StdResult;
use mbedtls::Error as MbedtlsError;

#[derive(Debug)]
pub enum Error {
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
#[repr(C)]
pub struct privateKeyMcEliece_t {
    pub prng_seed: [u8; 32],
    pub rejections: u8,
    pub secondIterThreshold: u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct publicKeyMcEliece_t {
    pub Mtr: [DIGIT; 905],
}

pub struct AES_XOF_struct {
    pub ctr: Box<mbedtls::cipher::raw::Cipher>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct AES256_CTR_DRBG_struct {
    pub key: [u8; 32],
    pub v: [u8; 16],
    pub reseed_counter: i32,
}
