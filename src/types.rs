use std::result::Result as StdResult;

#[derive(Debug)]
pub enum Error {
    Custom(String)
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

#[derive ( Copy, Clone )]
#[repr(C)]
pub struct AES_XOF_struct {
    pub buffer: [u8; 16],
    pub buffer_pos: i32,
    pub length_remaining: u64,
    pub key: [u8; 32],
    pub ctr: [u8; 16],
}
#[derive ( Copy, Clone )]
#[repr(C)]
pub struct AES256_CTR_DRBG_struct {
    pub Key: [u8; 32],
    pub V: [u8; 16],
    pub reseed_counter: i32,
}
