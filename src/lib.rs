#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]

mod consts;
mod types;

mod bf_decoding;
mod constant_weight_codec;
mod dfr_test;
mod djbsort;
mod encrypt;
mod gf2x_arith_mod_xPplusOne;
mod gf2x_arith;
mod H_Q_matrices_generation;
mod marshalling;
mod mceliece_cca2_decrypt;
mod mceliece_cca2_encrypt;
mod mceliece_keygen;
mod crypto;

pub use encrypt::crypto_encrypt_keypair;
pub use encrypt::crypto_encrypt;
pub use encrypt::crypto_decrypt;
pub use crypto::randombytes_init;
pub use types::{Error, Result};
