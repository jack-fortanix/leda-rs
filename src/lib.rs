#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

mod consts;
mod types;

mod api;

mod H_Q_matrices_generation;
mod bf_decoding;
mod constant_weight_codec;
mod crypto;
mod dfr_test;
mod djbsort;
mod gf2x_arith;
mod gf2x_arith_mod_xPplusOne;
mod mceliece_cca2_decrypt;
mod mceliece_cca2_encrypt;
mod mceliece_keygen;

pub use api::leda_decrypt;
pub use api::leda_encrypt;
pub use api::leda_gen_keypair;
pub use crypto::randombytes_init;
pub use types::{Error, Result};
