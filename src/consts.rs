// Params for security level 3, DFR 2^-64

pub const N0: usize = 2;
pub const P: usize = 57899;
pub const DV: usize = 11;
pub const M: usize = 11;
//pub const M0: usize = 6;
//pub const M1: usize = 5;
pub const NUM_ERRORS: usize = 199;

pub const P32: u32 = P as u32;

//pub const HASH_BYTE_LENGTH: usize = 48;
pub const TRNG_BYTE_LENGTH: usize = 32;

pub const K: usize = (N0 - 1) * P;
//pub const N: usize = (N0 * P);
//pub const DC: usize = (N0 * DV);

//pub const MAX_ENCODABLE_BIT_SIZE_CW_ENCODING: usize = HASH_BYTE_LENGTH * 8;
pub const KOBARA_IMAI_CONSTANT_LENGTH_B: usize = TRNG_BYTE_LENGTH;

pub const MAX_BYTES_IN_IWORD: usize = ((K - 8 * (KOBARA_IMAI_CONSTANT_LENGTH_B + 8)) / 8);

pub const DIGIT_SIZE_B: usize = 8;
pub const DIGIT_SIZE_b: usize = DIGIT_SIZE_B * 8;

pub const NUM_DIGITS_GF2X_ELEMENT: usize = ((P + DIGIT_SIZE_b - 1) / DIGIT_SIZE_b);
pub const NUM_DIGITS_GF2X_MODULUS: usize = ((P + DIGIT_SIZE_b) / DIGIT_SIZE_b);

//pub const MSb_POSITION_IN_MSB_DIGIT_OF_ELEMENT: usize = (P % DIGIT_SIZE_b) ? (P % DIGIT_SIZE_b)-1 : DIGIT_SIZE_b-1
pub const MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS: usize =
    (P - DIGIT_SIZE_b * (NUM_DIGITS_GF2X_MODULUS - 1));

pub const GF2_INVERSE_MASK: u64 = 0x80000000000;

// Derived parameters, they are useful for QC-LDPC algorithms
// Circulant weight structure of the Q matrix, specialized per value of N0
pub const qBlockWeights: [[u8; 2]; 2] = [[6u8, 5u8], [5u8, 6u8]];
