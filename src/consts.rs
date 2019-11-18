
// Params for security level 3, DFR 2^-64

pub const N0 : usize = 2;
pub const P : usize = 57899;
pub const DV : usize = 11;
pub const M : usize = 11;
pub const M0 : usize = 6;
pub const M1 : usize = 5;
pub const NUM_ERRORS : usize = 199;

pub const HASH_BYTE_LENGTH : usize = 48;
pub const TRNG_BYTE_LENGTH : usize = 32;

pub const K : usize = (N0 - 1)*P;
pub const N : usize = (N0 * P);
pub const DC : usize = (N0*DV);

pub const MAX_ENCODABLE_BIT_SIZE_CW_ENCODING : usize = HASH_BYTE_LENGTH * 8;
pub const KOBARA_IMAI_CONSTANT_LENGTH_B : usize = TRNG_BYTE_LENGTH;

pub const MAX_BYTES_IN_IWORD : usize = ((K - 8*(KOBARA_IMAI_CONSTANT_LENGTH_B + 8) )/8);

pub const DIGIT_SIZE_B : usize = 8;
pub const DIGIT_SIZE_b : usize = DIGIT_SIZE_B * 8;

pub const NUM_DIGITS_GF2X_ELEMENT : usize = ((P+DIGIT_SIZE_b-1)/DIGIT_SIZE_b);

