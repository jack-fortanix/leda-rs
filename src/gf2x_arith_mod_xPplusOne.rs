use crate::consts::*;
use crate::crypto::seedexpander;
use crate::djbsort::uint32_sort;
use crate::gf2x_arith::*;
use crate::types::*;

fn gf2x_mod(out: &mut [DIGIT], input: &[DIGIT]) {
    // specialized for input.len() == 2 * NUM_DIGITS_GF2X_ELEMENT, as it is only used by gf2x_mul
    assert_eq!(input.len(), 2 * NUM_DIGITS_GF2X_ELEMENT);

    let mut aux: [DIGIT; NUM_DIGITS_GF2X_ELEMENT + 1] = [0; NUM_DIGITS_GF2X_ELEMENT + 1];

    aux.copy_from_slice(&input[0..(NUM_DIGITS_GF2X_ELEMENT + 1)]);

    right_bit_shift_n(
        NUM_DIGITS_GF2X_ELEMENT as i32 + 1,
        &mut aux,
        MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS as i32);

    gf2x_mod_add_3(
        out,
        &aux[1..NUM_DIGITS_GF2X_ELEMENT + 1],
        &input[NUM_DIGITS_GF2X_ELEMENT..2 * NUM_DIGITS_GF2X_ELEMENT],
    );

    out[0] &= ((1 as DIGIT) << MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS) - 1;
}

fn left_bit_shift(input: &mut [DIGIT]) {
    for i in 0..(input.len() - 1) {
        input[i] <<= 1;
        input[i] ^= input[i+1] >> (DIGIT_SIZE_b - 1);
    }
    input[input.len() - 1] <<= 1;
}

fn right_bit_shift(input: &mut [DIGIT]) {
    for j in (1..input.len()).rev() {
        input[j] >>= 1;
        input[j] |= (input[(j - 1)] & (1 as DIGIT)) << (DIGIT_SIZE_b - 1);
    }
    input[0] >>= 1;
}

fn reverse_digit(b: DIGIT) -> DIGIT {
    b.reverse_bits()
}

pub fn gf2x_transpose_in_place(mut A: &mut [DIGIT]) {
    /* it keeps the lsb in the same position and
     * inverts the sequence of the remaining bits
     */
    let mask: DIGIT = 0x1 as DIGIT;

    let slack_bits_amount = NUM_DIGITS_GF2X_ELEMENT * DIGIT_SIZE_b - P;

    let a00 = A[NUM_DIGITS_GF2X_ELEMENT - 1] & mask;
    right_bit_shift(&mut A);

    let mut i = (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
    while i >= ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + 1i32) / 2i32 {
        let rev1 = reverse_digit(A[i as usize]);
        let rev2 = reverse_digit(A[NUM_DIGITS_GF2X_ELEMENT - (i as usize) - 1]);
        A[i as usize] = rev2;
        A[NUM_DIGITS_GF2X_ELEMENT - (i as usize) - 1] = rev1;
        i -= 1
    }

    if NUM_DIGITS_GF2X_ELEMENT % 2 == 1 {
        A[NUM_DIGITS_GF2X_ELEMENT / 2] = reverse_digit(A[NUM_DIGITS_GF2X_ELEMENT / 2]);
    }
    if slack_bits_amount != 0 {
        right_bit_shift_n(
            NUM_DIGITS_GF2X_ELEMENT as i32,
            A,
            slack_bits_amount as i32,
        }
    }

    A[NUM_DIGITS_GF2X_ELEMENT - 1] = (A[NUM_DIGITS_GF2X_ELEMENT - 1] & (!mask)) | a00;
}
// end transpose_in_place
/*----------------------------------------------------------------------------*/

fn rotate_bit_left(input: &mut [DIGIT]) {
    /* equivalent to x * in(x) mod x^P+1 */

    assert_eq!(NUM_DIGITS_GF2X_MODULUS, NUM_DIGITS_GF2X_ELEMENT);

    let msb_offset_in_digit = MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS - 1;
    let mask = (0x1i32 as DIGIT) << msb_offset_in_digit;
    let rotated_bit = (input[0] & mask != 0) as i32 as DIGIT;
    input[0] &= !mask;

    left_bit_shift(input);
    input[NUM_DIGITS_GF2X_ELEMENT - 1] |= rotated_bit;
}

fn rotate_bit_right(input: &mut [DIGIT]) {
    /* x^{-1} * in(x) mod x^P+1 */
    assert_eq!(input.len(), NUM_DIGITS_GF2X_ELEMENT);

    let mut rotated_bit: DIGIT = input[NUM_DIGITS_GF2X_ELEMENT - 1] & (1 as DIGIT);
    right_bit_shift(input);

    if NUM_DIGITS_GF2X_MODULUS == NUM_DIGITS_GF2X_ELEMENT {
        let msb_offset_in_digit = MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS - 1;
        rotated_bit = rotated_bit << msb_offset_in_digit
    } else {
        /* NUM_DIGITS_GF2X_MODULUS == 1 + NUM_DIGITS_GF2X_ELEMENT and
         * MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS == 0
         */
        rotated_bit = rotated_bit << (DIGIT_SIZE_b - 1);
    }
    input[0] |= rotated_bit;
}

unsafe fn gf2x_swap(length: i32, mut f: *mut DIGIT, mut s: *mut DIGIT) {
    let mut t: DIGIT = 0;
    let mut i: i32 = length - 1i32;
    while i >= 0i32 {
        t = *f.offset(i as isize);
        *f.offset(i as isize) = *s.offset(i as isize);
        *s.offset(i as isize) = t;
        i -= 1
    }
}
/*----------------------------------------------------------------------------*/
// end gf2x_swap
/*----------------------------------------------------------------------------*/
/*
 * Optimized extended GCD algorithm to compute the multiplicative inverse of
 * a non-zero element in GF(2)[x] mod x^P+1, in polyn. representation.
 *
 * H. Brunner, A. Curiger, and M. Hofstetter. 1993.
 * On Computing Multiplicative Inverses in GF(2^m).
 * IEEE Trans. Comput. 42, 8 (August 1993), 1010-1015.
 * DOI=http://dx.doi.org/10.1109/12.238496
 *
 *
 * Henri Cohen, Gerhard Frey, Roberto Avanzi, Christophe Doche, Tanja Lange,
 * Kim Nguyen, and Frederik Vercauteren. 2012.
 * Handbook of Elliptic and Hyperelliptic Curve Cryptography,
 * Second Edition (2nd ed.). Chapman & Hall/CRC.
 * (Chapter 11 -- Algorithm 11.44 -- pag 223)
 *
 */

pub fn gf2x_mod_inverse(out: &mut [DIGIT], input: &[DIGIT]) -> i32
/* in^{-1} mod x^P-1 */ {
    unsafe {
        let out = out.as_mut_ptr();
        let input = input.as_ptr();

        let mut i: i32 = 0;
        let mut delta: i32 = 0;
        let mut u: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
        let mut v: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
        let mut s: [DIGIT; NUM_DIGITS_GF2X_MODULUS] = [0; NUM_DIGITS_GF2X_MODULUS];
        let mut f: [DIGIT; NUM_DIGITS_GF2X_MODULUS] = [0; NUM_DIGITS_GF2X_MODULUS];
        u[NUM_DIGITS_GF2X_ELEMENT - 1] = 0x1;
        s[NUM_DIGITS_GF2X_MODULUS - 1] = 0x1;

        s[0] |= GF2_INVERSE_MASK;
        i = (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
        while i >= 0i32 && *input.offset(i as isize) == 0i32 as u64 {
            i -= 1
        }
        if i < 0i32 {
            return 0i32;
        }
        if (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
            == 1i32 + (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
        {
            i = (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
            while i >= 1i32 {
                f[i as usize] = *input.offset((i - 1i32) as isize);
                i -= 1
            }
        } else {
            /* they are equal */
            i = (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
            while i >= 0i32 {
                f[i as usize] = *input.offset(i as isize);
                i -= 1
            }
        }
        i = 1i32;
        while i <= 2i32 * crate::consts::P as i32 {
            if f[0] & GF2_INVERSE_MASK == 0i32 as u64 {
                left_bit_shift(&mut f);
                rotate_bit_left(&mut u);
                delta += 1i32
            } else {
                if s[0] & GF2_INVERSE_MASK != 0i32 as u64 {
                    gf2x_mod_add_2(&mut s, &f);
                    gf2x_mod_add_2(&mut v, &u);
                }
                left_bit_shift(&mut s);
                if delta == 0i32 {
                    gf2x_swap(
                        (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                        f.as_mut_ptr(),
                        s.as_mut_ptr(),
                    );
                    gf2x_swap(
                        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                        u.as_mut_ptr(),
                        v.as_mut_ptr(),
                    );
                    rotate_bit_left(&mut u);
                    delta = 1i32
                } else {
                    rotate_bit_right(&mut u);
                    delta = delta - 1i32
                }
            }
            i += 1
        }
        i = (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
        while i >= 0i32 {
            *out.offset(i as isize) = u[i as usize];
            i -= 1
        }
        return (delta == 0i32) as i32;
    }
}
// end gf2x_mod_inverse

pub fn gf2x_mod_mul(Res: &mut [DIGIT], A: &[DIGIT], B: &[DIGIT]) {
    assert_eq!(A.len(), NUM_DIGITS_GF2X_MODULUS);
    assert_eq!(B.len(), NUM_DIGITS_GF2X_MODULUS);

    let mut aux: [DIGIT; 2 * NUM_DIGITS_GF2X_ELEMENT] = [0; 2 * NUM_DIGITS_GF2X_ELEMENT];
    unsafe {
        gf2x_mul_TC3(
            (2 * NUM_DIGITS_GF2X_ELEMENT) as i32,
            aux.as_mut_ptr(),
            NUM_DIGITS_GF2X_ELEMENT as i32,
            A.as_ptr(),
            NUM_DIGITS_GF2X_ELEMENT as i32,
            B.as_ptr(),
        );
    }
    gf2x_mod(Res, &aux);
}
// end gf2x_mod_mul
/*----------------------------------------------------------------------------*/
/* computes operand*x^shiftAmt + Res. assumes res is
 * wide and operand is NUM_DIGITS_GF2X_ELEMENT with blank slack bits */
fn gf2x_fmac(Res: &mut [DIGIT], operand: &[DIGIT], shiftAmt: u32) {
    let digitShift = shiftAmt as usize / DIGIT_SIZE_b;
    let inDigitShift: u32 = shiftAmt % DIGIT_SIZE_b as u32;
    let inDigitShiftMask: i64 = ((inDigitShift > 0i32 as u32) as i32 as i64)
        << (8i32 << 3i32) - 1i32
        >> (8i32 << 3i32) - 1i32;

    let mut prevLo: DIGIT = 0i32 as DIGIT;

    for i in (0..NUM_DIGITS_GF2X_ELEMENT).rev() {
        let tmp = operand[i];

        Res[NUM_DIGITS_GF2X_ELEMENT+i-digitShift as usize] ^= prevLo | (tmp << inDigitShift);

        if inDigitShift > 0 {
            prevLo =
                tmp >> ((8i32 << 3i32) as u32).wrapping_sub(inDigitShift) & inDigitShiftMask as u64;
        }
    }
  Res[NUM_DIGITS_GF2X_ELEMENT-1-digitShift as usize] ^= prevLo;
}
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/*PRE: the representation of the sparse coefficients is sorted in increasing
order of the coefficients themselves */

pub fn gf2x_mod_mul_dense_to_sparse(Res: &mut [DIGIT], dense: &[DIGIT], sparse: &[u32]) {
    let mut resDouble: [DIGIT; N0 * NUM_DIGITS_GF2X_ELEMENT] = [0; N0 * NUM_DIGITS_GF2X_ELEMENT];

    for s in sparse {
        if *s != P32 {
            gf2x_fmac(&mut resDouble, dense, *s);
        }
    }
    gf2x_mod(Res, &resDouble);
}

pub fn gf2x_mod_mul_sparse(Res: &mut [u32], A: &[u32], B: &[u32]) {
    let sizeR = Res.len() as usize;
    let sizeB = B.len() as usize;
    let sizeA = A.len() as usize;

    /* compute all the coefficients, filling invalid positions with P*/
    let mut lastFilledPos: usize = 0;
    for i in 0..sizeA {
        for j in 0..sizeB {
            let mut prod: u32 = (A[i]).wrapping_add(B[j]);
            prod = if prod >= P32 {
                prod.wrapping_sub(P32)
            } else {
                prod
            };
            if A[i] != P32 && B[j] != P32 {
                Res[lastFilledPos] = prod
            } else {
                Res[lastFilledPos] = P32
            }
            lastFilledPos = lastFilledPos.wrapping_add(1);
        }
    }
    while lastFilledPos < sizeR {
        Res[lastFilledPos] = P32;
        lastFilledPos = lastFilledPos.wrapping_add(1)
    }
    uint32_sort(Res);
    /* eliminate duplicates */
    let mut lastReadPos: u32 = Res[0];
    let mut duplicateCount: i32 = 0;
    let mut write_idx: usize = 0;
    let mut read_idx: usize = 0;
    while read_idx < sizeR && Res[read_idx] != P32 {
        lastReadPos = Res[read_idx];
        read_idx += 1;
        duplicateCount = 1i32;
        while Res[read_idx] == lastReadPos && Res[read_idx] != P32 {
            read_idx += 1;
            duplicateCount += 1
        }
        if duplicateCount % 2i32 != 0 {
            Res[write_idx] = lastReadPos;
            write_idx += 1
        }
    }
    /* fill remaining cells with INVALID_POS_VALUE */
    while write_idx < sizeR {
        Res[write_idx] = P32;
        write_idx += 1
    }
}
/*---------------------------------------------------------------------------*/
// end gf2x_mod_mul_sparse
/*----------------------------------------------------------------------------*/
/* PRE: A and B should be sorted and have INVALID_POS_VALUE at the end */

pub fn gf2x_mod_add_sparse(A: &mut [u32], B: &[u32]) {
    let mut R: Vec<u32> = vec![0u32; A.len()];
    let mut idxA: usize = 0;
    let mut idxB: usize = 0;
    let mut idxR: usize = 0;
    while idxA < A.len() && idxB < B.len() && A[idxA] != P32 && B[idxB] != P32 {
        if A[idxA] == B[idxB] {
            idxA += 1;
            idxB += 1
        } else {
            if A[idxA] < B[idxB] {
                R[idxR] = A[idxA];
                idxA += 1
            } else {
                R[idxR] = B[idxB];
                idxB += 1
            }
            idxR += 1
        }
    }
    while idxA < A.len() && A[idxA] != P32 {
        R[idxR] = A[idxA];
        idxA += 1;
        idxR += 1
    }
    while idxB < B.len() && B[idxB] != P32 {
        R[idxR] = B[idxB];
        idxB += 1;
        idxR += 1
    }
    while idxR < A.len() {
        R[idxR] = P32;
        idxR += 1
    }
    A.copy_from_slice(&R);
}
// end gf2x_mod_add_sparse
/*----------------------------------------------------------------------------*/
/* Return a uniform random value in the range 0..n-1 inclusive,
 * applying a rejection sampling strategy and exploiting as a random source
 * the NIST seedexpander seeded with the proper key.
 * Assumes that the maximum value for the range n is 2^32-1
 */
fn rand_range(n: u32, seed_expander_ctx: &mut AES_XOF_struct) -> u32 {
    let required_rnd_bytes = ((32 - n.leading_zeros() + 7) / 8) as usize;
    let mask = n.next_power_of_two() - 1;

    loop {
        let mut rnd_char_buffer: [u8; 4] = [0; 4];
        seedexpander(
            seed_expander_ctx,
            &mut rnd_char_buffer[0..required_rnd_bytes],
        )
        .unwrap();
        /* obtain an endianness independent representation of the generated random
        bytes into an unsigned integer */
        let rnd_value: u32 = u32::from_le_bytes(rnd_char_buffer) & mask;

        if rnd_value < n {
            return rnd_value;
        }
    }
}

/* Obtains fresh randomness and seed-expands it until all the required positions
 * for the '1's in the circulant block are obtained
*/

pub fn rand_circulant_sparse_block(
    pos_ones: &mut [u32],
    countOnes: usize,
    seed_expander_ctx: &mut AES_XOF_struct,
) {
    let mut placedOnes = 0;
    while placedOnes < countOnes {
        let p = rand_range(crate::consts::P as u32, seed_expander_ctx);

        let mut duplicated = false;
        for j in 0..placedOnes {
            if pos_ones[j as usize] == p {
                duplicated = true;
                break;
            }
        }

        if duplicated == false {
            pos_ones[placedOnes] = p;
            placedOnes += 1
        }
    }
}
// rand_circulant_sparse_block
/*----------------------------------------------------------------------------*/
