extern "C" {
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;

}

use crate::crypto::seedexpander;
use crate::djbsort::int32_sort;
use crate::gf2x_arith::*;
use crate::types::*;
use crate::consts::*;

pub type SIGNED_DIGIT = i64;

// memcpy(...), memset(...)
/*----------------------------------------------------------------------------*/
/* specialized for nin == 2 * NUM_DIGITS_GF2X_ELEMENT, as it is only used
 * by gf2x_mul */
#[inline]
unsafe fn gf2x_mod(mut out: *mut DIGIT, _nin: i32, mut input: *const DIGIT) {
    let mut aux: [DIGIT; 906] = [0; 906];
    memcpy(
        aux.as_mut_ptr() as *mut libc::c_void,
        input as *const libc::c_void,
        (((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + 1i32) * 8i32) as u64,
    );
    right_bit_shift_n(
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + 1i32,
        aux.as_mut_ptr(),
        crate::consts::P as i32
            - (8i32 << 3i32)
                * ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
                    - 1i32),
    );
    gf2x_add(
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
        out,
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
        aux.as_mut_ptr().offset(1) as *const DIGIT,
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
        input.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) as isize),
    );
    let ref mut fresh0 = *out.offset(0);
    *fresh0 &= ((1i32 as DIGIT)
        << crate::consts::P as i32
            - (8i32 << 3i32)
                * ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
                    - 1i32))
        .wrapping_sub(1i32 as u64);
}
// end gf2x_mod
/*----------------------------------------------------------------------------*/
unsafe fn left_bit_shift(length: i32, mut input: *mut DIGIT) {
    let mut j: i32 = 0; /* logical shift does not need clearing */
    j = 0i32;
    while j < length - 1i32 {
        *input.offset(j as isize) <<= 1i32;
        let ref mut fresh1 = *input.offset(j as isize);
        *fresh1 |= *input.offset((j + 1i32) as isize) >> (8i32 << 3i32) - 1i32;
        j += 1
    }
    *input.offset(j as isize) <<= 1i32;
}
// end left_bit_shift
/*----------------------------------------------------------------------------*/
unsafe fn right_bit_shift(length: i32, mut input: *mut DIGIT) {
    let mut j: i32 = 0;
    j = length - 1i32;
    while j > 0i32 {
        *input.offset(j as isize) >>= 1i32;
        let ref mut fresh2 = *input.offset(j as isize);
        *fresh2 |= (*input.offset((j - 1i32) as isize) & 0x1i32 as DIGIT) << (8i32 << 3i32) - 1i32;
        j -= 1
    }
    *input.offset(j as isize) >>= 1i32;
}
// end right_bit_shift
/*----------------------------------------------------------------------------*/

fn reverse_digit(b: DIGIT) -> DIGIT {
    b.reverse_bits()
}

pub unsafe fn gf2x_transpose_in_place(mut A: *mut DIGIT) {
    /* it keeps the lsb in the same position and
     * inverts the sequence of the remaining bits
     */
    let mut mask: DIGIT = 0x1i32 as DIGIT;
    let mut rev1: DIGIT = 0;
    let mut rev2: DIGIT = 0;
    let mut a00: DIGIT = 0;
    let mut i: i32 = 0;
    let mut slack_bits_amount: i32 =
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * (8i32 << 3i32)
            - crate::consts::P as i32;
    if (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) == 1i32 {
        a00 = *A.offset(0) & mask;
        right_bit_shift(1i32, A);
        rev1 = reverse_digit(*A.offset(0));
        rev1 >>= (8i32 << 3i32) - crate::consts::P as i32 % (8i32 << 3i32);
        *A.offset(0) = rev1 & !mask | a00;
        return;
    }
    a00 = *A.offset(
        ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as isize,
    ) & mask;
    right_bit_shift(
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
        A,
    );
    i = (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
    while i >= ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + 1i32) / 2i32 {
        rev1 = reverse_digit(*A.offset(i as isize));
        rev2 = reverse_digit(*A.offset(
            ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32 - i)
                as isize,
        ));
        *A.offset(i as isize) = rev2;
        *A.offset(
            ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32 - i)
                as isize,
        ) = rev1;
        i -= 1
    }
    if (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) % 2i32 == 1i32 {
        *A.offset(
            ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) / 2i32) as isize,
        ) = reverse_digit(*A.offset(
            ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) / 2i32) as isize,
        ))
    }
    if slack_bits_amount != 0 {
        right_bit_shift_n(
            (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
            A,
            slack_bits_amount,
        );
    }
    *A.offset(
        ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as isize,
    ) = *A.offset(
        ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as isize,
    ) & !mask
        | a00;
}
// end transpose_in_place
/*----------------------------------------------------------------------------*/

pub unsafe fn rotate_bit_left(mut input: *mut DIGIT)
/*  equivalent to x * in(x) mod x^P+1 */
{
    let mut mask: DIGIT = 0; /* clear shifted bit */
    let mut rotated_bit: DIGIT = 0;
    if (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
        == (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
    {
        let mut msb_offset_in_digit: i32 = crate::consts::P as i32
            - (8i32 << 3i32)
                * ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
                    - 1i32)
            - 1i32;
        mask = (0x1i32 as DIGIT) << msb_offset_in_digit;
        rotated_bit = (*input.offset(0) & mask != 0) as i32 as DIGIT;
        let ref mut fresh3 = *input.offset(0);
        *fresh3 &= !mask;
        left_bit_shift(
            (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
            input,
        );
    } else {
        /* NUM_DIGITS_GF2X_MODULUS == 1 + NUM_DIGITS_GF2X_ELEMENT and
         * MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS == 0
         */
        mask = (0x1i32 as DIGIT) << (8i32 << 3i32) - 1i32; /* clear shifted bit */
        rotated_bit = (*input.offset(0) & mask != 0) as i32 as DIGIT;
        let ref mut fresh4 = *input.offset(0);
        *fresh4 &= !mask;
        left_bit_shift(
            (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
            input,
        );
    }
    let ref mut fresh5 = *input.offset(
        ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as isize,
    );
    *fresh5 |= rotated_bit;
}
// end rotate_bit_left
/*----------------------------------------------------------------------------*/

pub unsafe fn rotate_bit_right(mut input: *mut DIGIT)
/*  x^{-1} * in(x) mod x^P+1 */
{
    let mut rotated_bit: DIGIT = *input.offset(
        ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as isize,
    ) & 0x1i32 as DIGIT;
    right_bit_shift(
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
        input,
    );
    if (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
        == (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
    {
        let mut msb_offset_in_digit: i32 = crate::consts::P as i32
            - (8i32 << 3i32)
                * ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
                    - 1i32)
            - 1i32;
        rotated_bit = rotated_bit << msb_offset_in_digit
    } else {
        /* NUM_DIGITS_GF2X_MODULUS == 1 + NUM_DIGITS_GF2X_ELEMENT and
         * MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS == 0
         */
        rotated_bit = rotated_bit << (8i32 << 3i32) - 1i32
    }
    let ref mut fresh6 = *input.offset(0);
    *fresh6 |= rotated_bit;
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

pub unsafe fn gf2x_mod_inverse(mut out: *mut DIGIT, mut input: *const DIGIT) -> i32
/* in^{-1} mod x^P-1 */ {
    let mut i: i32 = 0;
    let mut delta: libc::c_long = 0i32 as libc::c_long;
    let mut u: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    let mut v: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    let mut s: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    let mut f: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    let mut mask: DIGIT = 0;
    u[((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as usize] =
        0x1i32 as DIGIT;
    v[((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as usize] =
        0i32 as DIGIT;
    s[((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32)
        as usize] = 0x1i32 as DIGIT;
    if crate::consts::P as i32
        - (8i32 << 3i32)
            * ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32)
        == 0i32
    {
        mask = 0x1i32 as DIGIT
    } else {
        mask = (0x1i32 as DIGIT)
            << crate::consts::P as i32
                - (8i32 << 3i32)
                    * ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
                        - 1i32)
    }
    s[0] |= mask;
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
        if f[0] & mask == 0i32 as u64 {
            left_bit_shift(
                (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                f.as_mut_ptr(),
            );
            rotate_bit_left(u.as_mut_ptr());
            delta += 1i32 as libc::c_long
        } else {
            if s[0] & mask != 0i32 as u64 {
                gf2x_add(
                    (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                    s.as_mut_ptr(),
                    (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                    s.as_mut_ptr() as *const DIGIT,
                    (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                    f.as_mut_ptr() as *const DIGIT,
                );
                gf2x_mod_add(
                    v.as_mut_ptr(),
                    v.as_mut_ptr() as *const DIGIT,
                    u.as_mut_ptr() as *const DIGIT,
                );
            }
            left_bit_shift(
                (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                s.as_mut_ptr(),
            );
            if delta == 0i32 as libc::c_long {
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
                rotate_bit_left(u.as_mut_ptr());
                delta = 1i32 as libc::c_long
            } else {
                rotate_bit_right(u.as_mut_ptr());
                delta = delta - 1i32 as libc::c_long
            }
        }
        i += 1
    }
    i = (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
    while i >= 0i32 {
        *out.offset(i as isize) = u[i as usize];
        i -= 1
    }
    return (delta == 0i32 as libc::c_long) as i32;
}
// end gf2x_mod_inverse

pub unsafe fn gf2x_mod_mul(mut Res: *mut DIGIT, mut A: *const DIGIT, mut B: *const DIGIT) {
    let mut aux: [DIGIT; N0*NUM_DIGITS_GF2X_ELEMENT] = [0; N0*NUM_DIGITS_GF2X_ELEMENT];
    gf2x_mul_TC3(
        2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)),
        aux.as_mut_ptr(),
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
        A,
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
        B,
    );
    gf2x_mod(
        Res,
        2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)),
        aux.as_mut_ptr() as *const DIGIT,
    );
}
// end gf2x_mod_mul
/*----------------------------------------------------------------------------*/
/* computes operand*x^shiftAmt + Res. assumes res is
 * wide and operand is NUM_DIGITS_GF2X_ELEMENT with blank slack bits */
#[inline]
unsafe fn gf2x_fmac(mut Res: *mut DIGIT, mut operand: *const DIGIT, shiftAmt: u32) {
    let mut digitShift: u32 = shiftAmt.wrapping_div((8i32 << 3i32) as u32);
    let mut inDigitShift: u32 = shiftAmt.wrapping_rem((8i32 << 3i32) as u32);
    let mut tmp: DIGIT = 0;
    let mut prevLo: DIGIT = 0i32 as DIGIT;
    let mut i: i32 = 0;
    let mut inDigitShiftMask: SIGNED_DIGIT = ((inDigitShift > 0i32 as u32) as i32 as SIGNED_DIGIT)
        << (8i32 << 3i32) - 1i32
        >> (8i32 << 3i32) - 1i32;
    i = (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
    while i >= 0i32 {
        tmp = *operand.offset(i as isize);
        let ref mut fresh7 = *Res.offset(
            (((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + i) as u32)
                .wrapping_sub(digitShift) as isize,
        );
        *fresh7 ^= prevLo | tmp << inDigitShift;

        if inDigitShift > 0 {
            prevLo =
                tmp >> ((8i32 << 3i32) as u32).wrapping_sub(inDigitShift) & inDigitShiftMask as u64;
        }
        i -= 1
    }
    let ref mut fresh8 = *Res.offset(
        (((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + i) as u32)
            .wrapping_sub(digitShift) as isize,
    );
    *fresh8 ^= prevLo;
}
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/*PRE: the representation of the sparse coefficients is sorted in increasing
order of the coefficients themselves */

pub unsafe fn gf2x_mod_mul_dense_to_sparse(
    mut Res: *mut DIGIT,
    mut dense: *const DIGIT,
    mut sparse: *const u32,
    mut nPos: u32,
) {
    let mut resDouble: [DIGIT; N0*NUM_DIGITS_GF2X_ELEMENT] = [0; N0*NUM_DIGITS_GF2X_ELEMENT];
    let mut i: u32 = 0i32 as u32;
    while i < nPos {
        if *sparse.offset(i as isize) != crate::consts::P as i32 as u32 {
            gf2x_fmac(resDouble.as_mut_ptr(), dense, *sparse.offset(i as isize));
        }
        i = i.wrapping_add(1)
    }
    gf2x_mod(
        Res,
        2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)),
        resDouble.as_mut_ptr() as *const DIGIT,
    );
}
// end gf2x_mod_mul
/*----------------------------------------------------------------------------*/

pub unsafe fn gf2x_mod_mul_sparse(
    mut sizeR: i32,
    mut Res: *mut u32,
    mut sizeA: i32,
    mut A: *const u32,
    mut sizeB: i32,
    mut B: *const u32,
) {
    /* compute all the coefficients, filling invalid positions with P*/
    let mut lastFilledPos: u32 = 0i32 as u32;
    let mut i: i32 = 0i32;
    while i < sizeA {
        let mut j: i32 = 0i32;
        while j < sizeB {
            let mut prod: u32 = (*A.offset(i as isize)).wrapping_add(*B.offset(j as isize));
            prod = if prod >= crate::consts::P as i32 as u32 {
                prod.wrapping_sub(crate::consts::P as i32 as u32)
            } else {
                prod
            };
            if *A.offset(i as isize) != crate::consts::P as i32 as u32
                && *B.offset(j as isize) != crate::consts::P as i32 as u32
            {
                *Res.offset(lastFilledPos as isize) = prod
            } else {
                *Res.offset(lastFilledPos as isize) = crate::consts::P as i32 as u32
            }
            lastFilledPos = lastFilledPos.wrapping_add(1);
            j += 1
        }
        i += 1
    }
    while lastFilledPos < sizeR as u32 {
        *Res.offset(lastFilledPos as isize) = crate::consts::P as i32 as u32;
        lastFilledPos = lastFilledPos.wrapping_add(1)
    }
    int32_sort(Res as *mut i32, sizeR as isize);
    /* eliminate duplicates */
    let mut lastReadPos: u32 = *Res.offset(0);
    let mut duplicateCount: i32 = 0;
    let mut write_idx: i32 = 0i32;
    let mut read_idx: i32 = 0i32;
    while read_idx < sizeR && *Res.offset(read_idx as isize) != crate::consts::P as i32 as u32 {
        lastReadPos = *Res.offset(read_idx as isize);
        read_idx += 1;
        duplicateCount = 1i32;
        while *Res.offset(read_idx as isize) == lastReadPos
            && *Res.offset(read_idx as isize) != crate::consts::P as i32 as u32
        {
            read_idx += 1;
            duplicateCount += 1
        }
        if duplicateCount % 2i32 != 0 {
            *Res.offset(write_idx as isize) = lastReadPos;
            write_idx += 1
        }
    }
    /* fill remaining cells with INVALID_POS_VALUE */
    while write_idx < sizeR {
        *Res.offset(write_idx as isize) = crate::consts::P as i32 as u32;
        write_idx += 1
    }
}
/*---------------------------------------------------------------------------*/
// end gf2x_mod_mul_sparse
/*----------------------------------------------------------------------------*/
/* the implementation is safe even in case A or B alias with the result */
/* PRE: A and B should be sorted and have INVALID_POS_VALUE at the end */

pub unsafe fn gf2x_mod_add_sparse(
    mut sizeR: i32,
    mut Res: *mut u32,
    mut sizeA: i32,
    mut A: *mut u32,
    mut sizeB: i32,
    mut B: *mut u32,
) {
    let vla = sizeR as usize;
    let mut tmpRes: Vec<u32> = ::std::vec::from_elem(0, vla);
    let mut idxA: i32 = 0i32;
    let mut idxB: i32 = 0i32;
    let mut idxR: i32 = 0i32;
    while idxA < sizeA
        && idxB < sizeB
        && *A.offset(idxA as isize) != crate::consts::P as i32 as u32
        && *B.offset(idxB as isize) != crate::consts::P as i32 as u32
    {
        if *A.offset(idxA as isize) == *B.offset(idxB as isize) {
            idxA += 1;
            idxB += 1
        } else {
            if *A.offset(idxA as isize) < *B.offset(idxB as isize) {
                *tmpRes.as_mut_ptr().offset(idxR as isize) = *A.offset(idxA as isize);
                idxA += 1
            } else {
                *tmpRes.as_mut_ptr().offset(idxR as isize) = *B.offset(idxB as isize);
                idxB += 1
            }
            idxR += 1
        }
    }
    while idxA < sizeA && *A.offset(idxA as isize) != crate::consts::P as i32 as u32 {
        *tmpRes.as_mut_ptr().offset(idxR as isize) = *A.offset(idxA as isize);
        idxA += 1;
        idxR += 1
    }
    while idxB < sizeB && *B.offset(idxB as isize) != crate::consts::P as i32 as u32 {
        *tmpRes.as_mut_ptr().offset(idxR as isize) = *B.offset(idxB as isize);
        idxB += 1;
        idxR += 1
    }
    while idxR < sizeR {
        *tmpRes.as_mut_ptr().offset(idxR as isize) = crate::consts::P as i32 as u32;
        idxR += 1
    }
    memcpy(
        Res as *mut libc::c_void,
        tmpRes.as_mut_ptr() as *const libc::c_void,
        (::std::mem::size_of::<u32>() as u64).wrapping_mul(sizeR as u64),
    );
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

pub unsafe fn rand_circulant_sparse_block(
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
