
extern "C" {
    // end gf2x_add
    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    fn gf2x_mul_TC3(nr: i32, Res: *mut DIGIT, na: i32,
                    A: *const DIGIT, nb: i32, B: *const DIGIT);
    /* PRE: MAX ALLOWED ROTATION AMOUNT : DIGIT_SIZE_b */
    #[no_mangle]
    fn right_bit_shift_n(length: i32, in_0: *mut DIGIT,
                         amount: i32);
    /* PRE: MAX ALLOWED ROTATION AMOUNT : DIGIT_SIZE_b */
    #[no_mangle]
    fn left_bit_shift_n(length: i32, in_0: *mut DIGIT,
                        amount: i32);
    #[no_mangle]
    fn seedexpander(ctx: *mut AES_XOF_struct, x: *mut u8,
                    xlen: u64) -> i32;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64)
     -> *mut libc::c_void;

}

use crate::types::*;
use crate::gf2x_arith::*;
use crate::djbsort::int32_sort;

pub type SIGNED_DIGIT = i64;
#[derive ( Copy, Clone )]
#[repr ( C )]
pub union toReverse_t {
    pub inByte: [u8; 8],
    pub digitValue: DIGIT,
}

// memcpy(...), memset(...)
/*----------------------------------------------------------------------------*/
/* specialized for nin == 2 * NUM_DIGITS_GF2X_ELEMENT, as it is only used
 * by gf2x_mul */
#[inline]
unsafe fn gf2x_mod(mut out: *mut DIGIT, _nin: i32,
                              mut in_0: *const DIGIT) {
    let mut aux: [DIGIT; 906] = [0; 906];
    memcpy(aux.as_mut_ptr() as *mut libc::c_void, in_0 as *const libc::c_void,
           (((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + 1i32) *
                8i32) as u64);
    right_bit_shift_n((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) +
                          1i32, aux.as_mut_ptr(),
                      crate::consts::P as i32 -
                          (8i32 << 3i32) *
                              ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                                   (8i32 << 3i32) - 1i32));
    gf2x_add((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), out,
             (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
             aux.as_mut_ptr().offset(1) as *const DIGIT,
             (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
             in_0.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32))
                             as isize));
    let ref mut fresh0 = *out.offset(0);
    *fresh0 &=
        ((1i32 as DIGIT) <<
             crate::consts::P as i32 -
                 (8i32 << 3i32) *
                     ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                          (8i32 << 3i32) -
                          1i32)).wrapping_sub(1i32 as u64);
}
// end gf2x_mod
/*----------------------------------------------------------------------------*/
unsafe fn left_bit_shift(length: i32,
                                    mut in_0: *mut DIGIT) {
    let mut j: i32 = 0; /* logical shift does not need clearing */
    j = 0i32;
    while j < length - 1i32 {
        *in_0.offset(j as isize) <<= 1i32;
        let ref mut fresh1 = *in_0.offset(j as isize);
        *fresh1 |= *in_0.offset((j + 1i32) as isize) >> (8i32 << 3i32) - 1i32;
        j += 1
    }
    *in_0.offset(j as isize) <<= 1i32;
}
// end left_bit_shift
/*----------------------------------------------------------------------------*/
unsafe fn right_bit_shift(length: i32,
                                     mut in_0: *mut DIGIT) {
    let mut j: i32 = 0;
    j = length - 1i32;
    while j > 0i32 {
        *in_0.offset(j as isize) >>= 1i32;
        let ref mut fresh2 = *in_0.offset(j as isize);
        *fresh2 |=
            (*in_0.offset((j - 1i32) as isize) & 0x1i32 as DIGIT) <<
                (8i32 << 3i32) - 1i32;
        j -= 1
    }
    *in_0.offset(j as isize) >>= 1i32;
}
// end right_bit_shift
/*----------------------------------------------------------------------------*/
/* shifts by whole digits */
#[inline]
unsafe fn left_DIGIT_shift_n(length: i32,
                                        mut in_0: *mut DIGIT,
                                        mut amount: i32) {
    let mut j: i32 = 0;
    j = 0i32;
    while j + amount < length {
        *in_0.offset(j as isize) = *in_0.offset((j + amount) as isize);
        j += 1
    }
    while j < length { *in_0.offset(j as isize) = 0i32 as DIGIT; j += 1 };
}
// end left_bit_shift_n
/*----------------------------------------------------------------------------*/
/* may shift by an arbitrary amount*/
#[no_mangle]
pub unsafe fn left_bit_shift_wide_n(length: i32,
                                               mut in_0: *mut DIGIT,
                                               mut amount: i32) {
    left_DIGIT_shift_n(length, in_0, amount / (8i32 << 3i32));
    left_bit_shift_n(length, in_0, amount % (8i32 << 3i32));
}
// end left_bit_shift_n
/*----------------------------------------------------------------------------*/
unsafe fn byte_reverse_with_64bitDIGIT(mut b: u8) -> u8 {
    b =
        ((b as u64).wrapping_mul(0x202020202u64) &
             0x10884422010u64).wrapping_rem(1023i32 as u64) as
            u8;
    return b;
}
// end byte_reverse_64bitDIGIT
/*----------------------------------------------------------------------------*/
unsafe fn reverse_digit(b: DIGIT) -> DIGIT {
    let mut i: i32 = 0;
    let mut toReverse: toReverse_t = toReverse_t{inByte: [0; 8],};
    toReverse.digitValue = b;
    i = 0i32;
    while i < 8i32 {
        toReverse.inByte[i as usize] =
            byte_reverse_with_64bitDIGIT(toReverse.inByte[i as usize]);
        i += 1
    }
    return (toReverse.digitValue as u64).swap_bytes() as DIGIT;
}
// end reverse_digit
/*----------------------------------------------------------------------------*/
#[no_mangle]
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
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * (8i32 << 3i32) -
            crate::consts::P as i32;
    if (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) == 1i32 {
        a00 = *A.offset(0) & mask;
        right_bit_shift(1i32, A);
        rev1 = reverse_digit(*A.offset(0));
        rev1 >>= (8i32 << 3i32) - crate::consts::P as i32 % (8i32 << 3i32);
        *A.offset(0) = rev1 & !mask | a00;
        return
    }
    a00 =
        *A.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32)
                      as isize) & mask;
    right_bit_shift((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), A);
    i = (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
    while i >=
              ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + 1i32) /
                  2i32 {
        rev1 = reverse_digit(*A.offset(i as isize));
        rev2 =
            reverse_digit(*A.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                         (8i32 << 3i32) - 1i32 - i) as
                                        isize));
        *A.offset(i as isize) = rev2;
        *A.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32
                       - i) as isize) = rev1;
        i -= 1
    }
    if (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) % 2i32 == 1i32 {
        *A.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) / 2i32)
                      as isize) =
            reverse_digit(*A.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                         (8i32 << 3i32) / 2i32) as isize))
    }
    if slack_bits_amount != 0 {
        right_bit_shift_n((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                          A, slack_bits_amount);
    }
    *A.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as
                  isize) =
        *A.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32)
                      as isize) & !mask | a00;
}
// end transpose_in_place
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe fn rotate_bit_left(mut in_0: *mut DIGIT) 
 /*  equivalent to x * in(x) mod x^P+1 */
 {
    let mut mask: DIGIT = 0; /* clear shifted bit */
    let mut rotated_bit: DIGIT = 0;
    if (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) ==
           (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) {
        let mut msb_offset_in_digit: i32 =
            crate::consts::P as i32 -
                (8i32 << 3i32) *
                    ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                         (8i32 << 3i32) - 1i32) - 1i32;
        mask = (0x1i32 as DIGIT) << msb_offset_in_digit;
        rotated_bit = (*in_0.offset(0) & mask != 0) as i32 as DIGIT;
        let ref mut fresh3 = *in_0.offset(0);
        *fresh3 &= !mask;
        left_bit_shift((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                       in_0);
    } else {
        /* NUM_DIGITS_GF2X_MODULUS == 1 + NUM_DIGITS_GF2X_ELEMENT and
              * MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS == 0
              */
        mask =
            (0x1i32 as DIGIT) <<
                (8i32 << 3i32) - 1i32; /* clear shifted bit */
        rotated_bit = (*in_0.offset(0) & mask != 0) as i32 as DIGIT;
        let ref mut fresh4 = *in_0.offset(0);
        *fresh4 &= !mask;
        left_bit_shift((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                       in_0);
    }
    let ref mut fresh5 =
        *in_0.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) -
                          1i32) as isize);
    *fresh5 |= rotated_bit;
}
// end rotate_bit_left
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe fn rotate_bit_right(mut in_0: *mut DIGIT) 
 /*  x^{-1} * in(x) mod x^P+1 */
 {
    let mut rotated_bit: DIGIT =
        *in_0.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) -
                          1i32) as isize) & 0x1i32 as DIGIT;
    right_bit_shift((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                    in_0);
    if (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) ==
           (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) {
        let mut msb_offset_in_digit: i32 =
            crate::consts::P as i32 -
                (8i32 << 3i32) *
                    ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                         (8i32 << 3i32) - 1i32) - 1i32;
        rotated_bit = rotated_bit << msb_offset_in_digit
    } else {
        /* NUM_DIGITS_GF2X_MODULUS == 1 + NUM_DIGITS_GF2X_ELEMENT and
              * MSb_POSITION_IN_MSB_DIGIT_OF_MODULUS == 0
              */
        rotated_bit = rotated_bit << (8i32 << 3i32) - 1i32
    }
    let ref mut fresh6 = *in_0.offset(0);
    *fresh6 |= rotated_bit;
}
#[no_mangle]
pub unsafe fn gf2x_digit_times_poly_mul(nr: i32,
                                                   mut Res: *mut DIGIT,
                                                   _na: i32,
                                                   mut A: *const DIGIT,
                                                   B: DIGIT) {
    let mut pres: [DIGIT; 2] = [0; 2];
    *Res.offset((nr - 1i32) as isize) = 0i32 as DIGIT;
    let mut i: i32 = nr - 1i32 - 1i32;
    while i >= 0i32 {
        gf2x_mul_TC3(2i32, pres.as_mut_ptr(), 1i32, &*A.offset(i as isize),
                     1i32, &B);
        *Res.offset((i + 1i32) as isize) =
            *Res.offset((i + 1i32) as isize) ^ pres[1];
        *Res.offset(i as isize) = pres[0];
        i -= 1
    };
}
unsafe fn gf2x_swap(length: i32, mut f: *mut DIGIT,
                               mut s: *mut DIGIT) {
    let mut t: DIGIT = 0;
    let mut i: i32 = length - 1i32;
    while i >= 0i32 {
        t = *f.offset(i as isize);
        *f.offset(i as isize) = *s.offset(i as isize);
        *s.offset(i as isize) = t;
        i -= 1
    };
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
#[no_mangle]
pub unsafe fn gf2x_mod_inverse(mut out: *mut DIGIT,
                                          mut in_0: *const DIGIT)
 -> i32 
 /* in^{-1} mod x^P-1 */
 {
    let mut i: i32 = 0;
    let mut delta: libc::c_long = 0i32 as libc::c_long;
    let mut u: [DIGIT; 905] = [0; 905];
    let mut v: [DIGIT; 905] = [0; 905];
    let mut s: [DIGIT; 905] = [0; 905];
    let mut f: [DIGIT; 905] = [0; 905];
    let mut mask: DIGIT = 0;
    u[((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as usize] =
        0x1i32 as DIGIT;
    v[((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as usize] =
        0i32 as DIGIT;
    s[((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32) as
          usize] = 0x1i32 as DIGIT;
    if crate::consts::P as i32 -
           (8i32 << 3i32) *
               ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) -
                    1i32) == 0i32 {
        mask = 0x1i32 as DIGIT
    } else {
        mask =
            (0x1i32 as DIGIT) <<
                crate::consts::P as i32 -
                    (8i32 << 3i32) *
                        ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                             (8i32 << 3i32) - 1i32)
    }
    s[0] |= mask;
    i = (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
    while i >= 0i32 && *in_0.offset(i as isize) == 0i32 as u64 {
        i -= 1
    }
    if i < 0i32 { return 0i32 }
    if (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) ==
           1i32 + (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) {
        i = (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
        while i >= 1i32 {
            f[i as usize] = *in_0.offset((i - 1i32) as isize);
            i -= 1
        }
    } else {
        /* they are equal */
        i = (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
        while i >= 0i32 { f[i as usize] = *in_0.offset(i as isize); i -= 1 }
    }
    i = 1i32;
    while i <= 2i32 * crate::consts::P as i32 {
        if f[0] & mask == 0i32 as u64 {
            left_bit_shift((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                               (8i32 << 3i32), f.as_mut_ptr());
            rotate_bit_left(u.as_mut_ptr());
            delta += 1i32 as libc::c_long
        } else {
            if s[0] & mask != 0i32 as u64 {
                gf2x_add((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                             (8i32 << 3i32), s.as_mut_ptr(),
                         (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                             (8i32 << 3i32), s.as_mut_ptr() as *const DIGIT,
                         (crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                             (8i32 << 3i32), f.as_mut_ptr() as *const DIGIT);
                gf2x_mod_add(v.as_mut_ptr(), v.as_mut_ptr() as *const DIGIT,
                             u.as_mut_ptr() as *const DIGIT);
            }
            left_bit_shift((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                               (8i32 << 3i32), s.as_mut_ptr());
            if delta == 0i32 as libc::c_long {
                gf2x_swap((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                              (8i32 << 3i32), f.as_mut_ptr(), s.as_mut_ptr());
                gf2x_swap((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32),
                          u.as_mut_ptr(), v.as_mut_ptr());
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
    while i >= 0i32 { *out.offset(i as isize) = u[i as usize]; i -= 1 }
    return (delta == 0i32 as libc::c_long) as i32;
}
// end gf2x_mod_inverse
/*----------------------------------------------------------------------------
*
* Based on: K. Kobayashi, N. Takagi and K. Takagi, "Fast inversion algorithm in 
* GF(2m) suitable for implementation with a polynomial multiply instruction on 
* GF(2)," in IET Computers & Digital Techniques, vol. 6, no. 3, pp. 180-185, 
* May 2012. doi: 10.1049/iet-cdt.2010.0006
*/
#[no_mangle]
pub unsafe fn gf2x_mod_inverse_KTT(mut out: *mut DIGIT,
                                              mut in_0: *const DIGIT)
 -> i32 {
    /* in^{-1} mod x^P-1 */
    let mut s: [DIGIT; 906] = [0; 906];
    let mut r: [DIGIT; 906] = [0; 906];
    r[0] = 0i32 as DIGIT;
    memcpy(r.as_mut_ptr().offset(1) as *mut libc::c_void,
           in_0 as *const libc::c_void,
           ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * 8i32) as
               u64);
    /* S starts set to the modulus */
    s[((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + 1i32 - 1i32) as
          usize] = 1i32 as DIGIT; /* x */
    s[(0i32 + 1i32) as usize] |=
        (1i32 as DIGIT) <<
            crate::consts::P as i32 -
                (8i32 << 3i32) *
                    ((crate::consts::P as i32 + 1i32 + (8i32 << 3i32) - 1i32) /
                         (8i32 << 3i32) - 1i32);
    let mut v: [DIGIT; 1810] = [0; 1810];
    let mut u: [DIGIT; 1810] = [0; 1810];
    u[(2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) - 1i32) as
          usize] = 2i32 as DIGIT;
    let mut deg_r: i32 =
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * (8i32 << 3i32) -
            1i32;
    let mut deg_s: i32 =
        (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * (8i32 << 3i32) -
            1i32;
    let mut c: DIGIT = 0;
    let mut d: DIGIT = 0;
    let mut h00: DIGIT = 0;
    let mut h01: DIGIT = 0;
    let mut h10: DIGIT = 0;
    let mut h11: DIGIT = 0;
    let mut hibitmask: DIGIT = (1i32 as DIGIT) << (8i32 << 3i32) - 1i32;
    let mut r_h00: [DIGIT; 907] = [0; 907];
    let mut s_h01: [DIGIT; 907] = [0; 907];
    let mut r_h10: [DIGIT; 907] = [0; 907];
    let mut s_h11: [DIGIT; 907] = [0; 907];
    let mut u_h00: [DIGIT; 1811] = [0; 1811];
    let mut v_h01: [DIGIT; 1811] = [0; 1811];
    let mut u_h10: [DIGIT; 1811] = [0; 1811];
    let mut v_h11: [DIGIT; 1811] = [0; 1811];
    while deg_r > 0i32 {
        c = r[1];
        d = s[1];
        if c == 0i32 as u64 {
            left_DIGIT_shift_n((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                   (8i32 << 3i32) + 1i32, r.as_mut_ptr(),
                               1i32);
            left_DIGIT_shift_n(2i32 *
                                   ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                        (8i32 << 3i32)), u.as_mut_ptr(),
                               1i32);
            deg_r = deg_r - (8i32 << 3i32)
        } else {
            /* H = I */
            h00 = 1i32 as DIGIT; /* while */
            h01 = 0i32 as DIGIT; /* hibit r[0] set */
            h10 = 0i32 as DIGIT;
            h11 = 1i32 as DIGIT;
            let mut j: i32 = 1i32;
            while j < 8i32 << 3i32 && deg_r > 0i32 {
                if c & hibitmask == 0i32 as u64 {
                    /* */
                    c = c << 1i32; /* if (deg_r != deg_s) */
                    h00 =
                        h00 <<
                            1i32; /* hibit r[0] set, s[0] unset, deg_r == deg_s */
                    h01 = h01 << 1i32;
                    deg_r -= 1
                } else if deg_r == deg_s {
                    deg_r -= 1;
                    if d & hibitmask == hibitmask {
                        let mut temp: DIGIT = c;
                        /* hibit r[0],s[0] set, deg_r == deg_s */
                        c = (c ^ d) << 1i32; /* (c-d)*x */
                        d = temp;
                        let mut r00: DIGIT = 0;
                        r00 = h00 << 1i32 ^ h10 << 1i32;
                        let mut r01: DIGIT = 0;
                        r01 = h01 << 1i32 ^ h11 << 1i32;
                        h10 = h00;
                        h11 = h01;
                        h00 = r00;
                        h01 = r01
                    } else {
                        let mut temp_0: DIGIT = 0;
                        temp_0 = c;
                        c = d << 1i32;
                        d = temp_0;
                        /*mult H*/
                        /*mult H*/
                        let mut r00_0: DIGIT =
                            0; /* hibit r[0] set, s[0] unset, deg_r != deg_s */
                        r00_0 = h10 << 1i32;
                        let mut r01_0: DIGIT = 0;
                        r01_0 = h11 << 1i32;
                        h10 = h00;
                        h11 = h01;
                        h00 = r00_0;
                        h01 = r01_0
                    }
                } else {
                    deg_s -= 1;
                    if d & hibitmask == hibitmask {
                        /* hibit r[0],s[0] set, deg_r != deg_s */
                        d = (c ^ d) << 1i32; /* (c-d) * x*/
                        /* mult H */
                        h10 = h00 << 1i32 ^ h10 << 1i32;
                        h11 = h01 << 1i32 ^ h11 << 1i32
                    } else {
                        d = d << 1i32;
                        /*mul H*/
                        h10 = h10 << 1i32;
                        h11 = h11 << 1i32
                    }
                }
                j += 1
                /*(deg_r == deg_s)*/
                /* if ( (c & ((DIGIT 1) << (DIGIT_SIZE_b-1))) == 0) */
            }
            /*update r , s */
            gf2x_digit_times_poly_mul((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32) + 2i32,
                                      r_h00.as_mut_ptr(),
                                      (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32) + 1i32,
                                      r.as_mut_ptr() as *const DIGIT, h00);
            gf2x_digit_times_poly_mul((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32) + 2i32,
                                      s_h01.as_mut_ptr(),
                                      (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32) + 1i32,
                                      s.as_mut_ptr() as *const DIGIT, h01);
            gf2x_digit_times_poly_mul((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32) + 2i32,
                                      r_h10.as_mut_ptr(),
                                      (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32) + 1i32,
                                      r.as_mut_ptr() as *const DIGIT, h10);
            gf2x_digit_times_poly_mul((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32) + 2i32,
                                      s_h11.as_mut_ptr(),
                                      (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32) + 1i32,
                                      s.as_mut_ptr() as *const DIGIT, h11);
            gf2x_add((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) +
                         1i32, r.as_mut_ptr(),
                     (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) +
                         1i32, r_h00.as_mut_ptr().offset(1) as *const DIGIT,
                     (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) +
                         1i32, s_h01.as_mut_ptr().offset(1) as *const DIGIT);
            gf2x_add((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) +
                         1i32, s.as_mut_ptr(),
                     (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) +
                         1i32, r_h10.as_mut_ptr().offset(1) as *const DIGIT,
                     (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) +
                         1i32, s_h11.as_mut_ptr().offset(1) as *const DIGIT);
            /* *********************** update u, v *************************/
            gf2x_digit_times_poly_mul(2i32 *
                                          ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32)) + 1i32,
                                      u_h00.as_mut_ptr(),
                                      2i32 *
                                          ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32)),
                                      u.as_mut_ptr() as *const DIGIT, h00);
            gf2x_digit_times_poly_mul(2i32 *
                                          ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32)) + 1i32,
                                      v_h01.as_mut_ptr(),
                                      2i32 *
                                          ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32)),
                                      v.as_mut_ptr() as *const DIGIT, h01);
            gf2x_digit_times_poly_mul(2i32 *
                                          ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32)) + 1i32,
                                      u_h10.as_mut_ptr(),
                                      2i32 *
                                          ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32)),
                                      u.as_mut_ptr() as *const DIGIT, h10);
            gf2x_digit_times_poly_mul(2i32 *
                                          ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32)) + 1i32,
                                      v_h11.as_mut_ptr(),
                                      2i32 *
                                          ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32)),
                                      v.as_mut_ptr() as *const DIGIT, h11);
            gf2x_add(2i32 *
                         ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                              (8i32 << 3i32)), u.as_mut_ptr(),
                     2i32 *
                         ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                              (8i32 << 3i32)),
                     u_h00.as_mut_ptr().offset(1) as *const DIGIT,
                     2i32 *
                         ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                              (8i32 << 3i32)),
                     v_h01.as_mut_ptr().offset(1) as *const DIGIT);
            gf2x_add(2i32 *
                         ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                              (8i32 << 3i32)), v.as_mut_ptr(),
                     2i32 *
                         ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                              (8i32 << 3i32)),
                     u_h10.as_mut_ptr().offset(1) as *const DIGIT,
                     2i32 *
                         ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                              (8i32 << 3i32)),
                     v_h11.as_mut_ptr().offset(1) as *const DIGIT);
        }
    }
    if deg_r == 0i32 {
        memcpy(out as *mut libc::c_void,
               u.as_mut_ptr() as *const libc::c_void,
               ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * 8i32) as
                   u64);
    } else {
        memcpy(out as *mut libc::c_void,
               v.as_mut_ptr() as *const libc::c_void,
               ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * 8i32) as
                   u64);
    }
    return 0i32;
}
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe fn gf2x_mod_mul(mut Res: *mut DIGIT,
                                      mut A: *const DIGIT,
                                      mut B: *const DIGIT) {
    let mut aux: [DIGIT; 1810] = [0; 1810];
    gf2x_mul_TC3(2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)),
                 aux.as_mut_ptr(),
                 (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), A,
                 (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), B);
    gf2x_mod(Res,
             2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)),
             aux.as_mut_ptr() as *const DIGIT);
}
// end gf2x_mod_mul
/*----------------------------------------------------------------------------*/
/* computes operand*x^shiftAmt + Res. assumes res is  
 * wide and operand is NUM_DIGITS_GF2X_ELEMENT with blank slack bits */
#[inline]
unsafe fn gf2x_fmac(mut Res: *mut DIGIT, mut operand: *const DIGIT,
                               shiftAmt: u32) {
    let mut digitShift: u32 =
        shiftAmt.wrapping_div((8i32 << 3i32) as u32);
    let mut inDigitShift: u32 =
        shiftAmt.wrapping_rem((8i32 << 3i32) as u32);
    let mut tmp: DIGIT = 0;
    let mut prevLo: DIGIT = 0i32 as DIGIT;
    let mut i: i32 = 0;
    let mut inDigitShiftMask: SIGNED_DIGIT =
        ((inDigitShift > 0i32 as u32) as i32 as SIGNED_DIGIT)
            << (8i32 << 3i32) - 1i32 >> (8i32 << 3i32) - 1i32;
    i = (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
    while i >= 0i32 {
        tmp = *operand.offset(i as isize);
        let ref mut fresh7 =
            *Res.offset((((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
                              + i) as u32).wrapping_sub(digitShift)
                            as isize);
        *fresh7 ^= prevLo | tmp << inDigitShift;

        if inDigitShift > 0 {
            prevLo =
                tmp >> ((8i32 << 3i32) as u32).wrapping_sub(inDigitShift)
                & inDigitShiftMask as u64;
        }
        i -= 1
    }
    let ref mut fresh8 =
        *Res.offset((((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) + i)
                         as u32).wrapping_sub(digitShift) as isize);
    *fresh8 ^= prevLo;
}
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/*PRE: the representation of the sparse coefficients is sorted in increasing
 order of the coefficients themselves */
#[no_mangle]
pub unsafe fn gf2x_mod_mul_dense_to_sparse(mut Res: *mut DIGIT,
                                                      mut dense: *const DIGIT,
                                                      mut sparse:
                                                          *const u32,
                                                      mut nPos:
                                                          u32) {
    let mut resDouble: [DIGIT; 1810] = [0; 1810];
    let mut i: u32 = 0i32 as u32;
    while i < nPos {
        if *sparse.offset(i as isize) != crate::consts::P as i32 as u32 {
            gf2x_fmac(resDouble.as_mut_ptr(), dense,
                      *sparse.offset(i as isize));
        }
        i = i.wrapping_add(1)
    }
    gf2x_mod(Res,
             2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)),
             resDouble.as_mut_ptr() as *const DIGIT);
}
// end gf2x_mod_mul
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe fn gf2x_transpose_in_place_sparse(mut sizeA:
                                                            i32,
                                                        mut A:
                                                            *mut u32) {
    let mut t: u32 = 0;
    let mut i: i32 = 0i32;
    let mut j: i32 = 0;
    if *A.offset(i as isize) == 0i32 as u32 { i = 1i32 }
    j = i;
    while i < sizeA && *A.offset(i as isize) != crate::consts::P as i32 as u32 {
        *A.offset(i as isize) =
            (crate::consts::P as i32 as u32).wrapping_sub(*A.offset(i as isize));
        i += 1
    }
    i -= 1i32;
    while j < i {
        t = *A.offset(j as isize);
        *A.offset(j as isize) = *A.offset(i as isize);
        *A.offset(i as isize) = t;
        j += 1;
        i -= 1
    };
}
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
// end gf2x_transpose_in_place_sparse
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe fn gf2x_mod_mul_sparse(mut sizeR: i32,
                                             mut Res: *mut u32,
                                             mut sizeA: i32,
                                             mut A: *const u32,
                                             mut sizeB: i32,
                                             mut B: *const u32) {
    /* compute all the coefficients, filling invalid positions with P*/
    let mut lastFilledPos: u32 = 0i32 as u32;
    let mut i: i32 = 0i32;
    while i < sizeA {
        let mut j: i32 = 0i32;
        while j < sizeB {
            let mut prod: u32 =
                (*A.offset(i as isize)).wrapping_add(*B.offset(j as isize));
            prod =
                if prod >= crate::consts::P as i32 as u32 {
                    prod.wrapping_sub(crate::consts::P as i32 as u32)
                } else { prod };
            if *A.offset(i as isize) != crate::consts::P as i32 as u32 &&
                   *B.offset(j as isize) != crate::consts::P as i32 as u32 {
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
    while read_idx < sizeR &&
              *Res.offset(read_idx as isize) != crate::consts::P as i32 as u32 {
        lastReadPos = *Res.offset(read_idx as isize);
        read_idx += 1;
        duplicateCount = 1i32;
        while *Res.offset(read_idx as isize) == lastReadPos &&
                  *Res.offset(read_idx as isize) != crate::consts::P as i32 as u32 {
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
    };
}
/*---------------------------------------------------------------------------*/
// end gf2x_mod_mul_sparse
/*----------------------------------------------------------------------------*/
/* the implementation is safe even in case A or B alias with the result */
/* PRE: A and B should be sorted and have INVALID_POS_VALUE at the end */
#[no_mangle]
pub unsafe fn gf2x_mod_add_sparse(mut sizeR: i32,
                                             mut Res: *mut u32,
                                             mut sizeA: i32,
                                             mut A: *mut u32,
                                             mut sizeB: i32,
                                             mut B: *mut u32) {
    let vla = sizeR as usize;
    let mut tmpRes: Vec<u32> = ::std::vec::from_elem(0, vla);
    let mut idxA: i32 = 0i32;
    let mut idxB: i32 = 0i32;
    let mut idxR: i32 = 0i32;
    while idxA < sizeA && idxB < sizeB &&
              *A.offset(idxA as isize) != crate::consts::P as i32 as u32 &&
              *B.offset(idxB as isize) != crate::consts::P as i32 as u32 {
        if *A.offset(idxA as isize) == *B.offset(idxB as isize) {
            idxA += 1;
            idxB += 1
        } else {
            if *A.offset(idxA as isize) < *B.offset(idxB as isize) {
                *tmpRes.as_mut_ptr().offset(idxR as isize) =
                    *A.offset(idxA as isize);
                idxA += 1
            } else {
                *tmpRes.as_mut_ptr().offset(idxR as isize) =
                    *B.offset(idxB as isize);
                idxB += 1
            }
            idxR += 1
        }
    }
    while idxA < sizeA && *A.offset(idxA as isize) != crate::consts::P as i32 as u32
          {
        *tmpRes.as_mut_ptr().offset(idxR as isize) = *A.offset(idxA as isize);
        idxA += 1;
        idxR += 1
    }
    while idxB < sizeB && *B.offset(idxB as isize) != crate::consts::P as i32 as u32
          {
        *tmpRes.as_mut_ptr().offset(idxR as isize) = *B.offset(idxB as isize);
        idxB += 1;
        idxR += 1
    }
    while idxR < sizeR {
        *tmpRes.as_mut_ptr().offset(idxR as isize) = crate::consts::P as i32 as u32;
        idxR += 1
    }
    memcpy(Res as *mut libc::c_void,
           tmpRes.as_mut_ptr() as *const libc::c_void,
           (::std::mem::size_of::<u32>() as
                u64).wrapping_mul(sizeR as u64));
}
// end gf2x_mod_add_sparse
/*----------------------------------------------------------------------------*/
/* Return a uniform random value in the range 0..n-1 inclusive,
 * applying a rejection sampling strategy and exploiting as a random source
 * the NIST seedexpander seeded with the proper key.
 * Assumes that the maximum value for the range n is 2^32-1
 */
unsafe fn rand_range(n: i32, logn: i32,
                                mut seed_expander_ctx: *mut AES_XOF_struct)
 -> i32 {
    let mut required_rnd_bytes: u64 =
        ((logn + 7i32) / 8i32) as u64;
    let mut rnd_char_buffer: [u8; 4] = [0; 4];
    let mut rnd_value: u32 = 0;
    let mut mask: u32 =
        ((1i32 as u32) << logn).wrapping_sub(1i32 as u32);
    loop  {
        seedexpander(seed_expander_ctx, rnd_char_buffer.as_mut_ptr(),
                     required_rnd_bytes);
        /* obtain an endianness independent representation of the generated random
       bytes into an unsigned integer */
        rnd_value =
            ((rnd_char_buffer[3] as u32) <<
                 24i32).wrapping_add((rnd_char_buffer[2] as u32) <<
                                         16i32).wrapping_add((rnd_char_buffer[1]
                                                                  as u32)
                                                                 <<
                                                                 8i32).wrapping_add((rnd_char_buffer[0]
                                                                                         as
                                                                                         u32)
                                                                                        <<
                                                                                        0i32);
        rnd_value = mask & rnd_value;
        if !(rnd_value >= n as u32) { break ; }
    }
    return rnd_value as i32;
}
// end rand_range
/*----------------------------------------------------------------------------*/
/* Obtains fresh randomness and seed-expands it until all the required positions
 * for the '1's in the circulant block are obtained */
#[no_mangle]
pub unsafe fn rand_circulant_sparse_block(mut pos_ones:
                                                         *mut u32,
                                                     countOnes: i32,
                                                     mut seed_expander_ctx:
                                                         *mut AES_XOF_struct) {
    let mut duplicated: i32 = 0;
    let mut placedOnes: i32 = 0i32;
    while placedOnes < countOnes {
        let mut p: i32 =
            rand_range(crate::consts::P as i32,
                       if crate::consts::P as i32 == 0i32 {
                           1i32
                       } else {
                           (31i32 +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 1i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 1i32 {
                                     1i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 2i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 2i32 {
                                     2i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 3i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 3i32 {
                                     3i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 4i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 4i32 {
                                     4i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 5i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 5i32 {
                                     5i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 6i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 6i32 {
                                     6i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 7i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 7i32 {
                                     7i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 8i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 8i32 {
                                     8i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 9i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 9i32 {
                                     9i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 10i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 10i32 {
                                     10i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 11i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 11i32 {
                                     11i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 12i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 12i32 {
                                     12i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 13i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 13i32 {
                                     13i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 14i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 14i32 {
                                     14i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 15i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 15i32 {
                                     15i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 16i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 16i32 {
                                     16i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 17i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 17i32 {
                                     17i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 18i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 18i32 {
                                     18i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 19i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 19i32 {
                                     19i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 20i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 20i32 {
                                     20i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 21i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 21i32 {
                                     21i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 22i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 22i32 {
                                     22i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 23i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 23i32 {
                                     23i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 24i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 24i32 {
                                     24i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 25i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 25i32 {
                                     25i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 26i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 26i32 {
                                     26i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 27i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 27i32 {
                                     27i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 28i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 28i32 {
                                     28i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 29i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 29i32 {
                                     29i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 30i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 30i32 {
                                     30i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 31i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 31i32 {
                                     31i32
                                 } else { -1i32 })) +
                               (if crate::consts::P as i32 as u64 >=
                                       1u64 << 32i32 - 1i32 &&
                                       (crate::consts::P as i32 as u64) <
                                           1u64 << 32i32 {
                                    32i32
                                } else { -1i32 })
                       }, seed_expander_ctx);
        duplicated = 0i32;
        let mut j: i32 = 0i32;
        while j < placedOnes {
            if *pos_ones.offset(j as isize) == p as u32 {
                duplicated = 1i32
            }
            j += 1
        }
        if duplicated == 0i32 {
            *pos_ones.offset(placedOnes as isize) = p as u32;
            placedOnes += 1
        }
    };
}
// rand_circulant_sparse_block
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe fn rand_circulant_blocks_sequence(mut sequence:
                                                            *mut DIGIT,
                                                        countOnes:
                                                            i32,
                                                        mut seed_expander_ctx:
                                                            *mut AES_XOF_struct) {
    let vla = countOnes as usize;
    let mut rndPos: Vec<i32> = ::std::vec::from_elem(0, vla);
    let mut duplicated: i32 = 0;
    let mut counter: i32 = 0i32;
    memset(sequence as *mut libc::c_void, 0i32,
           (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64);
    while counter < countOnes {
        let mut p: i32 =
            rand_range(2i32 * crate::consts::P as i32,
                       if crate::consts::P as i32 == 0i32 {
                           1i32
                       } else {
                           (31i32 +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 1i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 1i32 {
                                     1i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 2i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 2i32 {
                                     2i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 3i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 3i32 {
                                     3i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 4i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 4i32 {
                                     4i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 5i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 5i32 {
                                     5i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 6i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 6i32 {
                                     6i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 7i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 7i32 {
                                     7i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 8i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 8i32 {
                                     8i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 9i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 9i32 {
                                     9i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 10i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 10i32 {
                                     10i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 11i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 11i32 {
                                     11i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 12i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 12i32 {
                                     12i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 13i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 13i32 {
                                     13i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 14i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 14i32 {
                                     14i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 15i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 15i32 {
                                     15i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 16i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 16i32 {
                                     16i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 17i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 17i32 {
                                     17i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 18i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 18i32 {
                                     18i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 19i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 19i32 {
                                     19i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 20i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 20i32 {
                                     20i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 21i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 21i32 {
                                     21i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 22i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 22i32 {
                                     22i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 23i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 23i32 {
                                     23i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 24i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 24i32 {
                                     24i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 25i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 25i32 {
                                     25i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 26i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 26i32 {
                                     26i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 27i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 27i32 {
                                     27i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 28i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 28i32 {
                                     28i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 29i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 29i32 {
                                     29i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 30i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 30i32 {
                                     30i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 31i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 31i32 {
                                     31i32
                                 } else { -1i32 })) +
                               (if crate::consts::P as i32 as u64 >=
                                       1u64 << 32i32 - 1i32 &&
                                       (crate::consts::P as i32 as u64) <
                                           1u64 << 32i32 {
                                    32i32
                                } else { -1i32 })
                       }, seed_expander_ctx);
        duplicated = 0i32;
        let mut j: i32 = 0i32;
        while j < counter {
            if *rndPos.as_mut_ptr().offset(j as isize) == p {
                duplicated = 1i32
            }
            j += 1
        }
        if duplicated == 0i32 {
            *rndPos.as_mut_ptr().offset(counter as isize) = p;
            counter += 1
        }
    }
    let mut j_0: i32 = 0i32;
    while j_0 < counter {
        let mut polyIndex: i32 =
            *rndPos.as_mut_ptr().offset(j_0 as isize) / crate::consts::P as i32;
        let mut exponent: i32 =
            *rndPos.as_mut_ptr().offset(j_0 as isize) % crate::consts::P as i32;
        gf2x_set_coeff(sequence.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                            (8i32 << 3i32) * polyIndex) as
                                           isize), exponent as u32,
                       1i32 as DIGIT);
        j_0 += 1
    };
}
// end rand_circulant_blocks_sequence
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe fn rand_error_pos(mut errorPos: *mut u32,
                                        mut seed_expander_ctx:
                                            *mut AES_XOF_struct) {
    let mut duplicated: i32 = 0;
    let mut counter: i32 = 0i32;
    while counter < 199i32 {
        let mut p: i32 =
            rand_range(2i32 * crate::consts::P as i32,
                       if crate::consts::P as i32 == 0i32 {
                           1i32
                       } else {
                           (31i32 +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 1i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 1i32 {
                                     1i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 2i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 2i32 {
                                     2i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 3i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 3i32 {
                                     3i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 4i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 4i32 {
                                     4i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 5i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 5i32 {
                                     5i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 6i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 6i32 {
                                     6i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 7i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 7i32 {
                                     7i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 8i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 8i32 {
                                     8i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 9i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 9i32 {
                                     9i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 10i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 10i32 {
                                     10i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 11i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 11i32 {
                                     11i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 12i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 12i32 {
                                     12i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 13i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 13i32 {
                                     13i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 14i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 14i32 {
                                     14i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 15i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 15i32 {
                                     15i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 16i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 16i32 {
                                     16i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 17i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 17i32 {
                                     17i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 18i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 18i32 {
                                     18i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 19i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 19i32 {
                                     19i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 20i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 20i32 {
                                     20i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 21i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 21i32 {
                                     21i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 22i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 22i32 {
                                     22i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 23i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 23i32 {
                                     23i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 24i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 24i32 {
                                     24i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 25i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 25i32 {
                                     25i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 26i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 26i32 {
                                     26i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 27i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 27i32 {
                                     27i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 28i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 28i32 {
                                     28i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 29i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 29i32 {
                                     29i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 30i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 30i32 {
                                     30i32
                                 } else { -1i32 }) +
                                (if crate::consts::P as i32 as u64 >=
                                        1u64 << 31i32 - 1i32 &&
                                        (crate::consts::P as i32 as u64) <
                                            1u64 << 31i32 {
                                     31i32
                                 } else { -1i32 })) +
                               (if crate::consts::P as i32 as u64 >=
                                       1u64 << 32i32 - 1i32 &&
                                       (crate::consts::P as i32 as u64) <
                                           1u64 << 32i32 {
                                    32i32
                                } else { -1i32 })
                       }, seed_expander_ctx);
        duplicated = 0i32;
        let mut j: i32 = 0i32;
        while j < counter {
            if *errorPos.offset(j as isize) == p as u32 {
                duplicated = 1i32
            }
            j += 1
        }
        if duplicated == 0i32 {
            *errorPos.offset(counter as isize) = p as u32;
            counter += 1
        }
    };
}
/* *
 *
 * <gf2x_arith_mod_xPplusOne.h>
 *
 * @version 2.0 (March 2019)
 *
 * Reference ISO-C11 Implementation of LEDAcrypt using GCC built-ins.
 *
 * In alphabetical order:
 *
 * @author Marco Baldi <m.baldi@univpm.it>
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Franco Chiaraluce <f.chiaraluce@univpm.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author Paolo Santini <p.santini@pm.univpm.it>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
// end gf2x_copy
/*---------------------------------------------------------------------------*/
// void gf2x_mod(DIGIT out[],
//               const int nin, const DIGIT in[]); /* out(x) = in(x) mod x^P+1  */
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
// end gf2x_mod_add
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
/* ret. 1 if inv. exists */
/*---------------------------------------------------------------------------*/
/* in place bit-transp. of a(x) % x^P+1  *
                                      * e.g.: a3 a2 a1 a0 --> a1 a2 a3 a0     */
/*---------------------------------------------------------------------------*/
/* population count for a single polynomial */
// end population_count
/*--------------------------------------------------------------------------*/
/* returns the coefficient of the x^exponent term as the LSB of a digit */
/*--------------------------------------------------------------------------*/
/* sets the coefficient of the x^exponent term as the LSB of a digit */
/* clear given coefficient */
/*--------------------------------------------------------------------------*/
/* toggles (flips) the coefficient of the x^exponent term as the LSB of a digit */
/* clear given coefficient */
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
// end rand_error_pos
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe fn expand_error(mut sequence: *mut DIGIT,
                                      mut errorPos: *mut u32) {
    memset(sequence as *mut libc::c_void, 0i32,
           (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64);
    let mut j: i32 = 0i32;
    while j < 199i32 {
        let mut polyIndex: i32 =
            (*errorPos.offset(j as
                                  isize)).wrapping_div(crate::consts::P as i32 as
                                                           u32) as
                i32;
        let mut exponent: i32 =
            (*errorPos.offset(j as
                                  isize)).wrapping_rem(crate::consts::P as i32 as
                                                           u32) as
                i32;
        gf2x_set_coeff(sequence.offset(((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                            (8i32 << 3i32) * polyIndex) as
                                           isize), exponent as u32,
                       1i32 as DIGIT);
        j += 1
    };
}
/*----------------------------------------------------------------------------*/
// end rand_circulant_blocks_sequence
