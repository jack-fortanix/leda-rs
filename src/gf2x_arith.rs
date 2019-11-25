use crate::consts::*;
use crate::types::*;

extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
}

pub fn gf2x_copy(mut dest: &mut [DIGIT], input: &[DIGIT]) {
    for i in 0..NUM_DIGITS_GF2X_ELEMENT {
        dest[i] = input[i];
    }
}

pub fn population_count(upc: &[DIGIT]) -> usize {
    let mut sum : usize = 0;
    for x in upc {
        sum += x.count_ones() as usize;
    }
    return sum;
}

pub unsafe fn gf2x_get_coeff(mut poly: *const DIGIT, exponent: u32) -> DIGIT {
    let mut straightIdx: u32 = (((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
        * (8i32 << 3i32)
        - 1i32) as u32)
        .wrapping_sub(exponent);
    let mut digitIdx: u32 = straightIdx.wrapping_div((8i32 << 3i32) as u32);
    let mut inDigitIdx: u32 = straightIdx.wrapping_rem((8i32 << 3i32) as u32);
    return *poly.offset(digitIdx as isize)
        >> (((8i32 << 3i32) - 1i32) as u32).wrapping_sub(inDigitIdx)
        & 1i32 as DIGIT;
}

pub unsafe fn gf2x_mod_add(mut Res: *mut DIGIT, A: *const DIGIT, B: *const DIGIT) {
    gf2x_add(
        NUM_DIGITS_GF2X_ELEMENT as i32,
        Res,
        NUM_DIGITS_GF2X_ELEMENT as i32,
        A,
        NUM_DIGITS_GF2X_ELEMENT as i32,
        B,
    );
}

pub unsafe fn gf2x_toggle_coeff(mut poly: *mut DIGIT, exponent: u32) {
    let mut straightIdx: i32 = (((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
        * (8i32 << 3i32)
        - 1i32) as u32)
        .wrapping_sub(exponent) as i32;
    let mut digitIdx: i32 = straightIdx / (8i32 << 3i32);
    let mut inDigitIdx: u32 = (straightIdx % (8i32 << 3i32)) as u32;
    let mut mask: DIGIT =
        (1i32 as DIGIT) << (((8i32 << 3i32) - 1i32) as u32).wrapping_sub(inDigitIdx);
    *poly.offset(digitIdx as isize) = *poly.offset(digitIdx as isize) ^ mask;
}

/* *
 *
 * <gf2x_arith.h>
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
/*
 * Elements of GF(2)[x] are stored in compact dense binary form.
 *
 * Each bit in a byte is assumed to be the coefficient of a binary
 * polynomial f(x), in Big-Endian format (i.e., reading everything from
 * left to right, the most significant element is met first):
 *
 * byte:(0000 0000) == 0x00 ... f(x) == 0
 * byte:(0000 0001) == 0x01 ... f(x) == 1
 * byte:(0000 0010) == 0x02 ... f(x) == x
 * byte:(0000 0011) == 0x03 ... f(x) == x+1
 * ...                      ... ...
 * byte:(0000 1111) == 0x0F ... f(x) == x^{3}+x^{2}+x+1
 * ...                      ... ...
 * byte:(1111 1111) == 0xFF ... f(x) == x^{7}+x^{6}+x^{5}+x^{4}+x^{3}+x^{2}+x+1
 *
 *
 * A "machine word" (A_i) is considered as a DIGIT.
 * Bytes in a DIGIT are assumed in Big-Endian format:
 * E.g., if sizeof(DIGIT) == 4:
 * A_i: A_{i,3} A_{i,2} A_{i,1} A_{i,0}.
 * A_{i,3} denotes the most significant byte, A_{i,0} the least significant one.
 * f(x) ==   x^{31} + ... + x^{24} +
 *         + x^{23} + ... + x^{16} +
 *         + x^{15} + ... + x^{8}  +
 *         + x^{7}  + ... + x^{0}
 *
 *
 * Multi-precision elements (i.e., with multiple DIGITs) are stored in
 * Big-endian format:
 *           A = A_{n-1} A_{n-2} ... A_1 A_0
 *
 *           position[A_{n-1}] == 0
 *           position[A_{n-2}] == 1
 *           ...
 *           position[A_{1}]  ==  n-2
 *           position[A_{0}]  ==  n-1
 */
/*----------------------------------------------------------------------------*/
pub unsafe fn gf2x_add(
    nr: i32,
    mut Res: *mut DIGIT,
    _na: i32,
    mut A: *const DIGIT,
    _nb: i32,
    mut B: *const DIGIT,
) {
    let mut i: u32 = 0i32 as u32;
    while i < nr as u32 {
        *Res.offset(i as isize) = *A.offset(i as isize) ^ *B.offset(i as isize);
        i = i.wrapping_add(1)
    }
}

/*--------------------------------------------------------------------------*/
/* sets the coefficient of the x^exponent term as the LSB of a digit */
pub fn gf2x_set_coeff(poly: &mut [DIGIT], exponent: usize, value: DIGIT) {
    let straightIdx = (NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_b - 1) - exponent;
    let digitIdx = straightIdx / DIGIT_SIZE_b;
    let inDigitIdx = straightIdx % DIGIT_SIZE_b;

    /* clear given coefficient */
    let mask = !(((1 as DIGIT)) << (DIGIT_SIZE_b-1-inDigitIdx));
    poly[digitIdx] = poly[digitIdx] & mask;
    poly[digitIdx] = poly[digitIdx] | (( value & (1 as DIGIT)) << (DIGIT_SIZE_b-1-inDigitIdx));
}

unsafe fn gf2x_mul_comb(
    nr: i32,
    mut Res: *mut DIGIT,
    na: i32,
    mut A: *const DIGIT,
    nb: i32,
    mut B: *const DIGIT,
) {
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut k: i32 = 0;
    let mut u: DIGIT = 0;
    let mut h: DIGIT = 0;
    memset(
        Res as *mut libc::c_void,
        0i32,
        (nr as u64).wrapping_mul(::std::mem::size_of::<DIGIT>() as u64),
    );
    k = (8i32 << 3i32) - 1i32;
    while k > 0i32 {
        i = na - 1i32;
        while i >= 0i32 {
            if *A.offset(i as isize) & (0x1i32 as DIGIT) << k != 0 {
                j = nb - 1i32;
                while j >= 0i32 {
                    let ref mut fresh0 = *Res.offset((i + j + 1i32) as isize);
                    *fresh0 ^= *B.offset(j as isize);
                    j -= 1
                }
            }
            i -= 1
        }
        u = *Res.offset((na + nb - 1i32) as isize);
        *Res.offset((na + nb - 1i32) as isize) = u << 0x1i32;
        j = 1i32;
        while j < na + nb {
            h = u >> (8i32 << 3i32) - 1i32;
            u = *Res.offset((na + nb - 1i32 - j) as isize);
            *Res.offset((na + nb - 1i32 - j) as isize) = h ^ u << 0x1i32;
            j += 1
        }
        k -= 1
    }
    i = na - 1i32;
    while i >= 0i32 {
        if *A.offset(i as isize) & 0x1i32 as DIGIT != 0 {
            j = nb - 1i32;
            while j >= 0i32 {
                let ref mut fresh1 = *Res.offset((i + j + 1i32) as isize);
                *fresh1 ^= *B.offset(j as isize);
                j -= 1
            }
        }
        i -= 1
    }
}
/*----------------------------------------------------------------------------*/
/* allows the second operand to be shorter than the first */
/* the result should be as large as the first operand*/

unsafe fn gf2x_add_asymm(
    _nr: i32,
    mut Res: *mut DIGIT,
    na: i32,
    mut A: *const DIGIT,
    nb: i32,
    mut B: *const DIGIT,
) {
    let mut delta: i32 = na - nb;
    memcpy(
        Res as *mut libc::c_void,
        A as *const libc::c_void,
        (delta * 8i32) as u64,
    );
    gf2x_add(
        nb,
        Res.offset(delta as isize),
        nb,
        A.offset(delta as isize),
        nb,
        B,
    );
}
// end gf2x_add
/*----------------------------------------------------------------------------*/
/* PRE: MAX ALLOWED ROTATION AMOUNT : DIGIT_SIZE_b */

pub unsafe fn right_bit_shift_n(length: i32, mut input: *mut DIGIT, amount: i32) {
    if amount >= 8i32 << 3i32 {
        panic!("amount > DIGIT_SIZE");
    }
    if amount == 0i32 {
        return;
    }
    let mut j: i32 = 0;
    let mut mask: DIGIT = 0;
    mask = ((0x1i32 as DIGIT) << amount).wrapping_sub(1i32 as u64);
    j = length - 1i32;
    while j > 0i32 {
        *input.offset(j as isize) >>= amount;
        let ref mut fresh2 = *input.offset(j as isize);
        *fresh2 |= (*input.offset((j - 1i32) as isize) & mask) << (8i32 << 3i32) - amount;
        j -= 1
    }
    *input.offset(j as isize) >>= amount;
}

pub unsafe fn left_bit_shift_n(length: i32, mut input: *mut DIGIT, amount: i32) {
    if amount > 8i32 << 3i32 {
        panic!("amount > DIGIT_SIZE_b");
    }
    if amount == 0i32 {
        return;
    }
    let mut j: i32 = 0;
    let mut mask: DIGIT = 0;
    mask = !((0x1i32 as DIGIT) << (8i32 << 3i32) - amount).wrapping_sub(1i32 as u64);
    j = 0i32;
    while j < length - 1i32 {
        *input.offset(j as isize) <<= amount;
        let ref mut fresh3 = *input.offset(j as isize);
        *fresh3 |= (*input.offset((j + 1i32) as isize) & mask) >> (8i32 << 3i32) - amount;
        j += 1
    }
    *input.offset(j as isize) <<= amount;
}
// end left_bit_shift_n
/*----------------------------------------------------------------------------*/
#[inline]
unsafe fn gf2x_exact_div_x_plus_one(na: i32, mut A: *mut DIGIT) {
    let mut t: DIGIT = 0;
    let mut i: i32 = na - 1i32;
    while i >= 0i32 {
        t ^= *A.offset(i as isize);
        let mut j: i32 = 1i32;
        while j <= (8i32 << 3i32) / 2i32 {
            t ^= t << j as u32;
            j = j * 2i32
        }
        *A.offset(i as isize) = t;
        t >>= (8i32 << 3i32) - 1i32;
        i -= 1
    }
}
// end gf2x_exact_div_x_plus_one
/*---------------------------------------------------------------------------*/

unsafe fn gf2x_mul_Kar(
    nr: i32,
    mut Res: *mut DIGIT,
    na: i32,
    mut A: *const DIGIT,
    nb: i32,
    mut B: *const DIGIT,
) {
    if na < 9i32 || nb < 9i32 {
        /* fall back to schoolbook */
        gf2x_mul_comb(nr, Res, na, A, nb, B);
        return;
    }
    if na % 2i32 == 0i32 {
        let mut bih: u32 = (na / 2i32) as u32;
        let vla = (2i32 as u32).wrapping_mul(bih) as usize;
        let mut middle: Vec<DIGIT> = ::std::vec::from_elem(0, vla);
        let vla_0 = bih as usize;
        let mut sumA: Vec<DIGIT> = ::std::vec::from_elem(0, vla_0);
        let vla_1 = bih as usize;
        let mut sumB: Vec<DIGIT> = ::std::vec::from_elem(0, vla_1);
        gf2x_add(
            bih as i32,
            sumA.as_mut_ptr(),
            bih as i32,
            A,
            bih as i32,
            A.offset(bih as isize),
        );
        gf2x_add(
            bih as i32,
            sumB.as_mut_ptr(),
            bih as i32,
            B,
            bih as i32,
            B.offset(bih as isize),
        );
        gf2x_mul_Kar(
            (2i32 as u32).wrapping_mul(bih) as i32,
            middle.as_mut_ptr(),
            bih as i32,
            sumA.as_ptr(),
            bih as i32,
            sumB.as_ptr(),
        );
        gf2x_mul_Kar(
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset((2i32 as u32).wrapping_mul(bih) as isize),
            bih as i32,
            A.offset(bih as isize),
            bih as i32,
            B.offset(bih as isize),
        );
        gf2x_add(
            (2i32 as u32).wrapping_mul(bih) as i32,
            middle.as_mut_ptr(),
            (2i32 as u32).wrapping_mul(bih) as i32,
            middle.as_ptr(),
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset((2i32 as u32).wrapping_mul(bih) as isize) as *const DIGIT,
        );
        gf2x_mul_Kar(
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res,
            bih as i32,
            A,
            bih as i32,
            B,
        );
        gf2x_add(
            (2i32 as u32).wrapping_mul(bih) as i32,
            middle.as_mut_ptr(),
            (2i32 as u32).wrapping_mul(bih) as i32,
            middle.as_ptr(),
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res as *const DIGIT,
        );
        gf2x_add(
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset(bih as isize),
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset(bih as isize) as *const DIGIT,
            (2i32 as u32).wrapping_mul(bih) as i32,
            middle.as_ptr(),
        );
    } else {
        let mut bih_0: u32 = (na / 2i32 + 1i32) as u32;
        let vla_2 = (2i32 as u32).wrapping_mul(bih_0) as usize;
        let mut middle_0: Vec<DIGIT> = ::std::vec::from_elem(0, vla_2);
        let vla_3 = bih_0 as usize;
        let mut sumA_0: Vec<DIGIT> = ::std::vec::from_elem(0, vla_3);
        let vla_4 = bih_0 as usize;
        let mut sumB_0: Vec<DIGIT> = ::std::vec::from_elem(0, vla_4);
        gf2x_add_asymm(
            bih_0 as i32,
            sumA_0.as_mut_ptr(),
            bih_0 as i32,
            A.offset(bih_0 as isize).offset(-1),
            bih_0.wrapping_sub(1i32 as u32) as i32,
            A,
        );
        gf2x_add_asymm(
            bih_0 as i32,
            sumB_0.as_mut_ptr(),
            bih_0 as i32,
            B.offset(bih_0 as isize).offset(-1),
            bih_0.wrapping_sub(1i32 as u32) as i32,
            B,
        );
        gf2x_mul_Kar(
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            middle_0.as_mut_ptr(),
            bih_0 as i32,
            sumA_0.as_ptr(),
            bih_0 as i32,
            sumB_0.as_ptr(),
        );
        gf2x_mul_Kar(
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            Res.offset((2i32 as u32).wrapping_mul(bih_0.wrapping_sub(1i32 as u32)) as isize),
            bih_0 as i32,
            A.offset(bih_0 as isize).offset(-1),
            bih_0 as i32,
            B.offset(bih_0 as isize).offset(-1),
        );
        gf2x_add(
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            middle_0.as_mut_ptr(),
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            middle_0.as_ptr(),
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            Res.offset((2i32 as u32).wrapping_mul(bih_0.wrapping_sub(1i32 as u32)) as isize)
                as *const DIGIT,
        );
        gf2x_mul_Kar(
            (2i32 as u32).wrapping_mul(bih_0.wrapping_sub(1i32 as u32)) as i32,
            Res,
            bih_0.wrapping_sub(1i32 as u32) as i32,
            A,
            bih_0.wrapping_sub(1i32 as u32) as i32,
            B,
        );
        gf2x_add_asymm(
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            middle_0.as_mut_ptr(),
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            middle_0.as_ptr(),
            (2i32 as u32).wrapping_mul(bih_0.wrapping_sub(1i32 as u32)) as i32,
            Res as *const DIGIT,
        );
        gf2x_add(
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            Res.offset(bih_0 as isize).offset(-2),
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            Res.offset(bih_0 as isize).offset(-2) as *const DIGIT,
            (2i32 as u32).wrapping_mul(bih_0) as i32,
            middle_0.as_ptr(),
        );
    };
}
// end gf2x_add
/*----------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
/* Toom-Cook 3 algorithm as reported in
 * Marco Bodrato: "Towards Optimal Toom-Cook Multiplication for Univariate and
 * Multivariate Polynomials in Characteristic 2 and 0". WAIFI 2007: 116-133   */

pub unsafe fn gf2x_mul_TC3(
    nr: i32,
    mut Res: *mut DIGIT,
    na: i32,
    mut A: *const DIGIT,
    nb: i32,
    mut B: *const DIGIT,
) {
    if na < 50i32 || nb < 50i32 {
        /* fall back to schoolbook */
        gf2x_mul_Kar(nr, Res, na, A, nb, B); //number of limbs for each part.
        return;
    }
    let mut bih: u32 = 0;
    if na % 3i32 == 0i32 {
        bih = (na / 3i32) as u32
    } else {
        bih = (na / 3i32 + 1i32) as u32
    }
    let vla = bih as usize;
    let mut u2: Vec<DIGIT> = ::std::vec::from_elem(0, vla);
    let mut u1: *mut DIGIT = 0 as *mut DIGIT;
    let mut u0: *mut DIGIT = 0 as *mut DIGIT;
    let mut leading_slack: i32 = (3i32 - na % 3i32) % 3i32;
    //     printf("leading slack %d",leading_slack);
    let mut i: i32 = 0; /* partitioned inputs */
    i = 0i32; /*bih digit wide*/
    while i < leading_slack {
        *u2.as_mut_ptr().offset(i as isize) = 0i32 as DIGIT; /*bih digit wide*/
        i += 1
    }
    while (i as u32) < bih {
        *u2.as_mut_ptr().offset(i as isize) = *A.offset((i - leading_slack) as isize);
        i += 1
    }
    u1 = A.offset(bih as isize).offset(-(leading_slack as isize)) as *mut DIGIT;
    u0 = A
        .offset((2i32 as u32).wrapping_mul(bih) as isize)
        .offset(-(leading_slack as isize)) as *mut DIGIT;
    let vla_0 = bih as usize;
    let mut v2: Vec<DIGIT> = ::std::vec::from_elem(0, vla_0);
    let mut v1: *mut DIGIT = 0 as *mut DIGIT;
    let mut v0: *mut DIGIT = 0 as *mut DIGIT;
    i = 0i32;
    while i < leading_slack {
        *v2.as_mut_ptr().offset(i as isize) = 0i32 as DIGIT;
        i += 1
    }
    while (i as u32) < bih {
        *v2.as_mut_ptr().offset(i as isize) = *B.offset((i - leading_slack) as isize);
        i += 1
    }
    v1 = B.offset(bih as isize).offset(-(leading_slack as isize)) as *mut DIGIT;
    v0 = B
        .offset((2i32 as u32).wrapping_mul(bih) as isize)
        .offset(-(leading_slack as isize)) as *mut DIGIT;
    let vla_1 = bih as usize;
    let mut sum_u: Vec<DIGIT> = ::std::vec::from_elem(0, vla_1);
    gf2x_add(
        bih as i32,
        sum_u.as_mut_ptr(),
        bih as i32,
        u0 as *const DIGIT,
        bih as i32,
        u1 as *const DIGIT,
    );
    gf2x_add(
        bih as i32,
        sum_u.as_mut_ptr(),
        bih as i32,
        sum_u.as_ptr(),
        bih as i32,
        u2.as_ptr(),
    );
    let vla_2 = bih as usize;
    let mut sum_v: Vec<DIGIT> = ::std::vec::from_elem(0, vla_2);
    gf2x_add(
        bih as i32,
        sum_v.as_mut_ptr(),
        bih as i32,
        v0 as *const DIGIT,
        bih as i32,
        v1 as *const DIGIT,
    );
    gf2x_add(
        bih as i32,
        sum_v.as_mut_ptr(),
        bih as i32,
        sum_v.as_ptr(),
        bih as i32,
        v2.as_ptr(),
    );
    let vla_3 = (2i32 as u32).wrapping_mul(bih) as usize;
    let mut w1: Vec<DIGIT> = ::std::vec::from_elem(0, vla_3);
    gf2x_mul_TC3(
        (2i32 as u32).wrapping_mul(bih) as i32,
        w1.as_mut_ptr(),
        bih as i32,
        sum_u.as_ptr(),
        bih as i32,
        sum_v.as_ptr(),
    );
    let vla_4 = bih.wrapping_add(1i32 as u32) as usize;
    let mut u2_x2: Vec<DIGIT> = ::std::vec::from_elem(0, vla_4);
    *u2_x2.as_mut_ptr().offset(0) = 0i32 as DIGIT;
    memcpy(
        u2_x2.as_mut_ptr().offset(1) as *mut libc::c_void,
        u2.as_mut_ptr() as *const libc::c_void,
        bih.wrapping_mul(8i32 as u32) as u64,
    );
    left_bit_shift_n(
        bih.wrapping_add(1i32 as u32) as i32,
        u2_x2.as_mut_ptr(),
        2i32,
    );
    let vla_5 = bih.wrapping_add(1i32 as u32) as usize;
    let mut u1_x: Vec<DIGIT> = ::std::vec::from_elem(0, vla_5);
    *u1_x.as_mut_ptr().offset(0) = 0i32 as DIGIT;
    memcpy(
        u1_x.as_mut_ptr().offset(1) as *mut libc::c_void,
        u1 as *const libc::c_void,
        bih.wrapping_mul(8i32 as u32) as u64,
    );
    left_bit_shift_n(
        bih.wrapping_add(1i32 as u32) as i32,
        u1_x.as_mut_ptr(),
        1i32,
    );
    let vla_6 = bih.wrapping_add(1i32 as u32) as usize;
    let mut u1_x1_u2_x2: Vec<DIGIT> = ::std::vec::from_elem(0, vla_6);
    gf2x_add(
        bih.wrapping_add(1i32 as u32) as i32,
        u1_x1_u2_x2.as_mut_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        u1_x.as_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        u2_x2.as_ptr(),
    );
    let vla_7 = bih.wrapping_add(1i32 as u32) as usize;
    let mut temp_u_components: Vec<DIGIT> = ::std::vec::from_elem(0, vla_7);
    gf2x_add_asymm(
        bih.wrapping_add(1i32 as u32) as i32,
        temp_u_components.as_mut_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        u1_x1_u2_x2.as_ptr(),
        bih as i32,
        sum_u.as_ptr(),
    );
    let vla_8 = bih.wrapping_add(1i32 as u32) as usize;
    let mut v2_x2: Vec<DIGIT> = ::std::vec::from_elem(0, vla_8);
    *v2_x2.as_mut_ptr().offset(0) = 0i32 as DIGIT;
    memcpy(
        v2_x2.as_mut_ptr().offset(1) as *mut libc::c_void,
        v2.as_mut_ptr() as *const libc::c_void,
        bih.wrapping_mul(8i32 as u32) as u64,
    );
    left_bit_shift_n(
        bih.wrapping_add(1i32 as u32) as i32,
        v2_x2.as_mut_ptr(),
        2i32,
    );
    let vla_9 = bih.wrapping_add(1i32 as u32) as usize;
    let mut v1_x: Vec<DIGIT> = ::std::vec::from_elem(0, vla_9);
    *v1_x.as_mut_ptr().offset(0) = 0i32 as DIGIT;
    memcpy(
        v1_x.as_mut_ptr().offset(1) as *mut libc::c_void,
        v1 as *const libc::c_void,
        bih.wrapping_mul(8i32 as u32) as u64,
    );
    left_bit_shift_n(
        bih.wrapping_add(1i32 as u32) as i32,
        v1_x.as_mut_ptr(),
        1i32,
    );
    let vla_10 = bih.wrapping_add(1i32 as u32) as usize;
    let mut v1_x1_v2_x2: Vec<DIGIT> = ::std::vec::from_elem(0, vla_10);
    gf2x_add(
        bih.wrapping_add(1i32 as u32) as i32,
        v1_x1_v2_x2.as_mut_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        v1_x.as_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        v2_x2.as_ptr(),
    );
    let vla_11 = bih.wrapping_add(1i32 as u32) as usize;
    let mut temp_v_components: Vec<DIGIT> = ::std::vec::from_elem(0, vla_11);
    gf2x_add_asymm(
        bih.wrapping_add(1i32 as u32) as i32,
        temp_v_components.as_mut_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        v1_x1_v2_x2.as_ptr(),
        bih as i32,
        sum_v.as_ptr(),
    );

    let mut w3: Vec<DIGIT> = vec![0; 2*(bih as usize)+2];
    gf2x_mul_TC3(
        w3.len() as i32,
        w3.as_mut_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        temp_u_components.as_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        temp_v_components.as_ptr(),
    );
    gf2x_add_asymm(
        bih.wrapping_add(1i32 as u32) as i32,
        u1_x1_u2_x2.as_mut_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        u1_x1_u2_x2.as_ptr(),
        bih as i32,
        u0 as *const DIGIT,
    );
    gf2x_add_asymm(
        bih.wrapping_add(1i32 as u32) as i32,
        v1_x1_v2_x2.as_mut_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        v1_x1_v2_x2.as_ptr(),
        bih as i32,
        v0 as *const DIGIT,
    );
    let mut w2: Vec<DIGIT> = vec![0; 2*(bih as usize)+2];
    gf2x_mul_TC3(
        w3.len() as i32,
        w2.as_mut_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        u1_x1_u2_x2.as_ptr(),
        bih.wrapping_add(1i32 as u32) as i32,
        v1_x1_v2_x2.as_ptr(),
    );
    let vla_14 = (2i32 as u32).wrapping_mul(bih) as usize;
    let mut w4: Vec<DIGIT> = ::std::vec::from_elem(0, vla_14);
    gf2x_mul_TC3(
        (2i32 as u32).wrapping_mul(bih) as i32,
        w4.as_mut_ptr(),
        bih as i32,
        u2.as_ptr(),
        bih as i32,
        v2.as_ptr(),
    );
    let vla_15 = (2i32 as u32).wrapping_mul(bih) as usize;
    let mut w0: Vec<DIGIT> = ::std::vec::from_elem(0, vla_15);
    gf2x_mul_TC3(
        (2i32 as u32).wrapping_mul(bih) as i32,
        w0.as_mut_ptr(),
        bih as i32,
        u0 as *const DIGIT,
        bih as i32,
        v0 as *const DIGIT,
    );
    // Interpolation starts
    gf2x_add(
        w3.len() as i32,
        w3.as_mut_ptr(),
        w2.len() as i32,
        w2.as_ptr(),
        w3.len() as i32,
        w3.as_ptr(),
    );
    gf2x_add_asymm(
        w2.len() as i32,
        w2.as_mut_ptr(),
        w2.len() as i32,
        w2.as_ptr(),
        (2i32 as u32).wrapping_mul(bih) as i32,
        w0.as_ptr(),
    );
    right_bit_shift_n(
        (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) as i32,
        w2.as_mut_ptr(),
        1i32,
    );
    gf2x_add(
        w2.len() as i32,
        w2.as_mut_ptr(),
        (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) as i32,
        w2.as_ptr(),
        w3.len() as i32,
        w3.as_ptr(),
    );
    // w2 + (w4 * x^3+1) = w2 + w4 + w4 << 3
    let vla_16 = (2i32 as u32).wrapping_mul(bih).wrapping_add(1i32 as u32) as usize;
    let mut w4_x3_plus_1: Vec<DIGIT> = ::std::vec::from_elem(0, vla_16);
    *w4_x3_plus_1.as_mut_ptr().offset(0) = 0i32 as DIGIT;
    memcpy(
        w4_x3_plus_1.as_mut_ptr().offset(1) as *mut libc::c_void,
        w4.as_mut_ptr() as *const libc::c_void,
        (2i32 as u32).wrapping_mul(bih).wrapping_mul(8i32 as u32) as u64,
    );
    left_bit_shift_n(
        (2i32 as u32).wrapping_mul(bih).wrapping_add(1i32 as u32) as i32,
        w4_x3_plus_1.as_mut_ptr(),
        3i32,
    );
    gf2x_add_asymm(
        (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) as i32,
        w2.as_mut_ptr(),
        (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) as i32,
        w2.as_ptr(),
        (2i32 as u32).wrapping_mul(bih) as i32,
        w4.as_ptr(),
    );
    gf2x_add_asymm(
        (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) as i32,
        w2.as_mut_ptr(),
        (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) as i32,
        w2.as_ptr(),
        (2i32 as u32).wrapping_mul(bih).wrapping_add(1i32 as u32) as i32,
        w4_x3_plus_1.as_ptr(),
    );
    gf2x_exact_div_x_plus_one(
        (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) as i32,
        w2.as_mut_ptr(),
    );
    gf2x_add(
        (2i32 as u32).wrapping_mul(bih) as i32,
        w1.as_mut_ptr(),
        (2i32 as u32).wrapping_mul(bih) as i32,
        w1.as_ptr(),
        (2i32 as u32).wrapping_mul(bih) as i32,
        w0.as_ptr(),
    );
    gf2x_add_asymm(
        w3.len() as i32,
        w3.as_mut_ptr(),
        w3.len() as i32,
        w3.as_ptr(),
        (2i32 as u32).wrapping_mul(bih) as i32,
        w1.as_ptr(),
    );
    right_bit_shift_n(
        w3.len() as i32,
        w3.as_mut_ptr(),
        1i32,
    );
    gf2x_exact_div_x_plus_one(
        w3.len() as i32,
        w3.as_mut_ptr(),
    );
    gf2x_add(
        (2i32 as u32).wrapping_mul(bih) as i32,
        w1.as_mut_ptr(),
        (2i32 as u32).wrapping_mul(bih) as i32,
        w1.as_ptr(),
        (2i32 as u32).wrapping_mul(bih) as i32,
        w4.as_ptr(),
    );
    let vla_17 = (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) as usize;
    let mut w1_final: Vec<DIGIT> = ::std::vec::from_elem(0, vla_17);
    gf2x_add_asymm(
        (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) as i32,
        w1_final.as_mut_ptr(),
        w2.len() as i32,
        w2.as_ptr(),
        (2i32 as u32).wrapping_mul(bih) as i32,
        w1.as_ptr(),
    );
    gf2x_add(
        w2.len() as i32,
        w2.as_mut_ptr(),
        w2.len() as i32,
        w2.as_ptr(),
        w3.len() as i32,
        w3.as_ptr(),
    );
    // Result recombination starts here
    memset(Res as *mut libc::c_void, 0i32, (nr * 8i32) as u64);
    /* optimization: topmost slack digits should be computed, and not addedd,
     * zeroization can be avoided altogether with a proper merge of the
     * results */
    let mut leastSignifDigitIdx: i32 = nr - 1i32;
    let mut i_0: i32 = 0i32;
    while (i_0 as u32) < (2i32 as u32).wrapping_mul(bih) {
        let ref mut fresh4 = *Res.offset((leastSignifDigitIdx - i_0) as isize);
        *fresh4 ^= *w0.as_mut_ptr().offset(
            (2i32 as u32)
                .wrapping_mul(bih)
                .wrapping_sub(1i32 as u32)
                .wrapping_sub(i_0 as u32) as isize,
        );
        i_0 += 1
    }
    leastSignifDigitIdx = (leastSignifDigitIdx as u32).wrapping_sub(bih) as i32 as i32;
    let mut i_1: i32 = 0i32;
    while (i_1 as u32) < (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) {
        let ref mut fresh5 = *Res.offset((leastSignifDigitIdx - i_1) as isize);
        *fresh5 ^= *w1_final.as_mut_ptr().offset(
            (2i32 as u32)
                .wrapping_mul(bih)
                .wrapping_add(2i32 as u32)
                .wrapping_sub(1i32 as u32)
                .wrapping_sub(i_1 as u32) as isize,
        );
        i_1 += 1
    }
    leastSignifDigitIdx = (leastSignifDigitIdx as u32).wrapping_sub(bih) as i32 as i32;
    let mut i_2: i32 = 0i32;
    while (i_2 as u32) < (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) {
        let ref mut fresh6 = *Res.offset((leastSignifDigitIdx - i_2) as isize);
        *fresh6 ^= *w2.as_mut_ptr().offset(
            (2i32 as u32)
                .wrapping_mul(bih)
                .wrapping_add(2i32 as u32)
                .wrapping_sub(1i32 as u32)
                .wrapping_sub(i_2 as u32) as isize,
        );
        i_2 += 1
    }
    leastSignifDigitIdx = (leastSignifDigitIdx as u32).wrapping_sub(bih) as i32 as i32;
    let mut i_3: i32 = 0i32;
    while (i_3 as u32) < (2i32 as u32).wrapping_mul(bih).wrapping_add(2i32 as u32) {
        let ref mut fresh7 = *Res.offset((leastSignifDigitIdx - i_3) as isize);
        *fresh7 ^= *w3.as_mut_ptr().offset(
            (2i32 as u32)
                .wrapping_mul(bih)
                .wrapping_add(2i32 as u32)
                .wrapping_sub(1i32 as u32)
                .wrapping_sub(i_3 as u32) as isize,
        );
        i_3 += 1
    }
    leastSignifDigitIdx = (leastSignifDigitIdx as u32).wrapping_sub(bih) as i32 as i32;
    let mut i_4: i32 = 0i32;
    while (i_4 as u32) < (2i32 as u32).wrapping_mul(bih) && leastSignifDigitIdx - i_4 >= 0i32 {
        let ref mut fresh8 = *Res.offset((leastSignifDigitIdx - i_4) as isize);
        *fresh8 ^= *w4.as_mut_ptr().offset(
            (2i32 as u32)
                .wrapping_mul(bih)
                .wrapping_sub(1i32 as u32)
                .wrapping_sub(i_4 as u32) as isize,
        );
        i_4 += 1
    }
}
