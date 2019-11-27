use crate::consts::*;
use crate::types::*;

extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
}

pub fn gf2x_copy(mut dest: &mut [DIGIT], input: &[DIGIT]) {
    for i in 0..NUM_DIGITS_GF2X_ELEMENT {
        dest[i] = input[i];
    }
}

pub fn population_count(upc: &[DIGIT]) -> usize {
    let mut sum: usize = 0;
    for x in upc {
        sum += x.count_ones() as usize;
    }
    return sum;
}

pub fn gf2x_get_coeff(poly: &[DIGIT], exponent: u32) -> DIGIT {
    let straightIdx = (NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_b - 1) - exponent as usize;
    let digitIdx = straightIdx / DIGIT_SIZE_b;
    let inDigitIdx = straightIdx % DIGIT_SIZE_b;
    let mask = 1 as DIGIT;
    return (poly[digitIdx] >> (DIGIT_SIZE_b - 1 - inDigitIdx)) & mask;
}

pub fn gf2x_toggle_coeff(poly: &mut [DIGIT], exponent: u32) {
    let straightIdx = (NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_b - 1) - exponent as usize;
    let digitIdx = straightIdx / DIGIT_SIZE_b;
    let inDigitIdx = straightIdx % DIGIT_SIZE_b;
    let mask: DIGIT = (1 as DIGIT) << (DIGIT_SIZE_b - 1 - inDigitIdx);
    poly[digitIdx] ^= mask;
}

pub fn gf2x_mod_add_3(Res: &mut [DIGIT], A: &[DIGIT], B: &[DIGIT]) {
    assert_eq!(Res.len(), NUM_DIGITS_GF2X_ELEMENT);
    assert_eq!(A.len(), NUM_DIGITS_GF2X_ELEMENT);
    assert_eq!(B.len(), NUM_DIGITS_GF2X_ELEMENT);
    gf2x_add_3(Res, A, B);
}

pub fn gf2x_mod_add_2(Res: &mut [DIGIT], A: &[DIGIT]) {
    assert_eq!(Res.len(), NUM_DIGITS_GF2X_ELEMENT);
    assert_eq!(A.len(), NUM_DIGITS_GF2X_ELEMENT);
    gf2x_add_2(Res, A);
}

pub fn gf2x_add_3(Res: &mut [DIGIT], A: &[DIGIT], B: &[DIGIT]) {
    assert_eq!(Res.len(), A.len());
    assert_eq!(Res.len(), B.len());

    for i in 0..Res.len() {
        Res[i] = A[i] ^ B[i];
    }
}

pub fn gf2x_add_2(Res: &mut [DIGIT], A: &[DIGIT]) {
    assert_eq!(Res.len(), A.len());

    for i in 0..Res.len() {
        Res[i] ^= A[i];
    }
}

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
unsafe fn gf2x_add(
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
    let straightIdx = (NUM_DIGITS_GF2X_ELEMENT * DIGIT_SIZE_b - 1) - exponent;
    let digitIdx = straightIdx / DIGIT_SIZE_b;
    let inDigitIdx = straightIdx % DIGIT_SIZE_b;

    /* clear given coefficient */
    let mask = !((1 as DIGIT) << (DIGIT_SIZE_b - 1 - inDigitIdx));
    poly[digitIdx] = poly[digitIdx] & mask;
    poly[digitIdx] = poly[digitIdx] | ((value & (1 as DIGIT)) << (DIGIT_SIZE_b - 1 - inDigitIdx));
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

    for i in 0..nr {
        *Res.offset(i as isize) = 0;
    }
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

fn gf2x_add_asymm_3(Res: &mut [DIGIT], A: &[DIGIT], B: &[DIGIT]) {
    assert!(Res.len() >= A.len());
    assert!(A.len() >= B.len());

    let delta = A.len() - B.len();
    Res[0..delta].copy_from_slice(&A[0..delta]);
    for i in 0..B.len() {
        Res[i + delta] = A[i + delta] ^ B[i];
    }
}

fn gf2x_add_asymm_2(Res: &mut [DIGIT], A: &[DIGIT]) {
    assert!(Res.len() >= A.len());

    let delta = Res.len() - A.len();
    for i in 0..A.len() {
        Res[i + delta] ^= A[i];
    }
}

/*----------------------------------------------------------------------------*/
/* PRE: MAX ALLOWED ROTATION AMOUNT : DIGIT_SIZE_b */

pub fn right_bit_shift_n(input: &mut [DIGIT], amount: usize) {
    assert!(amount < DIGIT_SIZE_b);
    if amount == 0 {
        return;
    }
    let mask: DIGIT = ((1 as DIGIT) << amount) - 1;
    for j in (1..input.len()).rev() {
        input[j] >>= amount;
        input[j] |= (input[j - 1] & mask) << (DIGIT_SIZE_b - amount);
    }
    input[0] >>= amount;
}

fn left_bit_shift_n(input: &mut [DIGIT], amount: usize) {
    assert!(amount < DIGIT_SIZE_b);
    if amount == 0 {
        return;
    }
    let mask: DIGIT = !((1 as DIGIT) << (DIGIT_SIZE_b - amount - 1));
    for j in 0..(input.len() - 1) {
        input[j] <<= amount;
        input[j] |= (input[j+1] & mask) >> (DIGIT_SIZE_b - amount);
    }
    input[input.len() - 1] <<= amount;
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
        let bih: u32 = (na / 2i32) as u32;
        let bihu = bih as usize;
        let mut middle: Vec<DIGIT> = vec![0; 2 * bihu];
        let mut sumA: Vec<DIGIT> = vec![0; bihu];
        let mut sumB: Vec<DIGIT> = vec![0; bihu];
        gf2x_add(
            sumA.len() as i32,
            sumA.as_mut_ptr(),
            bih as i32,
            A,
            bih as i32,
            A.offset(bih as isize),
        );
        gf2x_add(
            sumB.len() as i32,
            sumB.as_mut_ptr(),
            bih as i32,
            B,
            bih as i32,
            B.offset(bih as isize),
        );
        gf2x_mul_Kar(
            middle.len() as i32,
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
            middle.len() as i32,
            middle.as_mut_ptr(),
            middle.len() as i32,
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
            middle.len() as i32,
            middle.as_mut_ptr(),
            middle.len() as i32,
            middle.as_ptr(),
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res as *const DIGIT,
        );
        gf2x_add(
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset(bih as isize),
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset(bih as isize) as *const DIGIT,
            middle.len() as i32,
            middle.as_ptr(),
        );
    } else {
        let bih: u32 = (na / 2i32 + 1i32) as u32;
        let bihu = bih as usize;
        let mut middle: Vec<DIGIT> = vec![0; bihu * 2];
        let mut sumA: Vec<DIGIT> = vec![0; bihu];
        let mut sumB: Vec<DIGIT> = vec![0; bihu];
        gf2x_add_asymm(
            sumA.len() as i32,
            sumA.as_mut_ptr(),
            bih as i32,
            A.offset(bih as isize).offset(-1),
            bih.wrapping_sub(1i32 as u32) as i32,
            A,
        );
        gf2x_add_asymm(
            bih as i32,
            sumB.as_mut_ptr(),
            bih as i32,
            B.offset(bih as isize).offset(-1),
            bih.wrapping_sub(1i32 as u32) as i32,
            B,
        );
        gf2x_mul_Kar(
            middle.len() as i32,
            middle.as_mut_ptr(),
            sumA.len() as i32,
            sumA.as_ptr(),
            sumB.len() as i32,
            sumB.as_ptr(),
        );
        gf2x_mul_Kar(
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset((2i32 as u32).wrapping_mul(bih.wrapping_sub(1i32 as u32)) as isize),
            bih as i32,
            A.offset(bih as isize).offset(-1),
            bih as i32,
            B.offset(bih as isize).offset(-1),
        );
        gf2x_add(
            middle.len() as i32,
            middle.as_mut_ptr(),
            middle.len() as i32,
            middle.as_ptr(),
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset((2i32 as u32).wrapping_mul(bih.wrapping_sub(1i32 as u32)) as isize)
                as *const DIGIT,
        );
        gf2x_mul_Kar(
            (2i32 as u32).wrapping_mul(bih.wrapping_sub(1i32 as u32)) as i32,
            Res,
            bih.wrapping_sub(1i32 as u32) as i32,
            A,
            bih.wrapping_sub(1i32 as u32) as i32,
            B,
        );
        gf2x_add_asymm(
            middle.len() as i32,
            middle.as_mut_ptr(),
            middle.len() as i32,
            middle.as_ptr(),
            (2i32 as u32).wrapping_mul(bih.wrapping_sub(1i32 as u32)) as i32,
            Res as *const DIGIT,
        );
        gf2x_add(
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset(bih as isize).offset(-2),
            (2i32 as u32).wrapping_mul(bih) as i32,
            Res.offset(bih as isize).offset(-2) as *const DIGIT,
            middle.len() as i32,
            middle.as_ptr(),
        );
    };
}
// end gf2x_add
/*----------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
/* Toom-Cook 3 algorithm as reported in
 * Marco Bodrato: "Towards Optimal Toom-Cook Multiplication for Univariate and
 * Multivariate Polynomials in Characteristic 2 and 0". WAIFI 2007: 116-133   */

pub unsafe fn gf2x_mul_TC3(Res: &mut [DIGIT], A: &[DIGIT], B: &[DIGIT]) {
    let nr = Res.len() as i32;
    let Res = Res.as_mut_ptr();

    if A.len() < 50 || B.len() < 50 {
        /* fall back to schoolbook */
        gf2x_mul_Kar(nr, Res, A.len() as i32, A.as_ptr(), B.len() as i32, B.as_ptr());
        return;
    }

    let bih = if A.len() % 3 == 0 {
        (A.len() / 3)
    } else {
        (A.len() / 3 + 1)
    };
    let mut u2: Vec<DIGIT> = vec![0; bih];
    let mut v2: Vec<DIGIT> = vec![0; bih];

    let leading_slack = (3 - A.len() % 3) % 3;
    for i in leading_slack..bih {
        u2[i] = A[(i - leading_slack)];
        v2[i] = B[(i - leading_slack)];
    }

    let u1 = &A[bih - leading_slack..2*bih - leading_slack];
    let u0 = &A[2*bih - leading_slack..3*bih - leading_slack];

    let v1 = &B[bih - leading_slack..2*bih - leading_slack];
    let v0 = &B[2*bih - leading_slack..3*bih - leading_slack];

    let mut sum_u: Vec<DIGIT> = vec![0; bih];
    gf2x_add_3(&mut sum_u, u0, u1);
    gf2x_add_2(&mut sum_u, &u2);

    let mut sum_v: Vec<DIGIT> = vec![0; bih];
    gf2x_add_3(&mut sum_v, v0, v1);
    gf2x_add_2(&mut sum_v, &v2);
    let mut w1: Vec<DIGIT> = vec![0; 2 * bih];
    gf2x_mul_TC3(&mut w1, &sum_u, &sum_v);
    let mut u2_x2: Vec<DIGIT> = vec![0; 1 + bih];
    u2_x2[1..1 + bih].copy_from_slice(&u2);
    left_bit_shift_n(&mut u2_x2, 2);
    let mut u1_x: Vec<DIGIT> = vec![0; bih + 1];
    u1_x[1..1 + bih].copy_from_slice(u1);
    left_bit_shift_n(&mut u1_x, 1);
    let mut u1_x1_u2_x2: Vec<DIGIT> = vec![0; bih + 1];
    gf2x_add_3(&mut u1_x1_u2_x2, &u1_x, &u2_x2);
    let mut temp_u_components: Vec<DIGIT> = vec![0; bih + 1];
    gf2x_add_asymm_3(&mut temp_u_components, &u1_x1_u2_x2, &sum_u);

    let mut v2_x2: Vec<DIGIT> = vec![0; bih + 1];
    v2_x2[1..bih+1].copy_from_slice(&v2);
    left_bit_shift_n(&mut v2_x2, 2);
    let mut v1_x: Vec<DIGIT> = vec![0; bih + 1];
    v1_x[1..1+bih].copy_from_slice(v1);
    left_bit_shift_n(&mut v1_x, 1);
    let mut v1_x1_v2_x2: Vec<DIGIT> = vec![0; bih + 1];
    gf2x_add_3(&mut v1_x1_v2_x2, &v1_x, &v2_x2);

    let mut temp_v_components: Vec<DIGIT> = vec![0; bih + 1];
    gf2x_add_asymm_3(&mut temp_v_components, &v1_x1_v2_x2, &sum_v);

    let mut w3: Vec<DIGIT> = vec![0; 2 * bih + 2];
    gf2x_mul_TC3(&mut w3, &temp_u_components, &temp_v_components);
    gf2x_add_asymm_2(&mut u1_x1_u2_x2, u0);
    gf2x_add_asymm_2(&mut v1_x1_v2_x2, v0);

    let mut w2: Vec<DIGIT> = vec![0; 2 * bih + 2];
    gf2x_mul_TC3(&mut w2, &u1_x1_u2_x2, &v1_x1_v2_x2);
    let mut w4: Vec<DIGIT> = vec![0; 2 * bih];
    gf2x_mul_TC3(&mut w4, &u2, &v2);
    let mut w0: Vec<DIGIT> = vec![0; 2 * bih];
    gf2x_mul_TC3(&mut w0, u0, v0);

    // Interpolation starts
    gf2x_add_2(&mut w3, &w2);
    gf2x_add_asymm_2(&mut w2, &w0);
    right_bit_shift_n(&mut w2, 1);
    gf2x_add_2(&mut w2, &w3);
    // w2 + (w4 * x^3+1) = w2 + w4 + w4 << 3
    let mut w4_x3_plus_1: Vec<DIGIT> = vec![0; 2*bih+1];
    w4_x3_plus_1[1..1 + 2 * bih].copy_from_slice(&w4);

    left_bit_shift_n(&mut w4_x3_plus_1, 3);
    gf2x_add_asymm_2(&mut w2, &w4);
    gf2x_add_asymm_2(&mut w2, &w4_x3_plus_1);
    gf2x_exact_div_x_plus_one(
        w2.len() as i32,
        w2.as_mut_ptr(),
    );
    gf2x_add_2(&mut w1, &w0);
    gf2x_add_asymm_2(&mut w3, &w1);
    right_bit_shift_n(&mut w3, 1);
    gf2x_exact_div_x_plus_one(w3.len() as i32, w3.as_mut_ptr());
    gf2x_add_2(&mut w1, &w4);
    let mut w1_final: Vec<DIGIT> = vec![0; 2*bih + 2];
    gf2x_add_asymm_3(&mut w1_final, &w2, &w1);
    gf2x_add_2(&mut w2, &w3);
    // Result recombination starts here

    for i in 0..nr {
        *Res.offset(i as isize) = 0;
    }
    /* optimization: topmost slack digits should be computed, and not addedd,
     * zeroization can be avoided altogether with a proper merge of the
     * results */
    let mut leastSignifDigitIdx: i32 = nr - 1i32;
    let mut i_0: i32 = 0i32;

    let bih = bih as u32;
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
