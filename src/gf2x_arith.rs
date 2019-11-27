use crate::consts::*;
use crate::types::*;

pub fn gf2x_copy(dest: &mut [DIGIT], input: &[DIGIT]) {
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
    let straightIdx = (NUM_DIGITS_GF2X_ELEMENT * DIGIT_SIZE_b - 1) - exponent as usize;
    let digitIdx = straightIdx / DIGIT_SIZE_b;
    let inDigitIdx = straightIdx % DIGIT_SIZE_b;
    let mask = 1 as DIGIT;
    return (poly[digitIdx] >> (DIGIT_SIZE_b - 1 - inDigitIdx)) & mask;
}

pub fn gf2x_toggle_coeff(poly: &mut [DIGIT], exponent: u32) {
    let straightIdx = (NUM_DIGITS_GF2X_ELEMENT * DIGIT_SIZE_b - 1) - exponent as usize;
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

fn gf2x_mul_comb(Res: &mut [DIGIT], A: &[DIGIT], B: &[DIGIT]) {
    for i in 0..Res.len() {
        Res[i] = 0;
    }

    for k in (1..DIGIT_SIZE_b).rev() {
        for i in (0..A.len()).rev() {
            if A[i] & (1 as DIGIT) << k != 0 {
                for j in (0..B.len()).rev() {
                    Res[i+j+1] ^= B[j];
                }
            }
        }
        let mut u = Res[A.len() + B.len() - 1];
        Res[A.len() + B.len() - 1] = u << 1;

        for j in 1..(A.len() + B.len()) {
            let h = u >> (DIGIT_SIZE_b - 1);
            u = Res[A.len() + B.len() - 1 - j];
            Res[A.len() + B.len() - 1 - j] = h ^ u << 1;
        }
    }
    for i in (0..A.len()).rev() {
        if A[i] & (1 as DIGIT) != 0 {
            for j in (0..B.len()).rev() {
                Res[i + j + 1] ^= B[j];
            }
        }
    }
}

/* allows the second operand to be shorter than the first */
/* the result should be as large as the first operand*/

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
        input[j] |= (input[j + 1] & mask) >> (DIGIT_SIZE_b - amount);
    }
    input[input.len() - 1] <<= amount;
}

fn gf2x_exact_div_x_plus_one(A: &mut [DIGIT]) {
    let mut t: DIGIT = 0;

    for i in (0..A.len()).rev() {
        t ^= A[i];
        let mut j = 1;
        while j <= DIGIT_SIZE_b / 2 {
            t ^= t << j;
            j = j * 2;
        }
        A[i] = t;
        t >>= DIGIT_SIZE_b - 1;
    }
}

fn gf2x_mul_Kar(Res: &mut [DIGIT], A: &[DIGIT], B: &[DIGIT]) {
    if A.len() % 2 != 0 || A.len() < 9 || B.len() < 9 {
        /* fall back to schoolbook */
        gf2x_mul_comb(Res, A, B);
        return;
    }

    let half = A.len() / 2;
    let mut middle: Vec<DIGIT> = vec![0; 2 * half];
    let mut sumA: Vec<DIGIT> = vec![0; half];
    let mut sumB: Vec<DIGIT> = vec![0; half];
    gf2x_add_3(&mut sumA, &A[0..half], &A[half..2 * half]);
    gf2x_add_3(&mut sumB, &B[0..half], &B[half..2 * half]);
    gf2x_mul_Kar(&mut middle, &sumA, &sumB);
    gf2x_mul_Kar(
        &mut Res[2 * half..4 * half],
        &A[half..2 * half],
        &B[half..2 * half],
    );
    gf2x_add_2(&mut middle, &Res[2 * half..4 * half]);
    gf2x_mul_Kar(&mut Res[0..2 * half], &A[0..half], &B[0..half]);
    gf2x_add_2(&mut middle, &Res[0..2 * half]);
    gf2x_add_2(&mut Res[half..3 * half], &middle);
}

/*----------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
/* Toom-Cook 3 algorithm as reported in
 * Marco Bodrato: "Towards Optimal Toom-Cook Multiplication for Univariate and
 * Multivariate Polynomials in Characteristic 2 and 0". WAIFI 2007: 116-133   */

pub fn gf2x_mul_TC3(Res: &mut [DIGIT], A: &[DIGIT], B: &[DIGIT]) {
    if A.len() < 50 || B.len() < 50 {
        /* fall back to Karatsuba */
        gf2x_mul_Kar(Res, A, B);
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

    let u1 = &A[bih - leading_slack..2 * bih - leading_slack];
    let u0 = &A[2 * bih - leading_slack..3 * bih - leading_slack];

    let v1 = &B[bih - leading_slack..2 * bih - leading_slack];
    let v0 = &B[2 * bih - leading_slack..3 * bih - leading_slack];

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
    v2_x2[1..bih + 1].copy_from_slice(&v2);
    left_bit_shift_n(&mut v2_x2, 2);
    let mut v1_x: Vec<DIGIT> = vec![0; bih + 1];
    v1_x[1..1 + bih].copy_from_slice(v1);
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
    let mut w4_x3_plus_1: Vec<DIGIT> = vec![0; 2 * bih + 1];
    w4_x3_plus_1[1..1 + 2 * bih].copy_from_slice(&w4);

    left_bit_shift_n(&mut w4_x3_plus_1, 3);
    gf2x_add_asymm_2(&mut w2, &w4);
    gf2x_add_asymm_2(&mut w2, &w4_x3_plus_1);
    gf2x_exact_div_x_plus_one(&mut w2);
    gf2x_add_2(&mut w1, &w0);
    gf2x_add_asymm_2(&mut w3, &w1);
    right_bit_shift_n(&mut w3, 1);
    gf2x_exact_div_x_plus_one(&mut w3);
    gf2x_add_2(&mut w1, &w4);
    let mut w1_final: Vec<DIGIT> = vec![0; 2 * bih + 2];
    gf2x_add_asymm_3(&mut w1_final, &w2, &w1);
    gf2x_add_2(&mut w2, &w3);
    // Result recombination starts here

    for i in 0..Res.len() {
        Res[i] = 0;
    }

    let mut leastSignifDigitIdx = Res.len() - 1;
    for i in 0..2 * bih {
        Res[leastSignifDigitIdx - i] ^= w0[2 * bih - 1 - i];
    }
    leastSignifDigitIdx -= bih;
    for i in 0..2 * bih + 2 {
        Res[leastSignifDigitIdx - i] ^= w1_final[2 * bih + 2 - 1 - i];
    }
    leastSignifDigitIdx -= bih;
    for i in 0..2 * bih + 2 {
        Res[leastSignifDigitIdx - i] ^= w2[2 * bih + 2 - 1 - i];
    }
    leastSignifDigitIdx -= bih;
    for i in 0..2 * bih + 2 {
        Res[leastSignifDigitIdx - i] ^= w3[2 * bih + 2 - 1 - i];
    }
    leastSignifDigitIdx -= bih;
    for i in 0..2 * bih {
        if i > leastSignifDigitIdx {
            break;
        }
        Res[leastSignifDigitIdx - i] ^= w4[2 * bih - 1 - i];
    }
}
