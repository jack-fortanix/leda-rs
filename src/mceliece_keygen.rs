use crate::consts::*;
use crate::crypto::seedexpander_from_trng;
use crate::dfr_test::DFR_test;
use crate::gf2x_arith::*;
use crate::gf2x_arith_mod_xPplusOne::*;
use crate::types::*;
use crate::H_Q_matrices_generation::*;

pub unsafe fn key_gen_mceliece(
    seed: &[u8],
    pk: &mut LedaPublicKey,
    sk: &mut LedaPrivateKey) {
    sk.prng_seed.copy_from_slice(seed);
    sk.rejections = 0;

    let P32 = P as u32;

    let mut keys_expander = seedexpander_from_trng(&sk.prng_seed).unwrap();
    // sequence of N0 circ block matrices (p x p): Hi
    let mut HPosOnes: [[u32; 11]; 2] = [[0; 11]; 2];
    /* Sparse representation of the transposed circulant matrix H,
    with weight DV. Each index contains the position of a '1' digit in the
    corresponding Htr block */
    /* Sparse representation of the matrix (Q).
    A matrix containing the positions of the ones in the circulant
    blocks of Q. Each row contains the position of the
    ones of all the blocks of a row of Q as exponent+
    P*block_position */
    let mut QPosOnes: [[u32; 11]; 2] = [[0; 11]; 2];
    /*Rejection-sample for a full L*/
    let mut LPosOnes: [[u32; 121]; 2] = [[0; 121]; 2];
    loop {
        generateHPosOnes(&mut HPosOnes, &mut keys_expander);
        generateQPosOnes(&mut QPosOnes, &mut keys_expander);
        for i in 0..2 {
            for j in 0..(11*11) {
                LPosOnes[i][j] = P32;
            }
        }
        let mut auxPosOnes: [u32; 121] = [0; 121];
        let mut processedQOnes: [usize; 2] = [0, 0];
        for colQ in 0..N0 {
            for i_0 in 0..N0 {
                gf2x_mod_mul_sparse(&mut auxPosOnes,
                                    &HPosOnes[i_0],
                                    &QPosOnes[i_0][processedQOnes[i_0]..(processedQOnes[i_0]+qBlockWeights[i_0][colQ] as usize)]);
                gf2x_mod_add_sparse(
                    11 * 11,
                    LPosOnes[colQ as usize].as_mut_ptr(),
                    11 * 11,
                    LPosOnes[colQ as usize].as_mut_ptr(),
                    11 * 11,
                    auxPosOnes.as_mut_ptr(),
                );
                processedQOnes[i_0] += qBlockWeights[i_0][colQ as usize] as usize;
            }
        }
        let mut is_L_full = 1i32;
        let mut i_1: i32 = 0i32;
        while i_1 < 2i32 {
            is_L_full = (is_L_full != 0
                && LPosOnes[i_1 as usize][(11 * 11 - 1i32) as usize] != P32) as i32;
            i_1 += 1
        }
        let mut isDFRok: i32 = 0;
        if is_L_full != 0 {
            isDFRok = DFR_test(LPosOnes.as_mut_ptr(), &mut sk.secondIterThreshold)
        }
        if !(is_L_full == 0 || isDFRok == 0) {
            break;
        }
        sk.rejections += 1;
    }
    let mut Ln0dense: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    let mut j_0: i32 = 0i32;
    while j_0 < 11 * 11 {
        if LPosOnes[(2i32 - 1i32) as usize][j_0 as usize] != P32 {
            gf2x_set_coeff(
                Ln0dense.as_mut_ptr(),
                LPosOnes[(2i32 - 1i32) as usize][j_0 as usize],
                1i32 as DIGIT,
            );
        }
        j_0 += 1
    }
    let mut Ln0Inv: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    gf2x_mod_inverse(Ln0Inv.as_mut_ptr(), Ln0dense.as_mut_ptr() as *const DIGIT);
    gf2x_mod_mul_dense_to_sparse(
        pk.Mtr.as_mut_ptr(),
        Ln0Inv.as_mut_ptr() as *const DIGIT,
        LPosOnes[0 as usize].as_mut_ptr() as *const u32,
        (11 * 11) as u32,
    );
    gf2x_transpose_in_place(pk.Mtr.as_mut_ptr());
}
