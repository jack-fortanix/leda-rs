use crate::consts::*;
use crate::crypto::seedexpander_from_trng;
use crate::dfr_test::DFR_test;
use crate::gf2x_arith::*;
use crate::gf2x_arith_mod_xPplusOne::*;
use crate::types::*;
use crate::H_Q_matrices_generation::*;

pub unsafe fn key_gen_mceliece(
    seed: &[u8],
    pk: &mut publicKeyMcEliece_t,
    sk: &mut privateKeyMcEliece_t,
) {
    sk.prng_seed.copy_from_slice(seed);

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
    let mut is_L_full: i32 = 0;
    let mut isDFRok: i32 = 0;
    sk.rejections = 0i32 as u8;
    loop {
        generateHPosOnes(HPosOnes.as_mut_ptr(), &mut keys_expander);
        generateQPosOnes(QPosOnes.as_mut_ptr(), &mut keys_expander);
        let mut i: i32 = 0i32;
        while i < 2i32 {
            let mut j: i32 = 0i32;
            while j < 11i32 * 11i32 {
                LPosOnes[i as usize][j as usize] = crate::consts::P as i32 as u32;
                j += 1
            }
            i += 1
        }
        let mut auxPosOnes: [u32; 121] = [0; 121];
        let mut processedQOnes: [u8; 2] = [0i32 as u8, 0];
        let mut colQ: i32 = 0i32;
        while colQ < 2i32 {
            let mut i_0: i32 = 0i32;
            while i_0 < 2i32 {
                gf2x_mod_mul_sparse(
                    11i32 * 11i32,
                    auxPosOnes.as_mut_ptr(),
                    11i32,
                    HPosOnes[i_0 as usize].as_mut_ptr() as *const u32,
                    qBlockWeights[i_0 as usize][colQ as usize] as i32,
                    QPosOnes[i_0 as usize]
                        .as_mut_ptr()
                        .offset(processedQOnes[i_0 as usize] as i32 as isize)
                        as *const u32,
                );
                gf2x_mod_add_sparse(
                    11 * 11,
                    LPosOnes[colQ as usize].as_mut_ptr(),
                    11 * 11,
                    LPosOnes[colQ as usize].as_mut_ptr(),
                    11 * 11,
                    auxPosOnes.as_mut_ptr(),
                );
                processedQOnes[i_0 as usize] = (processedQOnes[i_0 as usize] as i32
                    + qBlockWeights[i_0 as usize][colQ as usize] as i32)
                    as u8;
                i_0 += 1
            }
            colQ += 1
        }
        is_L_full = 1i32;
        let mut i_1: i32 = 0i32;
        while i_1 < 2i32 {
            is_L_full = (is_L_full != 0
                && LPosOnes[i_1 as usize][(11 * 11 - 1i32) as usize]
                    != crate::consts::P as i32 as u32) as i32;
            i_1 += 1
        }
        sk.rejections = (sk.rejections as i32 + 1i32) as u8;
        if is_L_full != 0 {
            isDFRok = DFR_test(LPosOnes.as_mut_ptr(), &mut sk.secondIterThreshold)
        }
        if !(is_L_full == 0 || isDFRok == 0) {
            break;
        }
    }
    sk.rejections = (sk.rejections as i32 - 1i32) as u8;
    let mut Ln0dense: [DIGIT; 905] = [0; 905];
    let mut j_0: i32 = 0i32;
    while j_0 < 11 * 11 {
        if LPosOnes[(2i32 - 1i32) as usize][j_0 as usize] != crate::consts::P as i32 as u32 {
            gf2x_set_coeff(
                Ln0dense.as_mut_ptr(),
                LPosOnes[(2i32 - 1i32) as usize][j_0 as usize],
                1i32 as DIGIT,
            );
        }
        j_0 += 1
    }
    let mut Ln0Inv: [DIGIT; 905] = [0; 905];
    gf2x_mod_inverse(Ln0Inv.as_mut_ptr(), Ln0dense.as_mut_ptr() as *const DIGIT);
    gf2x_mod_mul_dense_to_sparse(
        pk.Mtr.as_mut_ptr(),
        Ln0Inv.as_mut_ptr() as *const DIGIT,
        LPosOnes[0 as usize].as_mut_ptr() as *const u32,
        (11 * 11) as u32,
    );
    gf2x_transpose_in_place(pk.Mtr.as_mut_ptr());
}
