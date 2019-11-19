
use crate::types::*;
use crate::consts::*;

extern "C" {
    #[no_mangle]
    fn randombytes(x: *mut u8, xlen: u64)
     -> i32;
    #[no_mangle]
    fn seedexpander_from_trng(ctx: *mut AES_XOF_struct,
                              trng_entropy: *const u8);
    #[no_mangle]
    fn gf2x_mod_inverse(out: *mut DIGIT, in_0: *const DIGIT) -> i32;
    #[no_mangle]
    fn gf2x_transpose_in_place(A: *mut DIGIT);
    #[no_mangle]
    fn gf2x_mod_add_sparse(sizeR: i32, Res: *mut u32,
                           sizeA: i32, A: *mut u32,
                           sizeB: i32, B: *mut u32);
    #[no_mangle]
    fn gf2x_mod_mul_sparse(sizeR: i32, Res: *mut u32,
                           sizeA: i32, A: *const u32,
                           sizeB: i32, B: *const u32);
    #[no_mangle]
    fn gf2x_mod_mul_dense_to_sparse(Res: *mut DIGIT, dense: *const DIGIT,
                                    sparse: *const u32,
                                    nPos: u32);

    // HQ:
    #[no_mangle]
    fn generateHPosOnes(HPosOnes: *mut [u32; 11],
                        niederreiter_keys_expander: *mut AES_XOF_struct);
    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    fn generateQPosOnes(QPosOnes: *mut [u32; 11],
                        keys_expander: *mut AES_XOF_struct);
    #[no_mangle]
    fn DFR_test(LSparse: *mut [u32; 121],
                secondIterThreshold: *mut u8) -> i32;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64)
     -> *mut libc::c_void;
}

#[inline]
unsafe extern "C" fn gf2x_set_coeff(mut poly: *mut DIGIT,
                                    exponent: u32,
                                    mut value: DIGIT) {
    let mut straightIdx: i32 =
        (((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * (8i32 << 3i32)
              - 1i32) as u32).wrapping_sub(exponent) as i32;
    let mut digitIdx: i32 = straightIdx / (8i32 << 3i32);
    let mut inDigitIdx: u32 =
        (straightIdx % (8i32 << 3i32)) as u32;
    let mut mask: DIGIT =
        !((1i32 as DIGIT) <<
              (((8i32 << 3i32) - 1i32) as
                   u32).wrapping_sub(inDigitIdx));
    *poly.offset(digitIdx as isize) = *poly.offset(digitIdx as isize) & mask;
    *poly.offset(digitIdx as isize) =
        *poly.offset(digitIdx as isize) |
            (value & 1i32 as DIGIT) <<
                (((8i32 << 3i32) - 1i32) as
                     u32).wrapping_sub(inDigitIdx);
}
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe extern "C" fn key_gen_mceliece(pk: *mut publicKeyMcEliece_t,
                                          sk: *mut privateKeyMcEliece_t) {
    let mut keys_expander: AES_XOF_struct =
        AES_XOF_struct{buffer: [0; 16],
                       buffer_pos: 0,
                       length_remaining: 0,
                       key: [0; 32],
                       ctr: [0; 16],};
    memset(&mut keys_expander as *mut AES_XOF_struct as *mut libc::c_void,
           0i32, ::std::mem::size_of::<AES_XOF_struct>() as u64);
    randombytes((*sk).prng_seed.as_mut_ptr(), 32i32 as u64);
    /*
    dump(b"prng_seed\x00" as *const u8 as *const libc::c_char,
         (*sk).prng_seed.as_mut_ptr(), 32i32);
*/
    seedexpander_from_trng(&mut keys_expander, (*sk).prng_seed.as_mut_ptr());
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
    (*sk).rejections = 0i32 as u8;
    loop  {
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
        let mut processedQOnes: [u8; 2] =
            [0i32 as u8, 0];
        let mut colQ: i32 = 0i32;
        while colQ < 2i32 {
            let mut i_0: i32 = 0i32;
            while i_0 < 2i32 {
                gf2x_mod_mul_sparse(11i32 * 11i32, auxPosOnes.as_mut_ptr(),
                                    11i32,
                                    HPosOnes[i_0 as usize].as_mut_ptr() as
                                        *const u32,
                                    qBlockWeights[i_0 as usize][colQ as usize]
                                        as i32,
                                    QPosOnes[i_0 as
                                                 usize].as_mut_ptr().offset(processedQOnes[i_0
                                                                                               as
                                                                                               usize]
                                                                                as
                                                                                i32
                                                                                as
                                                                                isize)
                                        as *const u32);
                gf2x_mod_add_sparse(11i32 * 11i32,
                                    LPosOnes[colQ as usize].as_mut_ptr(),
                                    11i32 * 11i32,
                                    LPosOnes[colQ as usize].as_mut_ptr(),
                                    11i32 * 11i32, auxPosOnes.as_mut_ptr());
                processedQOnes[i_0 as usize] =
                    (processedQOnes[i_0 as usize] as i32 +
                         qBlockWeights[i_0 as usize][colQ as usize] as
                             i32) as u8;
                i_0 += 1
            }
            colQ += 1
        }
        is_L_full = 1i32;
        let mut i_1: i32 = 0i32;
        while i_1 < 2i32 {
            is_L_full =
                (is_L_full != 0 &&
                     LPosOnes[i_1 as usize][(11i32 * 11i32 - 1i32) as usize]
                         != crate::consts::P as i32 as u32) as i32;
            i_1 += 1
        }
        (*sk).rejections =
            ((*sk).rejections as i32 + 1i32) as u8;
        if is_L_full != 0 {
            isDFRok =
                DFR_test(LPosOnes.as_mut_ptr(),
                         &mut (*sk).secondIterThreshold)
        }
        if !(is_L_full == 0 || isDFRok == 0) { break ; }
    }
    (*sk).rejections = ((*sk).rejections as i32 - 1i32) as u8;
    let mut Ln0dense: [DIGIT; 905] = [0; 905];
    let mut j_0: i32 = 0i32;
    while j_0 < 11i32 * 11i32 {
        if LPosOnes[(2i32 - 1i32) as usize][j_0 as usize] !=
               crate::consts::P as i32 as u32 {
            gf2x_set_coeff(Ln0dense.as_mut_ptr(),
                           LPosOnes[(2i32 - 1i32) as usize][j_0 as usize],
                           1i32 as DIGIT);
        }
        j_0 += 1
    }
    let mut Ln0Inv: [DIGIT; 905] = [0; 905];
    gf2x_mod_inverse(Ln0Inv.as_mut_ptr(),
                     Ln0dense.as_mut_ptr() as *const DIGIT);
    let mut i_2: i32 = 0i32;
    while i_2 < 2i32 - 1i32 {
        gf2x_mod_mul_dense_to_sparse((*pk).Mtr.as_mut_ptr().offset((i_2 *
                                                                        ((crate::consts::P as i32
                                                                              +
                                                                              (8i32
                                                                                   <<
                                                                                   3i32)
                                                                              -
                                                                              1i32)
                                                                             /
                                                                             (8i32
                                                                                  <<
                                                                                  3i32)))
                                                                       as
                                                                       isize),
                                     Ln0Inv.as_mut_ptr() as *const DIGIT,
                                     LPosOnes[i_2 as usize].as_mut_ptr() as
                                         *const u32,
                                     (11i32 * 11i32) as u32);
        i_2 += 1
    }
    let mut i_3: i32 = 0i32;
    while i_3 < 2i32 - 1i32 {
        gf2x_transpose_in_place((*pk).Mtr.as_mut_ptr().offset((i_3 *
                                                                   ((crate::consts::P as i32
                                                                         +
                                                                         (8i32
                                                                              <<
                                                                              3i32)
                                                                         -
                                                                         1i32)
                                                                        /
                                                                        (8i32
                                                                             <<
                                                                             3i32)))
                                                                  as isize));
        i_3 += 1
    };
}
