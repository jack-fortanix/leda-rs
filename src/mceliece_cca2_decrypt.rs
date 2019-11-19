
use crate::types::*;
use crate::consts::*;
use crate::gf2x_arith::*;
use crate::gf2x_arith_mod_xPplusOne::*;
use crate::bf_decoding::*;
use crate::H_Q_matrices_generation::*;
use crate::constant_weight_codec::*;
use crate::crypto::{deterministic_random_byte_generator, seedexpander_from_trng};

extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64)
     -> *mut libc::c_void;
}

unsafe fn decrypt_McEliece(mut decoded_err: *mut DIGIT,
                           mut correct_codeword: *mut DIGIT,
                           mut sk: *const privateKeyMcEliece_t,
                           thresholds: &[i32],
                           ctx: *const u8)
 -> i32 {
    let mut mceliece_decrypt_expander =
        seedexpander_from_trng((*sk).prng_seed.as_ptr());
    /* rebuild secret key values */
    let mut HPosOnes: [[u32; 11]; 2] = [[0; 11]; 2];
    let mut QPosOnes: [[u32; 11]; 2] = [[0; 11]; 2];
    let mut rejections: i32 = (*sk).rejections as i32;
    let mut LPosOnes: [[u32; 121]; 2] = [[0; 121]; 2];
    loop  {
        generateHPosOnes(HPosOnes.as_mut_ptr(),
                         &mut mceliece_decrypt_expander);
        generateQPosOnes(QPosOnes.as_mut_ptr(),
                         &mut mceliece_decrypt_expander);
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
        rejections -= 1;
        if !(rejections >= 0i32) { break ; }
    }
    let mut HtrPosOnes: [[u32; 11]; 2] = [[0; 11]; 2];
    let mut QtrPosOnes: [[u32; 11]; 2] = [[0; 11]; 2];
    transposeHPosOnes(HtrPosOnes.as_mut_ptr(), HPosOnes.as_mut_ptr());
    transposeQPosOnes(QtrPosOnes.as_mut_ptr(), QPosOnes.as_mut_ptr());
    /* end rebuild secret key values */
    let mut codewordPoly: [DIGIT; 1810] =
        [0; 1810]; // privateSyndrome := yVar* Htr
    memcpy(codewordPoly.as_mut_ptr() as *mut libc::c_void,
           ctx as *const libc::c_void,
           (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64); // end for i
    let mut i_1: u32 = 0i32 as u32;
    while i_1 < 2i32 as u32 {
        gf2x_transpose_in_place(codewordPoly.as_mut_ptr().offset(i_1.wrapping_mul(((crate::consts::P as i32
                                                                                        +
                                                                                        (8i32
                                                                                             <<
                                                                                             3i32)
                                                                                        -
                                                                                        1i32)
                                                                                       /
                                                                                       (8i32
                                                                                            <<
                                                                                            3i32))
                                                                                      as
                                                                                      u32)
                                                                     as
                                                                     isize));
        i_1 = i_1.wrapping_add(1)
    }
    let mut privateSyndrome: [DIGIT; 905] = [0; 905];
    memset(privateSyndrome.as_mut_ptr() as *mut libc::c_void, 0i32,
           ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * 8i32) as
               u64);
    let mut aux: [DIGIT; 905] = [0; 905];
    let mut i_2: i32 = 0i32;
    while i_2 < 2i32 {
        gf2x_mod_mul_dense_to_sparse(aux.as_mut_ptr(),
                                     codewordPoly.as_mut_ptr().offset((i_2 *
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
                                                                          isize)
                                         as *const DIGIT,
                                     LPosOnes[i_2 as usize].as_mut_ptr() as
                                         *const u32,
                                     (11i32 * 11i32) as u32);
        gf2x_mod_add(privateSyndrome.as_mut_ptr(),
                     privateSyndrome.as_mut_ptr() as *const DIGIT,
                     aux.as_mut_ptr() as *const DIGIT);
        i_2 += 1
    }
    gf2x_transpose_in_place(privateSyndrome.as_mut_ptr());
    memset(decoded_err as *mut libc::c_void, 0i32,
           (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64);
    /*perform syndrome decoding to obtain error vector */
    let ok = bf_decoding(decoded_err,
                         HtrPosOnes.as_mut_ptr() as *const [u32; 11],
                         QtrPosOnes.as_mut_ptr() as *const [u32; 11],
                         privateSyndrome.as_mut_ptr(),
                         thresholds);
    if ok == 0i32 { return 0i32 }
    let mut err_weight: i32 = 0i32;
    let mut i_3: i32 = 0i32;
    while i_3 < 2i32 {
        err_weight +=
            population_count(decoded_err.offset(((crate::consts::P as i32 + (8i32 << 3i32) -
                                                      1i32) / (8i32 << 3i32) *
                                                     i_3) as isize));
        i_3 += 1
    }
    if err_weight != 199i32 { return 0i32 }
    /* correct input codeword */
    let mut i_4: u32 = 0i32 as u32;
    while i_4 < 2i32 as u32 {
        gf2x_mod_add(correct_codeword.offset(i_4.wrapping_mul(((crate::consts::P as i32 +
                                                                    (8i32 <<
                                                                         3i32)
                                                                    - 1i32) /
                                                                   (8i32 <<
                                                                        3i32))
                                                                  as
                                                                  u32)
                                                 as isize),
                     (ctx as
                          *mut DIGIT).offset(i_4.wrapping_mul(((crate::consts::P as i32 +
                                                                    (8i32 <<
                                                                         3i32)
                                                                    - 1i32) /
                                                                   (8i32 <<
                                                                        3i32))
                                                                  as
                                                                  u32)
                                                 as isize) as *const DIGIT,
                     decoded_err.offset(i_4.wrapping_mul(((crate::consts::P as i32 +
                                                               (8i32 << 3i32)
                                                               - 1i32) /
                                                              (8i32 << 3i32))
                                                             as u32)
                                            as isize) as *const DIGIT);
        i_4 = i_4.wrapping_add(1)
    }
    return 1i32;
}
/*----------------------------------------------------------------------------*/
unsafe fn char_left_bit_shift_n(length: i32,
                                           mut in_0: *mut u8,
                                           amount: i32) {
    if amount > 8i32 {
        panic!("assertion");
    }
    if amount == 0i32 { return }
    let mut j: i32 = 0;
    let mask: u8 = !(((0x1i32 as u8 as i32) << 8i32 - amount) - 1i32) as u8;
    while j < length - 1i32 {
        let ref mut fresh0 = *in_0.offset(j as isize);
        *fresh0 = ((*fresh0 as i32) << amount) as u8;
        let ref mut fresh1 = *in_0.offset(j as isize);
        *fresh1 =
            (*fresh1 as i32 |
                 (*in_0.offset((j + 1i32) as isize) as i32 &
                      mask as i32) >> 8i32 - amount) as u8;
        j += 1
    }
    let ref mut fresh2 = *in_0.offset(j as isize);
    *fresh2 = ((*fresh2 as i32) << amount) as u8;
}
// end right_bit_shift_n
/*----------------------------------------------------------------------------*/
unsafe fn poly_seq_into_bytestream(mut output: *mut u8,
                                              byteOutputLength: u32,
                                              mut zPoly: *mut DIGIT,
                                              numPoly: u32)
 -> i32 {
    let mut output_bit_cursor: u32 =
        byteOutputLength.wrapping_mul(8i32 as
                                          u32).wrapping_sub(numPoly.wrapping_mul(crate::consts::P as i32
                                                                                              as
                                                                                              u32));
    if (crate::consts::P as i32 as u32).wrapping_mul(numPoly) >
           (8i32 as u32).wrapping_mul(byteOutputLength) {
        return 0i32
    }
    let mut i: i32 = 0i32;
    while (i as u32) < numPoly {
        let mut exponent: u32 = 0i32 as u32;
        while exponent < crate::consts::P as i32 as u32 {
            let bitValue =
                gf2x_get_coeff(zPoly.offset((i *
                                                 ((crate::consts::P as i32 + (8i32 << 3i32) -
                                                       1i32) /
                                                      (8i32 << 3i32))) as
                                                isize) as *const DIGIT,
                               exponent);
            bitstream_write(output, 1i32 as u32,
                            &mut output_bit_cursor, bitValue);
            exponent = exponent.wrapping_add(1)
        }
        i += 1
        // end for exponent
    }
    let mut padsize: i32 =
        if (2i32 - 1i32) * crate::consts::P as i32 % 8i32 != 0 {
            (8i32) - (2i32 - 1i32) * crate::consts::P as i32 % 8i32
        } else { 0i32 };
    char_left_bit_shift_n(byteOutputLength as i32, output, padsize);
    return 1i32;
}


pub unsafe fn decrypt_Kobara_Imai(sk: *const privateKeyMcEliece_t,
                                             clen: u64,
                                             ctx: *const u8) -> Vec<u8>
 // constituted by codeword || leftover
 {
    let mut err: [DIGIT; 1810] = [0; 1810];
    let mut correctedCodeword: [DIGIT; 1810] = [0; 1810];
    /* first N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B bytes are the actual McE
    * ciphertext. Note: storage endiannes in BE hardware should flip bytes */
    memcpy(correctedCodeword.as_mut_ptr() as *mut libc::c_void,
           ctx as *const libc::c_void,
           (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                     8i32) as u64);

    let thresholds: [i32; 2] = [64, (*sk).secondIterThreshold as i32];

    if decrypt_McEliece(err.as_mut_ptr(), correctedCodeword.as_mut_ptr(), sk, &thresholds,
                        ctx) == 0i32 {
        panic!("decoding fail");
    }
    /* correctedCodeword now contains the correct codeword, iword is the first
    * portion, followed by syndrome turn back iword into a bytesequence */
    let mut paddedSequenceLen: u64 = 0;
    if clen <=
           (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64 {
        paddedSequenceLen =
            (((2i32 - 1i32) * crate::consts::P as i32 + 7i32) / 8i32) as u64
    } else {
        paddedSequenceLen =
            clen.wrapping_sub((2i32 *
                                   ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                        (8i32 << 3i32)) * 8i32) as
                                  u64).wrapping_sub(1i32 as
                                                                      u64).wrapping_add((((2i32
                                                                                                             -
                                                                                                             1i32)
                                                                                                            *
                                                                                                            crate::consts::P as i32
                                                                                                            +
                                                                                                            7i32)
                                                                                                           /
                                                                                                           8i32)
                                                                                                          as
                                                                                                          u64)
                as u64
    }
    let vla = paddedSequenceLen as usize;
    let mut paddedOutput: Vec<u8> = ::std::vec::from_elem(0, vla);
    memset(paddedOutput.as_mut_ptr() as *mut libc::c_void, 0i32,
           paddedSequenceLen);
    poly_seq_into_bytestream(paddedOutput.as_mut_ptr(),
                             (((2i32 - 1i32) * crate::consts::P as i32 + 7i32) / 8i32) as
                                 u32, correctedCodeword.as_mut_ptr(),
                             (2i32 - 1i32) as u32);
    /* move back leftover padded string (if present) onto its position*/
    if clen >
           (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64 {
        /* meld back byte split across iword and leftover. Recall that leftover is
    * built with leading zeroes, and output from iword has trailing zeroes
    * so no masking away is needed */
        let ref mut fresh3 =
            *paddedOutput.as_mut_ptr().offset((((2i32 - 1i32) * crate::consts::P as i32 +
                                                    7i32) / 8i32 - 1i32) as
                                                  isize);
        *fresh3 =
            (*fresh3 as i32 |
                 *ctx.offset((2i32 *
                                  ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                       (8i32 << 3i32)) * 8i32) as isize) as
                     i32) as u8;
        let mut remainingToCopy: i32 =
            paddedSequenceLen.wrapping_sub((((2i32 - 1i32) * crate::consts::P as i32 + 7i32)
                                                / 8i32) as u64) as
                i32;
        memmove(paddedOutput.as_mut_ptr().offset((((2i32 - 1i32) * crate::consts::P as i32 +
                                                       7i32) / 8i32) as isize)
                    as *mut libc::c_void,
                ctx.offset((2i32 *
                                ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) /
                                     (8i32 << 3i32)) * 8i32) as
                               isize).offset(1) as *const libc::c_void,
                remainingToCopy as u64);
    }
    let mut outputHash: [u8; 48] =
        [0i32 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0];
    crate::crypto::sha3_384(paddedOutput.as_mut_ptr(), paddedSequenceLen as u32,
             outputHash.as_mut_ptr());
    /* rebuild message hash ^ seed from error vector */
    let mut cwEncOutputBuffer = vec![0u8; 1072];
    constant_weight_to_binary_approximate(cwEncOutputBuffer.as_mut_ptr(),
                                          err.as_mut_ptr() as *const DIGIT);
    /* obtain back the PRNG seed */
    let mut secretSeed: [u8; 32] = [0; 32];
    let mut i: i32 = 0i32;
    while i < 32i32 {
        secretSeed[i as usize] =
            (cwEncOutputBuffer[i as usize] as i32 ^
                 outputHash[i as usize] as i32) as u8;
        i += 1
    }
    /* test that the padding bytes of the seed are actually zero */
    let mut i_0: i32 = 32i32;
    while i_0 < 48i32 {
        if cwEncOutputBuffer[i_0 as usize] as i32 ^
            outputHash[i_0 as usize] as i32 != 0i32 {
                panic!("nonzero trng pad");
        }
        i_0 += 1
    }
    let vla_0 = paddedSequenceLen as usize;
    let mut prngSequence: Vec<u8> =
        ::std::vec::from_elem(0, vla_0);
    memset(prngSequence.as_mut_ptr() as *mut libc::c_void, 0i32,
           paddedSequenceLen);
    deterministic_random_byte_generator(prngSequence.as_mut_ptr(),
                                        (vla_0 *
                                             ::std::mem::size_of::<u8>())
                                            as u64 as
                                            u64,
                                        secretSeed.as_mut_ptr(),
                                        32i32 as u64);
    /* remove PRNG Pad from entire message */
    let mut i_1: i32 = 0i32;
    while (i_1 as u64) < paddedSequenceLen {
        let ref mut fresh4 = *paddedOutput.as_mut_ptr().offset(i_1 as isize);
        *fresh4 =
            (*fresh4 as i32 ^
                 *prngSequence.as_mut_ptr().offset(i_1 as isize) as
                     i32) as u8;
        i_1 += 1
    }
    /*test if Kobara Imai constant, default to zero, matches */
    let mut i_2: i32 = 0i32;
    while i_2 < 32i32 {
        if *paddedOutput.as_mut_ptr().offset(i_2 as isize) as i32 !=
            0i32 {
                panic!("KI const mismatch");
        }
        i_2 += 1
    }
    /* retrieve message len, and set it */
    let mut correctlySizedBytePtxLen: u64 = 0;
    memcpy(&mut correctlySizedBytePtxLen as *mut u64 as
               *mut libc::c_void,
           paddedOutput.as_mut_ptr().offset(32) as *const libc::c_void,
           ::std::mem::size_of::<u64>() as u64);

     let mut output = vec![0u8; correctlySizedBytePtxLen as usize];

    /* copy message in output buffer */
    memcpy(output.as_mut_ptr() as *mut libc::c_void,
           paddedOutput.as_mut_ptr().offset(32).offset(::std::mem::size_of::<u64>()
                                                           as u64 as
                                                           isize) as
               *const libc::c_void, correctlySizedBytePtxLen);
     return output;
}
// end decrypt_Kobara_Imai
