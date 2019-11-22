use crate::bf_decoding::*;
use crate::constant_weight_codec::*;
use crate::consts::*;
use crate::crypto::*;
use crate::gf2x_arith::*;
use crate::gf2x_arith_mod_xPplusOne::*;
use crate::types::*;
use crate::H_Q_matrices_generation::*;

use std::convert::TryInto;

extern "C" {
    #[no_mangle]
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
}

unsafe fn decrypt_McEliece(
    mut decoded_err: *mut DIGIT,
    mut correct_codeword: *mut DIGIT,
    sk: &LedaPrivateKey,
    thresholds: &[i32],
    ctext: &[u8]) -> i32 {

    let mut xof = seedexpander_from_trng(&sk.prng_seed).unwrap();
    /* rebuild secret key values */
    let mut HPosOnes: [[u32; 11]; 2] = [[0; 11]; 2];
    let mut QPosOnes: [[u32; 11]; 2] = [[0; 11]; 2];
    let mut rejections: i32 = sk.rejections as i32;
    let mut LPosOnes: [[u32; 121]; 2] = [[0; 121]; 2];
    loop {
        generateHPosOnes(&mut HPosOnes, &mut xof);
        generateQPosOnes(&mut QPosOnes, &mut xof);
        for i in 0..2 {
            for j in 0..(11*11) {
                LPosOnes[i][j] = crate::consts::P as u32;
            }
        }
        let mut auxPosOnes: [u32; 121] = [0; 121];
        let mut processedQOnes: [usize; 2] = [0, 0];
        for colQ in 0..N0 {
            for i in 0..N0 {
                gf2x_mod_mul_sparse(&mut auxPosOnes,
                                    &HPosOnes[i],
                                    &QPosOnes[i][processedQOnes[i]..(processedQOnes[i]+qBlockWeights[i][colQ] as usize)]);
                gf2x_mod_add_sparse(
                    11i32 * 11i32,
                    LPosOnes[colQ as usize].as_mut_ptr(),
                    11i32 * 11i32,
                    LPosOnes[colQ as usize].as_mut_ptr(),
                    11i32 * 11i32,
                    auxPosOnes.as_mut_ptr(),
                );
                processedQOnes[i] += qBlockWeights[i][colQ as usize] as usize;
            }
        }
        rejections -= 1;
        if !(rejections >= 0i32) {
            break;
        }
    }
    let mut HtrPosOnes: [[u32; DV]; 2] = [[0; DV]; 2];
    let mut QtrPosOnes: [[u32; DV]; 2] = [[0; DV]; 2];
    transposeHPosOnes(&mut HtrPosOnes, &HPosOnes);
    transposeQPosOnes(&mut QtrPosOnes, &QPosOnes);
    /* end rebuild secret key values */
    let mut codewordPoly: [DIGIT; N0*NUM_DIGITS_GF2X_ELEMENT] = [0; N0*NUM_DIGITS_GF2X_ELEMENT]; // privateSyndrome := yVar* Htr

    for i in 0..codewordPoly.len() {
        let digit : [u8; 8] = ctext[(8*i)..(8*(i+1))].try_into().expect("8 bytes");
        codewordPoly[i] = u64::from_le_bytes(digit);
    }

    let mut i_1: u32 = 0i32 as u32;
    while i_1 < 2i32 as u32 {
        gf2x_transpose_in_place(codewordPoly.as_mut_ptr().offset(i_1.wrapping_mul(
            ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) as u32,
        ) as isize));
        i_1 = i_1.wrapping_add(1)
    }
    let mut privateSyndrome: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    let mut aux: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    let mut i_2: i32 = 0i32;
    while i_2 < 2i32 {
        gf2x_mod_mul_dense_to_sparse(
            aux.as_mut_ptr(),
            codewordPoly.as_mut_ptr().offset(
                (i_2 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)))
                    as isize,
            ) as *const DIGIT,
            LPosOnes[i_2 as usize].as_mut_ptr() as *const u32,
            (11i32 * 11i32) as u32,
        );
        gf2x_mod_add(
            privateSyndrome.as_mut_ptr(),
            privateSyndrome.as_mut_ptr() as *const DIGIT,
            aux.as_mut_ptr() as *const DIGIT,
        );
        i_2 += 1
    }
    gf2x_transpose_in_place(privateSyndrome.as_mut_ptr());
    /*perform syndrome decoding to obtain error vector */
    let ok = bf_decoding(
        decoded_err,
        HtrPosOnes.as_mut_ptr() as *const [u32; DV],
        QtrPosOnes.as_mut_ptr() as *const [u32; DV],
        &mut privateSyndrome,
        thresholds,
    );
    if ok == 0i32 {
        return 0i32;
    }
    let mut err_weight: i32 = 0i32;
    let mut i_3: i32 = 0i32;
    while i_3 < 2i32 {
        err_weight += population_count(decoded_err.offset(
            ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * i_3) as isize,
        ));
        i_3 += 1
    }
    if err_weight != NUM_ERRORS as i32 {
        return 0i32;
    }
    /* correct input codeword */

    let mut i_4: u32 = 0i32 as u32;
    while i_4 < 2i32 as u32 {
        gf2x_mod_add(
            correct_codeword.offset(i_4.wrapping_mul(
                ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) as u32,
            ) as isize),
            (ctext.as_ptr() as *const DIGIT).offset(i_4.wrapping_mul(
                ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) as u32,
            ) as isize) as *const DIGIT,
            decoded_err.offset(i_4.wrapping_mul(
                ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) as u32,
            ) as isize) as *const DIGIT,
        );
        i_4 = i_4.wrapping_add(1)
    }
    return 1i32;
}
/*----------------------------------------------------------------------------*/
unsafe fn char_left_bit_shift_n(length: i32, mut input: *mut u8, amount: i32) {
    if amount > 8i32 {
        panic!("assertion");
    }
    if amount == 0i32 {
        return;
    }
    let mut j: i32 = 0;
    let mask: u8 = !(((0x1i32 as u8 as i32) << 8i32 - amount) - 1i32) as u8;
    while j < length - 1i32 {
        let ref mut fresh0 = *input.offset(j as isize);
        *fresh0 = ((*fresh0 as i32) << amount) as u8;
        let ref mut fresh1 = *input.offset(j as isize);
        *fresh1 = (*fresh1 as i32
            | (*input.offset((j + 1i32) as isize) as i32 & mask as i32) >> 8i32 - amount)
            as u8;
        j += 1
    }
    let ref mut fresh2 = *input.offset(j as isize);
    *fresh2 = ((*fresh2 as i32) << amount) as u8;
}
// end right_bit_shift_n
/*----------------------------------------------------------------------------*/
unsafe fn poly_seq_into_bytestream(
    mut output: *mut u8,
    byteOutputLength: u32,
    mut zPoly: *mut DIGIT,
    numPoly: u32,
) -> i32 {
    let mut output_bit_cursor: u32 = byteOutputLength
        .wrapping_mul(8i32 as u32)
        .wrapping_sub(numPoly.wrapping_mul(crate::consts::P as i32 as u32));
    if (crate::consts::P as i32 as u32).wrapping_mul(numPoly)
        > (8i32 as u32).wrapping_mul(byteOutputLength)
    {
        return 0i32;
    }
    let mut i: i32 = 0i32;
    while (i as u32) < numPoly {
        let mut exponent: u32 = 0i32 as u32;
        while exponent < crate::consts::P as i32 as u32 {
            let bitValue = gf2x_get_coeff(
                zPoly.offset(
                    (i * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)))
                        as isize,
                ) as *const DIGIT,
                exponent,
            );
            bitstream_write(output, 1i32 as u32, &mut output_bit_cursor, bitValue);
            exponent = exponent.wrapping_add(1)
        }
        i += 1
        // end for exponent
    }
    let mut padsize: i32 = if (2i32 - 1i32) * crate::consts::P as i32 % 8i32 != 0 {
        (8i32) - (2i32 - 1i32) * crate::consts::P as i32 % 8i32
    } else {
        0i32
    };
    char_left_bit_shift_n(byteOutputLength as i32, output, padsize);
    return 1i32;
}

pub unsafe fn decrypt_Kobara_Imai(sk: &LedaPrivateKey, ctext: &[u8]) -> Result<Vec<u8>> {
    if ctext.len() < N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B {
        return Err(Error::DecryptionFailed);
    }

    // constituted by codeword || leftover

    let clen = ctext.len() as u64;
    let ctx = ctext.as_ptr();

    let mut correctedCodeword: [DIGIT; N0*NUM_DIGITS_GF2X_ELEMENT] = [0; N0*NUM_DIGITS_GF2X_ELEMENT];
    /* first N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B bytes are the actual McE
     * ciphertext. Note: storage endiannes in BE hardware should flip bytes */

    for i in 0..correctedCodeword.len() {
        let digit : [u8; 8] = ctext[(8*i)..(8*(i+1))].try_into().expect("8 bytes");
        correctedCodeword[i] = u64::from_le_bytes(digit);
    }

    let thresholds: [i32; 2] = [64, sk.secondIterThreshold as i32];
    let mut err: [DIGIT; N0*NUM_DIGITS_GF2X_ELEMENT] = [0; N0*NUM_DIGITS_GF2X_ELEMENT];

    if decrypt_McEliece(
        err.as_mut_ptr(),
        correctedCodeword.as_mut_ptr(),
        sk,
        &thresholds,
        ctext,
    ) == 0i32
    {
        return Err(Error::DecryptionFailed);
    }
    /* correctedCodeword now contains the correct codeword, iword is the first
     * portion, followed by syndrome turn back iword into a bytesequence */
    let mut paddedSequenceLen: u64 = 0;
    if clen
        <= (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) * 8i32)
            as u64
    {
        paddedSequenceLen = (((2i32 - 1i32) * crate::consts::P as i32 + 7i32) / 8i32) as u64
    } else {
        paddedSequenceLen = clen
            .wrapping_sub(
                (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) * 8i32)
                    as u64,
            )
            .wrapping_sub(1i32 as u64)
            .wrapping_add((((2i32 - 1i32) * crate::consts::P as i32 + 7i32) / 8i32) as u64)
            as u64
    }
    let mut paddedOutput: Vec<u8> = vec![0u8; paddedSequenceLen as usize];
    poly_seq_into_bytestream(
        paddedOutput.as_mut_ptr(),
        (((2i32 - 1i32) * crate::consts::P as i32 + 7i32) / 8i32) as u32,
        correctedCodeword.as_mut_ptr(),
        (2i32 - 1i32) as u32,
    );
    /* move back leftover padded string (if present) onto its position*/
    if clen
        > (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) * 8i32)
            as u64
    {
        /* meld back byte split across iword and leftover. Recall that leftover is
         * built with leading zeroes, and output from iword has trailing zeroes
         * so no masking away is needed */
        let ref mut fresh3 = *paddedOutput
            .as_mut_ptr()
            .offset((((2i32 - 1i32) * crate::consts::P as i32 + 7i32) / 8i32 - 1i32) as isize);
        *fresh3 = (*fresh3 as i32
            | *ctx.offset(
                (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) * 8i32)
                    as isize,
            ) as i32) as u8;
        let mut remainingToCopy: i32 = paddedSequenceLen
            .wrapping_sub((((2i32 - 1i32) * crate::consts::P as i32 + 7i32) / 8i32) as u64)
            as i32;
        memmove(
            paddedOutput
                .as_mut_ptr()
                .offset((((2i32 - 1i32) * crate::consts::P as i32 + 7i32) / 8i32) as isize)
                as *mut libc::c_void,
            ctx.offset(
                (2i32 * ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) * 8i32)
                    as isize,
            )
            .offset(1) as *const libc::c_void,
            remainingToCopy as u64,
        );
    }

    let outputHash = sha3_384(&paddedOutput);
    /* rebuild message hash ^ seed from error vector */
    let mut cwEncOutputBuffer = vec![0u8; 1072];
    constant_weight_to_binary_approximate(
        cwEncOutputBuffer.as_mut_ptr(),
        err.as_mut_ptr() as *const DIGIT,
    );
    /* obtain back the PRNG seed */
    let mut secretSeed: [u8; 32] = [0; 32];
    let mut i: i32 = 0i32;
    while i < 32i32 {
        secretSeed[i as usize] =
            (cwEncOutputBuffer[i as usize] as i32 ^ outputHash[i as usize] as i32) as u8;
        i += 1
    }
    /* test that the padding bytes of the seed are actually zero */
    let mut i_0: i32 = 32i32;
    while i_0 < 48i32 {
        if cwEncOutputBuffer[i_0 as usize] as i32 ^ outputHash[i_0 as usize] as i32 != 0i32 {
            return Err(Error::DecryptionFailed);
        }
        i_0 += 1
    }

    let prngSequence =
        deterministic_random_byte_generator(&secretSeed, paddedSequenceLen as usize).unwrap();
    /* remove PRNG Pad from entire message */
    let mut i_1: i32 = 0i32;
    while (i_1 as u64) < paddedSequenceLen {
        let ref mut fresh4 = *paddedOutput.as_mut_ptr().offset(i_1 as isize);
        *fresh4 = (*fresh4 as i32 ^ prngSequence[i_1 as usize] as i32) as u8;
        i_1 += 1
    }
    /*test if Kobara Imai constant, default to zero, matches */
    let mut i_2: i32 = 0i32;
    while i_2 < 32i32 {
        if *paddedOutput.as_mut_ptr().offset(i_2 as isize) as i32 != 0i32 {
            return Err(Error::DecryptionFailed);
        }
        i_2 += 1
    }
    /* retrieve message len, and set it */
    let ptext_len: u64 = u64::from_le_bytes(paddedOutput[32..40].try_into().expect("8 bytes"));

    Ok(paddedOutput[40..(ptext_len as usize+40)].to_vec())
}
// end decrypt_Kobara_Imai
