
use crate::types::*;
use sha3::Digest;

extern "C" {
    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    fn bitstream_write(output: *mut u8,
                       amount_to_write: u32,
                       output_bit_cursor: *mut u32,
                       value_to_write: u64);
    #[no_mangle]
    fn deterministic_random_byte_generator(output: *mut u8,
                                           output_len: u64,
                                           seed: *const u8,
                                           seed_length: u64);
    #[no_mangle]
    fn seedexpander_from_trng(ctx: *mut AES_XOF_struct,
                              trng_entropy: *const u8);
    /* ret. 1 if inv. exists */
    /*---------------------------------------------------------------------------*/
    #[no_mangle]
    fn gf2x_transpose_in_place(A: *mut DIGIT);
    /*---------------------------------------------------------------------------*/
    #[no_mangle]
    fn gf2x_mod_add_sparse(sizeR: i32, Res: *mut u32,
                           sizeA: i32, A: *mut u32,
                           sizeB: i32, B: *mut u32);
    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    fn gf2x_mod_mul_sparse(sizeR: i32, Res: *mut u32,
                           sizeA: i32, A: *const u32,
                           sizeB: i32, B: *const u32);
    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    fn gf2x_mod_mul_dense_to_sparse(Res: *mut DIGIT, dense: *const DIGIT,
                                    sparse: *const u32,
                                    nPos: u32);
    #[no_mangle]
    fn constant_weight_to_binary_approximate(bitstreamOut: *mut u8,
                                             constantWeightIn: *const DIGIT);

    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    fn generateHPosOnes(HPosOnes: *mut [u32; 11],
                        niederreiter_keys_expander: *mut AES_XOF_struct);
    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    fn transposeHPosOnes(HtrPosOnes: *mut [u32; 11],
                         HPosOnes: *mut [u32; 11]);
    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    fn generateQPosOnes(QPosOnes: *mut [u32; 11],
                        keys_expander: *mut AES_XOF_struct);
    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    fn transposeQPosOnes(QtrPosOnes: *mut [u32; 11],
                         QPosOnes: *mut [u32; 11]);

    #[no_mangle]
    fn bf_decoding(err: *mut DIGIT, HtrPosOnes: *const [u32; 11],
                   QtrPosOnes: *const [u32; 11],
                   privateSyndrome: *mut DIGIT) -> i32;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64)
     -> *mut libc::c_void;
    // end poly_seq_into_bytestream
    /*----------------------------------------------------------------------------*/
    #[no_mangle]
    static mut thresholds: [i32; 2];
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
/*----------------------------------------------------------------------------*/
#[inline]
unsafe extern "C" fn gf2x_add(nr: i32, mut Res: *mut DIGIT,
                              na: i32, mut A: *const DIGIT,
                              nb: i32, mut B: *const DIGIT) {
    let mut i: u32 = 0i32 as u32;
    while i < nr as u32 {
        *Res.offset(i as isize) =
            *A.offset(i as isize) ^ *B.offset(i as isize);
        i = i.wrapping_add(1)
    };
}
static mut qBlockWeights: [[u8; 2]; 2] =
    [[6i32 as u8, 5i32 as u8],
     [5i32 as u8, 6i32 as u8]];
/*---------------------------------------------------------------------------*/
#[inline]
unsafe extern "C" fn gf2x_mod_add(mut Res: *mut DIGIT, mut A: *const DIGIT,
                                  mut B: *const DIGIT) {
    gf2x_add((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), Res,
             (57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), A,
             (57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), B);
}
/* in place bit-transp. of a(x) % x^P+1  *
                                      * e.g.: a3 a2 a1 a0 --> a1 a2 a3 a0     */
/*---------------------------------------------------------------------------*/
/* population count for a single polynomial */
#[inline]
unsafe extern "C" fn population_count(mut upc: *mut DIGIT) -> i32 {
    let mut ret: i32 = 0i32;
    let mut i: i32 =
        (57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) - 1i32;
    while i >= 0i32 {
        ret +=
            (*upc.offset(i as isize) as u64).count_ones() as
                i32;
        i -= 1
    }
    return ret;
}
// end population_count
/*--------------------------------------------------------------------------*/
/* returns the coefficient of the x^exponent term as the LSB of a digit */
#[inline]
unsafe extern "C" fn gf2x_get_coeff(mut poly: *const DIGIT,
                                    exponent: u32) -> DIGIT {
    let mut straightIdx: u32 =
        (((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * (8i32 << 3i32)
              - 1i32) as u32).wrapping_sub(exponent);
    let mut digitIdx: u32 =
        straightIdx.wrapping_div((8i32 << 3i32) as u32);
    let mut inDigitIdx: u32 =
        straightIdx.wrapping_rem((8i32 << 3i32) as u32);
    return *poly.offset(digitIdx as isize) >>
               (((8i32 << 3i32) - 1i32) as
                    u32).wrapping_sub(inDigitIdx) & 1i32 as DIGIT;
}
/* *
  *  Function to compute SHA3-384 on the input message.
  *  The output length is fixed to 48 bytes.
  */
#[inline]
unsafe extern "C" fn sha3_384(mut input: *const u8,
                              mut inputByteLen: u32,
                              mut output: *mut u8) {
    let mut hasher = sha3::Sha3_384::new();

    let slice = std::slice::from_raw_parts(input, inputByteLen as usize);
    hasher.input(slice);

    let result = hasher.result();

    std::ptr::copy(result.as_ptr(), output, result.len());
}
/* *
 *
 * @version 2.0 (March 2019)
 *
 * Reference ISO-C11 Implementation of the LEDAcrypt PKC cipher using GCC built-ins.
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
// memset(...), memcpy(....)
/*----------------------------------------------------------------------------*/
unsafe extern "C" fn decrypt_McEliece(mut decoded_err: *mut DIGIT,
                                      mut correct_codeword: *mut DIGIT,
                                      mut sk: *mut privateKeyMcEliece_t,
                                      ctx: *const u8)
 -> i32 {
    let mut mceliece_decrypt_expander: AES_XOF_struct =
        AES_XOF_struct{buffer: [0; 16],
                       buffer_pos: 0,
                       length_remaining: 0,
                       key: [0; 32],
                       ctr: [0; 16],};
    seedexpander_from_trng(&mut mceliece_decrypt_expander,
                           (*sk).prng_seed.as_mut_ptr());
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
                LPosOnes[i as usize][j as usize] = 57899i32 as u32;
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
           (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64); // end for i
    let mut i_1: u32 = 0i32 as u32;
    while i_1 < 2i32 as u32 {
        gf2x_transpose_in_place(codewordPoly.as_mut_ptr().offset(i_1.wrapping_mul(((57899i32
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
           ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * 8i32) as
               u64);
    let mut aux: [DIGIT; 905] = [0; 905];
    let mut i_2: i32 = 0i32;
    while i_2 < 2i32 {
        gf2x_mod_mul_dense_to_sparse(aux.as_mut_ptr(),
                                     codewordPoly.as_mut_ptr().offset((i_2 *
                                                                           ((57899i32
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
           (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64);
    /*perform syndrome decoding to obtain error vector */
    let mut ok: i32 = 0;
    ok =
        bf_decoding(decoded_err,
                    HtrPosOnes.as_mut_ptr() as *const [u32; 11],
                    QtrPosOnes.as_mut_ptr() as *const [u32; 11],
                    privateSyndrome.as_mut_ptr());
    if ok == 0i32 { return 0i32 }
    let mut err_weight: i32 = 0i32;
    let mut i_3: i32 = 0i32;
    while i_3 < 2i32 {
        err_weight +=
            population_count(decoded_err.offset(((57899i32 + (8i32 << 3i32) -
                                                      1i32) / (8i32 << 3i32) *
                                                     i_3) as isize));
        i_3 += 1
    }
    if err_weight != 199i32 { return 0i32 }
    /* correct input codeword */
    let mut i_4: u32 = 0i32 as u32;
    while i_4 < 2i32 as u32 {
        gf2x_mod_add(correct_codeword.offset(i_4.wrapping_mul(((57899i32 +
                                                                    (8i32 <<
                                                                         3i32)
                                                                    - 1i32) /
                                                                   (8i32 <<
                                                                        3i32))
                                                                  as
                                                                  u32)
                                                 as isize),
                     (ctx as
                          *mut DIGIT).offset(i_4.wrapping_mul(((57899i32 +
                                                                    (8i32 <<
                                                                         3i32)
                                                                    - 1i32) /
                                                                   (8i32 <<
                                                                        3i32))
                                                                  as
                                                                  u32)
                                                 as isize) as *const DIGIT,
                     decoded_err.offset(i_4.wrapping_mul(((57899i32 +
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
unsafe extern "C" fn char_left_bit_shift_n(length: i32,
                                           mut in_0: *mut u8,
                                           amount: i32) {
    if amount > 8i32 {
        panic!("assertion");
    }
    if amount == 0i32 { return }
    let mut j: i32 = 0;
    let mut mask: u8 = 0;
    mask =
        !(((0x1i32 as u8 as i32) << 8i32 - amount) - 1i32) as
            u8;
    j = 0i32;
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
unsafe extern "C" fn poly_seq_into_bytestream(mut output: *mut u8,
                                              byteOutputLength: u32,
                                              mut zPoly: *mut DIGIT,
                                              numPoly: u32)
 -> i32 {
    let mut bitValue: DIGIT = 0; // end for i
    let mut output_bit_cursor: u32 =
        byteOutputLength.wrapping_mul(8i32 as
                                          u32).wrapping_sub(numPoly.wrapping_mul(57899i32
                                                                                              as
                                                                                              u32));
    if (57899i32 as u32).wrapping_mul(numPoly) >
           (8i32 as u32).wrapping_mul(byteOutputLength) {
        return 0i32
    }
    let mut i: i32 = 0i32;
    while (i as u32) < numPoly {
        let mut exponent: u32 = 0i32 as u32;
        while exponent < 57899i32 as u32 {
            bitValue =
                gf2x_get_coeff(zPoly.offset((i *
                                                 ((57899i32 + (8i32 << 3i32) -
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
        if (2i32 - 1i32) * 57899i32 % 8i32 != 0 {
            (8i32) - (2i32 - 1i32) * 57899i32 % 8i32
        } else { 0i32 };
    char_left_bit_shift_n(byteOutputLength as i32, output, padsize);
    return 1i32;
}
/* *
 *
 * <mceliece_cca2_decrypt.h>
 *
 * @version 2.0 (March 2019)
 *
 * Reference ISO-C11 Implementation of the LEDAcrypt PKC cipher using GCC built-ins.
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
#[no_mangle]
pub unsafe extern "C" fn decrypt_Kobara_Imai(output: *mut u8,
                                             mut byteOutputLength:
                                                 *mut u64,
                                             mut sk:
                                                 *mut privateKeyMcEliece_t,
                                             clen: u64,
                                             ctx: *const u8)
 -> i32 
 // constituted by codeword || leftover
 {
    let mut err: [DIGIT; 1810] = [0; 1810];
    let mut correctedCodeword: [DIGIT; 1810] = [0; 1810];
    /* first N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B bytes are the actual McE
    * ciphertext. Note: storage endiannes in BE hardware should flip bytes */
    memcpy(correctedCodeword.as_mut_ptr() as *mut libc::c_void,
           ctx as *const libc::c_void,
           (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64);
    thresholds[1] = (*sk).secondIterThreshold as i32;
    if decrypt_McEliece(err.as_mut_ptr(), correctedCodeword.as_mut_ptr(), sk,
                        ctx) == 0i32 {
        panic!("decoding fail");
        return 0i32
    }
    /* correctedCodeword now contains the correct codeword, iword is the first
    * portion, followed by syndrome turn back iword into a bytesequence */
    let mut paddedSequenceLen: u64 = 0;
    if clen <=
           (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64 {
        paddedSequenceLen =
            (((2i32 - 1i32) * 57899i32 + 7i32) / 8i32) as u64
    } else {
        paddedSequenceLen =
            clen.wrapping_sub((2i32 *
                                   ((57899i32 + (8i32 << 3i32) - 1i32) /
                                        (8i32 << 3i32)) * 8i32) as
                                  u64).wrapping_sub(1i32 as
                                                                      u64).wrapping_add((((2i32
                                                                                                             -
                                                                                                             1i32)
                                                                                                            *
                                                                                                            57899i32
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
                             (((2i32 - 1i32) * 57899i32 + 7i32) / 8i32) as
                                 u32, correctedCodeword.as_mut_ptr(),
                             (2i32 - 1i32) as u32);
    /* move back leftover padded string (if present) onto its position*/
    if clen >
           (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as u64 {
        /* meld back byte split across iword and leftover. Recall that leftover is
    * built with leading zeroes, and output from iword has trailing zeroes
    * so no masking away is needed */
        let ref mut fresh3 =
            *paddedOutput.as_mut_ptr().offset((((2i32 - 1i32) * 57899i32 +
                                                    7i32) / 8i32 - 1i32) as
                                                  isize);
        *fresh3 =
            (*fresh3 as i32 |
                 *ctx.offset((2i32 *
                                  ((57899i32 + (8i32 << 3i32) - 1i32) /
                                       (8i32 << 3i32)) * 8i32) as isize) as
                     i32) as u8;
        let mut remainingToCopy: i32 =
            paddedSequenceLen.wrapping_sub((((2i32 - 1i32) * 57899i32 + 7i32)
                                                / 8i32) as u64) as
                i32;
        memmove(paddedOutput.as_mut_ptr().offset((((2i32 - 1i32) * 57899i32 +
                                                       7i32) / 8i32) as isize)
                    as *mut libc::c_void,
                ctx.offset((2i32 *
                                ((57899i32 + (8i32 << 3i32) - 1i32) /
                                     (8i32 << 3i32)) * 8i32) as
                               isize).offset(1) as *const libc::c_void,
                remainingToCopy as u64);
    }
    let mut outputHash: [u8; 48] =
        [0i32 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0];
    sha3_384(paddedOutput.as_mut_ptr(), paddedSequenceLen as u32,
             outputHash.as_mut_ptr());
    /* rebuild message hash ^ seed from error vector */
    let mut cwEncOutputBuffer: [u8; 1072] =
        [0i32 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
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
            return 0i32
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
            return 0i32
        }
        i_2 += 1
    }
    /* retrieve message len, and set it */
    let mut correctlySizedBytePtxLen: u64 = 0;
    memcpy(&mut correctlySizedBytePtxLen as *mut u64 as
               *mut libc::c_void,
           paddedOutput.as_mut_ptr().offset(32) as *const libc::c_void,
           ::std::mem::size_of::<u64>() as u64);
    *byteOutputLength = correctlySizedBytePtxLen as u64;
    /* copy message in output buffer */
    memcpy(output as *mut libc::c_void,
           paddedOutput.as_mut_ptr().offset(32).offset(::std::mem::size_of::<u64>()
                                                           as u64 as
                                                           isize) as
               *const libc::c_void, correctlySizedBytePtxLen);
    return 1i32;
}
// end decrypt_Kobara_Imai
