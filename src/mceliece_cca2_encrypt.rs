#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(label_break_value)]
extern "C" {
    #[no_mangle]
    fn randombytes(x: *mut libc::c_uchar, xlen: libc::c_ulonglong)
     -> libc::c_int;
    #[no_mangle]
    fn deterministic_random_byte_generator(output: *mut libc::c_uchar,
                                           output_len: libc::c_ulonglong,
                                           seed: *const libc::c_uchar,
                                           seed_length: libc::c_ulonglong);
    // end gf2x_copy
    /*---------------------------------------------------------------------------*/
    // void gf2x_mod(DIGIT out[],
//               const int nin, const DIGIT in[]); /* out(x) = in(x) mod x^P+1  */
    /*---------------------------------------------------------------------------*/
    #[no_mangle]
    fn gf2x_mod_mul(Res: *mut DIGIT, A: *const DIGIT, B: *const DIGIT);
    #[no_mangle]
    fn binary_to_constant_weight_approximate(constantWeightOut: *mut DIGIT,
                                             bitstreamIn:
                                                 *const libc::c_uchar,
                                             bitLength: libc::c_int)
     -> libc::c_int;
    #[no_mangle]
    fn bitstream_read(stream: *const libc::c_uchar, bit_amount: libc::c_uint,
                      bit_cursor: *mut libc::c_uint) -> uint64_t;
    #[no_mangle]
    fn Keccak(rate: libc::c_uint, capacity: libc::c_uint,
              input: *const libc::c_uchar, inputByteLen: libc::c_ulonglong,
              delimitedSuffix: libc::c_uchar, output: *mut libc::c_uchar,
              outputByteLen: libc::c_ulonglong);
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn __assert_fail(__assertion: *const libc::c_char,
                     __file: *const libc::c_char, __line: libc::c_uint,
                     __function: *const libc::c_char) -> !;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
/* *
 *
 * <gf2x_limbs.h>
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
/* limb size definitions for the multi-precision GF(2^x) library              */
/*----------------------------------------------------------------------------*/
// gcc -DCPU_WORD_BITS=64 ...
pub type DIGIT = uint64_t;
#[derive ( Copy, Clone )]
#[repr(C)]
pub struct publicKeyMcEliece_t {
    pub Mtr: [DIGIT; 905],
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
/*----------------------------------------------------------------------------*/
#[inline]
unsafe extern "C" fn gf2x_add(nr: libc::c_int, mut Res: *mut DIGIT,
                              na: libc::c_int, mut A: *const DIGIT,
                              nb: libc::c_int, mut B: *const DIGIT) {
    let mut i: libc::c_uint = 0i32 as libc::c_uint;
    while i < nr as libc::c_uint {
        *Res.offset(i as isize) =
            *A.offset(i as isize) ^ *B.offset(i as isize);
        i = i.wrapping_add(1)
    };
}
/*---------------------------------------------------------------------------*/
#[inline]
unsafe extern "C" fn gf2x_mod_add(mut Res: *mut DIGIT, mut A: *const DIGIT,
                                  mut B: *const DIGIT) {
    gf2x_add((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), Res,
             (57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), A,
             (57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32), B);
}
/*--------------------------------------------------------------------------*/
/* sets the coefficient of the x^exponent term as the LSB of a digit */
#[inline]
unsafe extern "C" fn gf2x_set_coeff(mut poly: *mut DIGIT,
                                    exponent: libc::c_uint,
                                    mut value: DIGIT) {
    let mut straightIdx: libc::c_int =
        (((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * (8i32 << 3i32)
              - 1i32) as libc::c_uint).wrapping_sub(exponent) as libc::c_int;
    let mut digitIdx: libc::c_int = straightIdx / (8i32 << 3i32);
    let mut inDigitIdx: libc::c_uint =
        (straightIdx % (8i32 << 3i32)) as libc::c_uint;
    /* clear given coefficient */
    let mut mask: DIGIT =
        !((1i32 as DIGIT) <<
              (((8i32 << 3i32) - 1i32) as
                   libc::c_uint).wrapping_sub(inDigitIdx));
    *poly.offset(digitIdx as isize) = *poly.offset(digitIdx as isize) & mask;
    *poly.offset(digitIdx as isize) =
        *poly.offset(digitIdx as isize) |
            (value & 1i32 as DIGIT) <<
                (((8i32 << 3i32) - 1i32) as
                     libc::c_uint).wrapping_sub(inDigitIdx);
}
/* *
  *  Function to compute SHA3-384 on the input message.
  *  The output length is fixed to 48 bytes.
  */
#[inline]
unsafe extern "C" fn sha3_384(mut input: *const libc::c_uchar,
                              mut inputByteLen: libc::c_uint,
                              mut output: *mut libc::c_uchar) {
    Keccak(832i32 as libc::c_uint, 768i32 as libc::c_uint, input,
           inputByteLen as libc::c_ulonglong, 0x6i32 as libc::c_uchar, output,
           48i32 as libc::c_ulonglong);
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
// memset(...), memcpy(...)
/*----------------------------------------------------------------------------*/
unsafe extern "C" fn encrypt_McEliece(mut codeword: *mut DIGIT,
                                      pk: *const publicKeyMcEliece_t,
                                      mut ptx: *const DIGIT,
                                      mut err: *const DIGIT) 
 // N0   polynomials
 {
    memcpy(codeword as *mut libc::c_void, ptx as *const libc::c_void,
           ((2i32 - 1i32) *
                ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) * 8i32)
               as libc::c_ulong);
    memset(codeword.offset(((2i32 - 1i32) *
                                ((57899i32 + (8i32 << 3i32) - 1i32) /
                                     (8i32 << 3i32))) as isize) as
               *mut libc::c_void, 0i32,
           ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * 8i32) as
               libc::c_ulong);
    let mut saux: [DIGIT; 905] = [0; 905];
    let mut i: libc::c_int = 0i32;
    while i < 2i32 - 1i32 {
        memset(saux.as_mut_ptr() as *mut libc::c_void, 0i32,
               ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * 8i32) as
                   libc::c_ulong);
        gf2x_mod_mul(saux.as_mut_ptr(),
                     (*pk).Mtr.as_ptr().offset((i *
                                                    ((57899i32 +
                                                          (8i32 << 3i32) -
                                                          1i32) /
                                                         (8i32 << 3i32))) as
                                                   isize),
                     ptx.offset((i *
                                     ((57899i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32))) as isize));
        gf2x_mod_add(codeword.offset(((2i32 - 1i32) *
                                          ((57899i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32))) as isize),
                     codeword.offset(((2i32 - 1i32) *
                                          ((57899i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32))) as isize) as
                         *const DIGIT, saux.as_mut_ptr() as *const DIGIT);
        i += 1
    }
    let mut i_0: libc::c_int = 0i32;
    while i_0 < 2i32 {
        gf2x_mod_add(codeword.offset((i_0 *
                                          ((57899i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32))) as isize),
                     codeword.offset((i_0 *
                                          ((57899i32 + (8i32 << 3i32) - 1i32)
                                               / (8i32 << 3i32))) as isize) as
                         *const DIGIT,
                     err.offset((i_0 *
                                     ((57899i32 + (8i32 << 3i32) - 1i32) /
                                          (8i32 << 3i32))) as isize));
        i_0 += 1
    };
}
// end encrypt_McEliece
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe extern "C" fn char_right_bit_shift_n(length: libc::c_int,
                                                mut in_0: *mut uint8_t,
                                                amount: libc::c_int) {
    if amount < 8i32 {
    } else {
        __assert_fail(b"amount < 8\x00" as *const u8 as *const libc::c_char,
                      b"mceliece_cca2_encrypt.c\x00" as *const u8 as
                          *const libc::c_char, 78i32 as libc::c_uint,
                      (*::std::mem::transmute::<&[u8; 61],
                                                &[libc::c_char; 61]>(b"void char_right_bit_shift_n(const int, uint8_t *, const int)\x00")).as_ptr());
    }
    if amount == 0i32 { return }
    let mut j: libc::c_int = 0;
    let mut mask: uint8_t = 0;
    mask = (((0x1i32 as uint8_t as libc::c_int) << amount) - 1i32) as uint8_t;
    j = length - 1i32;
    while j > 0i32 {
        let ref mut fresh0 = *in_0.offset(j as isize);
        *fresh0 = (*fresh0 as libc::c_int >> amount) as uint8_t;
        let ref mut fresh1 = *in_0.offset(j as isize);
        *fresh1 =
            (*fresh1 as libc::c_int |
                 (*in_0.offset((j - 1i32) as isize) as libc::c_int &
                      mask as libc::c_int) << 8i32 - amount) as uint8_t;
        j -= 1
    }
    let ref mut fresh2 = *in_0.offset(j as isize);
    *fresh2 = (*fresh2 as libc::c_int >> amount) as uint8_t;
}
/*----------------------------------------------------------------------------*/
/*  shifts the input stream so that the bytewise pad is on the left before
 * conversion */
unsafe extern "C" fn bytestream_into_poly_seq(mut polySeq: *mut DIGIT,
                                              mut numPoly: libc::c_int,
                                              mut S: *mut libc::c_uchar,
                                              byteLenS: libc::c_ulong)
 -> libc::c_int {
    let mut padsize: libc::c_int =
        if (2i32 - 1i32) * 57899i32 % 8i32 != 0 {
            (8i32) - (2i32 - 1i32) * 57899i32 % 8i32
        } else { 0i32 };
    char_right_bit_shift_n(byteLenS as libc::c_int, S, padsize);
    if numPoly <= 0i32 || byteLenS <= 0i32 as libc::c_ulong ||
           byteLenS < ((numPoly * 57899i32 + 7i32) / 8i32) as libc::c_ulong {
        return 0i32
    }
    let mut slack_bits: libc::c_uint =
        byteLenS.wrapping_mul(8i32 as
                                  libc::c_ulong).wrapping_sub((numPoly *
                                                                   57899i32)
                                                                  as
                                                                  libc::c_ulong)
            as libc::c_uint;
    let mut bitCursor: libc::c_uint = slack_bits;
    let mut buffer: uint64_t = 0i32 as uint64_t;
    let mut polyIdx: libc::c_uint = 0i32 as libc::c_uint;
    while polyIdx < numPoly as libc::c_uint {
        let mut exponent: libc::c_uint = 0i32 as libc::c_uint;
        while exponent < 57899i32 as libc::c_uint {
            buffer = bitstream_read(S, 1i32 as libc::c_uint, &mut bitCursor);
            gf2x_set_coeff(&mut *polySeq.offset((((57899i32 + (8i32 << 3i32) -
                                                       1i32) / (8i32 << 3i32))
                                                     as
                                                     libc::c_uint).wrapping_mul(polyIdx)
                                                    as isize), exponent,
                           buffer);
            exponent = exponent.wrapping_add(1)
        }
        polyIdx = polyIdx.wrapping_add(1)
    }
    return 1i32;
}
/* *
 *
 * <mceliece_cca2_encrypt.h>
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
// return 0 i.e., insuccess, if bitLenPtx > (N0-1)*P + be - bc - bh or bitLenPtx <= 0
// end bytestream_into_poly_seq
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe extern "C" fn encrypt_Kobara_Imai(output: *mut libc::c_uchar,
                                             pk: *const publicKeyMcEliece_t,
                                             bytePtxLen: uint32_t,
                                             ptx: *const libc::c_uchar)
 -> libc::c_int {
    /* Generate PRNG pad */
    let mut secretSeed: [libc::c_uchar; 32] = [0; 32];
    let mut paddedSequenceLen: uint64_t = 0;
    let mut isPaddedSequenceOnlyKBits: libc::c_int = 0i32;
    if bytePtxLen as libc::c_ulong <=
           (((2i32 - 1i32) * 57899i32) as
                libc::c_ulong).wrapping_sub((8i32 as
                                                 libc::c_ulong).wrapping_mul((32i32
                                                                                  as
                                                                                  libc::c_ulong).wrapping_add(::std::mem::size_of::<uint64_t>()
                                                                                                                  as
                                                                                                                  libc::c_ulong))).wrapping_div(8i32
                                                                                                                                                    as
                                                                                                                                                    libc::c_ulong)
       {
        /*warning, in this case the padded sequence is exactly K bits*/
        paddedSequenceLen =
            (((2i32 - 1i32) * 57899i32 + 7i32) / 8i32) as uint64_t;
        isPaddedSequenceOnlyKBits = 1i32
    } else {
        paddedSequenceLen =
            (32i32 as
                 libc::c_ulong).wrapping_add(::std::mem::size_of::<uint64_t>()
                                                 as
                                                 libc::c_ulong).wrapping_add(bytePtxLen
                                                                                 as
                                                                                 libc::c_ulong)
    }
    let vla = paddedSequenceLen as usize;
    let mut prngSequence: Vec<libc::c_uchar> = ::std::vec::from_elem(0, vla);
    randombytes(secretSeed.as_mut_ptr(), 32i32 as libc::c_ulonglong);
    deterministic_random_byte_generator(prngSequence.as_mut_ptr(),
                                        (vla *
                                             ::std::mem::size_of::<libc::c_uchar>())
                                            as libc::c_ulong as
                                            libc::c_ulonglong,
                                        secretSeed.as_mut_ptr(),
                                        32i32 as libc::c_ulonglong);
    /*to avoid the use of additional memory, exploit the memory allocated for
    * the ciphertext to host the prng-padded ptx+const+len. */
    memset(output as *mut libc::c_void, 0i32,
           (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as libc::c_ulong);
    let mut correctlySizedBytePtxLen: uint64_t = bytePtxLen as uint64_t;
    memcpy(output.offset(32) as *mut libc::c_void,
           &mut correctlySizedBytePtxLen as *mut uint64_t as
               *const libc::c_void,
           ::std::mem::size_of::<uint64_t>() as libc::c_ulong);
    memcpy(output.offset(32).offset(::std::mem::size_of::<uint64_t>() as
                                        libc::c_ulong as isize) as
               *mut libc::c_void, ptx as *const libc::c_void,
           bytePtxLen as libc::c_ulong);
    let mut i: libc::c_int = 0i32;
    while (i as libc::c_ulong) < paddedSequenceLen {
        let ref mut fresh3 = *output.offset(i as isize);
        *fresh3 =
            (*fresh3 as libc::c_int ^
                 *prngSequence.as_mut_ptr().offset(i as isize) as libc::c_int)
                as libc::c_uchar;
        i += 1
    }
    if isPaddedSequenceOnlyKBits == 1i32 {
        let ref mut fresh4 =
            *output.offset(paddedSequenceLen.wrapping_sub(1i32 as
                                                              libc::c_ulong)
                               as isize);
        *fresh4 =
            (*fresh4 as libc::c_int &
                 !(0xffi32 as uint8_t as libc::c_int >>
                       (2i32 - 1i32) * 57899i32 % 8i32)) as libc::c_uchar
    }
    /* prepare buffer which will be translated in the information word */
    if (((2i32 - 1i32) * 57899i32 + 7i32) / 8i32) as libc::c_ulong ==
           (32i32 as
                libc::c_ulong).wrapping_add(::std::mem::size_of::<uint64_t>()
                                                as
                                                libc::c_ulong).wrapping_add((((2i32
                                                                                   -
                                                                                   1i32)
                                                                                  *
                                                                                  57899i32)
                                                                                 as
                                                                                 libc::c_ulong).wrapping_sub((8i32
                                                                                                                  as
                                                                                                                  libc::c_ulong).wrapping_mul((32i32
                                                                                                                                                   as
                                                                                                                                                   libc::c_ulong).wrapping_add(::std::mem::size_of::<uint64_t>()
                                                                                                                                                                                   as
                                                                                                                                                                                   libc::c_ulong))).wrapping_div(8i32
                                                                                                                                                                                                                     as
                                                                                                                                                                                                                     libc::c_ulong)).wrapping_add(1i32
                                                                                                                                                                                                                                                      as
                                                                                                                                                                                                                                                      libc::c_ulong)
       {
    } else {
        __assert_fail(b"(K+7)/8 == KOBARA_IMAI_CONSTANT_LENGTH_B+KI_LENGTH_FIELD_SIZE+MAX_BYTES_IN_IWORD+1\x00"
                          as *const u8 as *const libc::c_char,
                      b"mceliece_cca2_encrypt.c\x00" as *const u8 as
                          *const libc::c_char, 163i32 as libc::c_uint,
                      (*::std::mem::transmute::<&[u8; 124],
                                                &[libc::c_char; 124]>(b"int encrypt_Kobara_Imai(unsigned char *const, const publicKeyMcEliece_t *const, const uint32_t, const unsigned char *const)\x00")).as_ptr());
    }
    let mut iwordBuffer: [libc::c_uchar; 7238] = [0; 7238];
    memcpy(iwordBuffer.as_mut_ptr() as *mut libc::c_void,
           output as *const libc::c_void,
           ::std::mem::size_of::<[libc::c_uchar; 7238]>() as libc::c_ulong);
    /* transform into an information word poly sequence */
    let mut informationWord: [DIGIT; 905] =
        [0i32 as DIGIT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    bytestream_into_poly_seq(informationWord.as_mut_ptr(), 2i32 - 1i32,
                             iwordBuffer.as_mut_ptr(),
                             (((2i32 - 1i32) * 57899i32 + 7i32) / 8i32) as
                                 libc::c_ulong);
    /* prepare hash of padded sequence, before leftover is moved to its final place */
    let mut hashDigest: [libc::c_uchar; 48] =
        [0i32 as libc::c_uchar, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0]; // output
    sha3_384(output, paddedSequenceLen as libc::c_uint,
             hashDigest.as_mut_ptr());
    /* move leftover padded string (if present) onto its final position*/
    if bytePtxLen as libc::c_ulong >
           (((2i32 - 1i32) * 57899i32) as
                libc::c_ulong).wrapping_sub((8i32 as
                                                 libc::c_ulong).wrapping_mul((32i32
                                                                                  as
                                                                                  libc::c_ulong).wrapping_add(::std::mem::size_of::<uint64_t>()
                                                                                                                  as
                                                                                                                  libc::c_ulong))).wrapping_div(8i32
                                                                                                                                                    as
                                                                                                                                                    libc::c_ulong)
       {
        memmove(output.offset((2i32 *
                                   ((57899i32 + (8i32 << 3i32) - 1i32) /
                                        (8i32 << 3i32)) * 8i32) as isize) as
                    *mut libc::c_void,
                output.offset(::std::mem::size_of::<[libc::c_uchar; 7238]>()
                                  as libc::c_ulong as isize).offset(-1) as
                    *const libc::c_void,
                (bytePtxLen as
                     libc::c_ulong).wrapping_sub((((2i32 - 1i32) * 57899i32)
                                                      as
                                                      libc::c_ulong).wrapping_sub((8i32
                                                                                       as
                                                                                       libc::c_ulong).wrapping_mul((32i32
                                                                                                                        as
                                                                                                                        libc::c_ulong).wrapping_add(::std::mem::size_of::<uint64_t>()
                                                                                                                                                        as
                                                                                                                                                        libc::c_ulong))).wrapping_div(8i32
                                                                                                                                                                                          as
                                                                                                                                                                                          libc::c_ulong)));
        /*clear partial leakage from leftover string, only happens if K%8 !=0 */
        let mut initialLeftoverMask: uint8_t =
            (0xffi32 as uint8_t as libc::c_int >>
                 (2i32 - 1i32) * 57899i32 % 8i32) as uint8_t;
        let ref mut fresh5 =
            *output.offset((2i32 *
                                ((57899i32 + (8i32 << 3i32) - 1i32) /
                                     (8i32 << 3i32)) * 8i32) as isize);
        *fresh5 =
            (*fresh5 as libc::c_int & initialLeftoverMask as libc::c_int) as
                libc::c_uchar
    }
    /*prepare CWEnc input as zero extended seed ^ hash of */
    let mut cwEncInputBuffer: [libc::c_uchar; 1072] = [0; 1072];
    memcpy(cwEncInputBuffer.as_mut_ptr() as *mut libc::c_void,
           hashDigest.as_mut_ptr() as *const libc::c_void,
           48i32 as libc::c_ulong);
    let mut i_0: libc::c_uint = 0i32 as libc::c_uint;
    while i_0 < 32i32 as libc::c_uint {
        cwEncInputBuffer[i_0 as usize] =
            (cwEncInputBuffer[i_0 as usize] as libc::c_int ^
                 secretSeed[i_0 as usize] as libc::c_int) as libc::c_uchar;
        i_0 = i_0.wrapping_add(1)
    }
    let mut cwEncodedError: [DIGIT; 1810] = [0; 1810];
    /* continue drawing fresh randomness in case the constant weight encoding
    * fails */
    let mut binaryToConstantWeightOk: libc::c_int = 0i32;
    loop  {
        /* blank cwenc destination buffer */
        memset(cwEncodedError.as_mut_ptr() as *mut libc::c_void, 0i32,
               (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                    8i32) as libc::c_ulong);
        /* draw filler randomness for cwenc input from an independent random*/
        randombytes(secretSeed.as_mut_ptr(), 32i32 as libc::c_ulonglong);
        deterministic_random_byte_generator(cwEncInputBuffer.as_mut_ptr().offset(48),
                                            1024i32 as libc::c_ulonglong,
                                            secretSeed.as_mut_ptr(),
                                            32i32 as libc::c_ulonglong);
        binaryToConstantWeightOk =
            binary_to_constant_weight_approximate(cwEncodedError.as_mut_ptr(),
                                                  cwEncInputBuffer.as_mut_ptr(),
                                                  48i32 + 1024i32);
        if !(binaryToConstantWeightOk == 0i32) { break ; }
    }
    let mut codeword: [DIGIT; 1810] =
        [0i32 as DIGIT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    encrypt_McEliece(codeword.as_mut_ptr(), pk,
                     informationWord.as_mut_ptr() as *const DIGIT,
                     cwEncodedError.as_mut_ptr() as *const DIGIT);
    /* output composition looks like codeword || left bytepad leftover
    * and is thus long as ROUND_UP(leftover_bits,8)+
    * N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B */
   // the output byte stream is made of N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B bytes
    memcpy(output as *mut libc::c_void,
           codeword.as_mut_ptr() as *const libc::c_void,
           (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                8i32) as libc::c_ulong);
    return 1i32;
}
/*----------------------------------------------------------------------------*/
// end encrypt_Kobara_Imai
