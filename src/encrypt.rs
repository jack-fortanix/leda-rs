#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    #[no_mangle]
    fn key_gen_mceliece(pk: *mut publicKeyMcEliece_t,
                        sk: *mut privateKeyMcEliece_t);
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
    #[no_mangle]
    fn encrypt_Kobara_Imai(output: *mut libc::c_uchar,
                           pk: *const publicKeyMcEliece_t,
                           byteLenPtx: uint32_t, ptx: *const libc::c_uchar)
     -> libc::c_int;
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
    fn decrypt_Kobara_Imai(output: *mut libc::c_uchar,
                           byteOutputLength: *mut libc::c_ulonglong,
                           sk: *mut privateKeyMcEliece_t,
                           clen: libc::c_ulonglong, ctx: *const libc::c_uchar)
     -> libc::c_int;
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
pub struct privateKeyMcEliece_t {
    pub prng_seed: [libc::c_uchar; 32],
    pub rejections: uint8_t,
    pub secondIterThreshold: uint8_t,
}
#[derive ( Copy, Clone )]
#[repr(C)]
pub struct publicKeyMcEliece_t {
    pub Mtr: [DIGIT; 905],
}
/* *
 *
 * <encrypt.c>
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
pub unsafe extern "C" fn crypto_encrypt_keypair(mut pk: *mut libc::c_uchar,
                                                mut sk: *mut libc::c_uchar)
 -> libc::c_int {
    key_gen_mceliece(pk as *mut publicKeyMcEliece_t,
                     sk as *mut privateKeyMcEliece_t);
    return 0i32;
}
#[no_mangle]
pub unsafe extern "C" fn crypto_encrypt(mut c: *mut libc::c_uchar,
                                        mut clen: *mut libc::c_ulonglong,
                                        mut m: *const libc::c_uchar,
                                        mut mlen: libc::c_ulonglong,
                                        mut pk: *const libc::c_uchar)
 -> libc::c_int {
    /* NIST API provides a byte aligned message: all bytes are assumed full.
    * Therefore, if mlen exceeds
    * floor( (k-8*(KOBARA_IMAI_CONSTANT_LENGTH_B+sizeof(KI_LENGTH_FIELD_TYPE)))/8 )
    * defined as MAX_BYTES_IN_IWORD the message will not fit , together with
    * the constant and its length, in the information word
    *
    * The minimum ciphertext overhead is
    * NUM_DIGITS_GF2X_ELEMENT +
    * KOBARA_IMAI_CONSTANT_LENGTH_B +
    * sizeof(KI_LENGTH_FIELD_TYPE)  */
    if mlen <=
           (((2i32 - 1i32) * 57899i32) as
                libc::c_ulong).wrapping_sub((8i32 as
                                                 libc::c_ulong).wrapping_mul((32i32
                                                                                  as
                                                                                  libc::c_ulong).wrapping_add(::std::mem::size_of::<uint64_t>()
                                                                                                                  as
                                                                                                                  libc::c_ulong))).wrapping_div(8i32
                                                                                                                                                    as
                                                                                                                                                    libc::c_ulong)
               as libc::c_ulonglong {
        *clen =
            (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                 8i32) as libc::c_ulonglong
    } else {
        let mut leftover_len: libc::c_int =
            mlen.wrapping_sub((((2i32 - 1i32) * 57899i32) as
                                   libc::c_ulong).wrapping_sub((8i32 as
                                                                    libc::c_ulong).wrapping_mul((32i32
                                                                                                     as
                                                                                                     libc::c_ulong).wrapping_add(::std::mem::size_of::<uint64_t>()
                                                                                                                                     as
                                                                                                                                     libc::c_ulong))).wrapping_div(8i32
                                                                                                                                                                       as
                                                                                                                                                                       libc::c_ulong)
                                  as libc::c_ulonglong) as libc::c_int;
        *clen =
            (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                 8i32 + leftover_len) as libc::c_ulonglong
    }
    if encrypt_Kobara_Imai(c, pk as *mut publicKeyMcEliece_t,
                           mlen as uint32_t, m) == 1i32 {
        return 0i32
    }
    return -1i32;
}
#[no_mangle]
pub unsafe extern "C" fn crypto_encrypt_open(mut m: *mut libc::c_uchar,
                                             mut mlen: *mut libc::c_ulonglong,
                                             mut c: *const libc::c_uchar,
                                             mut clen: libc::c_ulonglong,
                                             mut sk: *const libc::c_uchar)
 -> libc::c_int {
    if decrypt_Kobara_Imai(m, mlen, sk as *mut privateKeyMcEliece_t, clen, c)
           == 1i32 {
        return 0i32
    }
    return -1i32;
}
