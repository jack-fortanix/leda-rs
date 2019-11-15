
#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(const_raw_ptr_to_usize_cast, main)]
extern "C" {

    /* size in bytes of maximum overhead on the encrypted message */
    /*----------------------------------------------------------------------------*/
/*                                  PKC API                                   */
/*----------------------------------------------------------------------------*/
    /* Generates a keypair - pk is the public key and
 *                       sk is the secret key.
 */
    /* Encrypt - c is the ciphertext,
 *           m is the plaintext,
 *           pk is the public key
 */
    /* Decrypt - c is the ciphertext,
 *           m is the plaintext,
 *           sk is the secret key
 */
    #[no_mangle]
    fn crypto_encrypt_open(m: *mut libc::c_uchar,
                           mlen: *mut libc::c_ulonglong,
                           c: *const libc::c_uchar, clen: libc::c_ulonglong,
                           sk: *const libc::c_uchar) -> libc::c_int;
    #[no_mangle]
    fn crypto_encrypt(c: *mut libc::c_uchar, clen: *mut libc::c_ulonglong,
                      m: *const libc::c_uchar, mlen: libc::c_ulonglong,
                      pk: *const libc::c_uchar) -> libc::c_int;
    #[no_mangle]
    fn crypto_encrypt_keypair(pk: *mut libc::c_uchar, sk: *mut libc::c_uchar)
     -> libc::c_int;
}

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

use rustc_serialize::hex::ToHex;

pub type DIGIT = u64;

#[derive ( Copy, Clone )]
#[repr(C)]
pub struct privateKeyMcEliece_t {
    pub prng_seed: [libc::c_uchar; 32],
    pub rejections: u8,
    pub secondIterThreshold: u8,
}
#[derive ( Copy, Clone )]
#[repr(C)]
pub struct publicKeyMcEliece_t {
    pub Mtr: [DIGIT; 905],
}

pub fn dump(n: &str, b: &[u8], l: usize) {
    println!("{} = [{}] {}", n, l, (b[0..l].to_hex()));
}

pub fn kat() {
    let mut pk: [u8; 7240] = [0; 7240];
    let mut sk: [u8; 34] = [0; 34];
    unsafe { crypto_encrypt_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()); }
    dump("pk", &pk, 7240);
    dump("sk", &sk, 34);
    let ptext: [u8; 5] = [1, 2, 3, 4, 5];
    dump("ptext", &ptext, 5);
    let mut ctext = vec![0u8; 14485];
    let mut mlen: libc::c_ulonglong =
        ::std::mem::size_of::<[u8; 5]>() as libc::c_ulong as
            libc::c_ulonglong;
    let mut clen: libc::c_ulonglong = 0;
    unsafe { crypto_encrypt(ctext.as_mut_ptr(), &mut clen, ptext.as_ptr(), mlen,
                            pk.as_mut_ptr()); }
    dump("ctext", &ctext, clen as usize);
    let mut decr: [u8; 16] =
        [0i32 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut dlen: libc::c_ulonglong =
        ::std::mem::size_of::<[u8; 16]>() as libc::c_ulong as
            libc::c_ulonglong;
    unsafe { crypto_encrypt_open(decr.as_mut_ptr(), &mut dlen, ctext.as_mut_ptr(),
                                 clen, sk.as_mut_ptr()); }
    dump("recovered", &decr, dlen as usize);
}


mod aes256;
mod bf_decoding;
mod constant_weight_codec;
mod dfr_test;
mod djbsort;
mod encrypt;
mod gf2x_arith_mod_xPplusOne;
mod gf2x_arith;
mod H_Q_matrices_generation;
mod marshalling;
mod mceliece_cca2_decrypt;
mod mceliece_cca2_encrypt;
mod mceliece_keygen;
mod rng;
mod sha3_fallback;

fn main() {
    unsafe { kat(); }
}
