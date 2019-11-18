
use crate::types::*;

extern "C" {
    #[no_mangle]
    fn key_gen_mceliece(pk: *mut publicKeyMcEliece_t,
                        sk: *mut privateKeyMcEliece_t);

    // return 0 i.e., insuccess, if bitLenPtx > (N0-1)*P + be - bc - bh or bitLenPtx <= 0
    #[no_mangle]
    fn encrypt_Kobara_Imai(output: *mut u8,
                           pk: *const publicKeyMcEliece_t,
                           byteLenPtx: u32, ptx: *const u8)
     -> i32;

    #[no_mangle]
    fn decrypt_Kobara_Imai(output: *mut u8,
                           byteOutputLength: *mut u64,
                           sk: *mut privateKeyMcEliece_t,
                           clen: u64, ctx: *const u8)
     -> i32;
}

pub fn crypto_encrypt_keypair() -> Result<(Vec<u8>, Vec<u8>)> {

    let mut pk = vec![0u8; 7240];
    let mut sk = vec![0u8; 34];
    unsafe {
        key_gen_mceliece(pk.as_mut_ptr() as *mut publicKeyMcEliece_t,
                         sk.as_mut_ptr() as *mut privateKeyMcEliece_t);
    }

    Ok((sk,pk))
}

#[no_mangle]
pub unsafe extern "C" fn crypto_encrypt(mut c: *mut u8,
                                        mut clen: *mut u64,
                                        mut m: *const u8,
                                        mut mlen: u64,
                                        mut pk: *const u8)
 -> i32 {
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
                u64).wrapping_sub((8i32 as
                                                 u64).wrapping_mul((32i32
                                                                                  as
                                                                                  u64).wrapping_add(::std::mem::size_of::<u64>()
                                                                                                                  as
                                                                                                                  u64))).wrapping_div(8i32
                                                                                                                                                    as
                                                                                                                                                    u64)
               as u64 {
        *clen =
            (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                 8i32) as u64
    } else {
        let mut leftover_len: i32 =
            mlen.wrapping_sub((((2i32 - 1i32) * 57899i32) as
                                   u64).wrapping_sub((8i32 as
                                                                    u64).wrapping_mul((32i32
                                                                                                     as
                                                                                                     u64).wrapping_add(::std::mem::size_of::<u64>()
                                                                                                                                     as
                                                                                                                                     u64))).wrapping_div(8i32
                                                                                                                                                                       as
                                                                                                                                                                       u64)
                                  as u64) as i32;
        *clen =
            (2i32 * ((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) *
                 8i32 + leftover_len) as u64
    }
    if encrypt_Kobara_Imai(c, pk as *mut publicKeyMcEliece_t,
                           mlen as u32, m) == 1i32 {
        return 0i32
    }
    return -1i32;
}
#[no_mangle]
pub unsafe extern "C" fn crypto_encrypt_open(mut m: *mut u8,
                                             mut mlen: *mut u64,
                                             mut c: *const u8,
                                             mut clen: u64,
                                             mut sk: *const u8)
 -> i32 {
    if decrypt_Kobara_Imai(m, mlen, sk as *mut privateKeyMcEliece_t, clen, c)
           == 1i32 {
        return 0i32
    }
    return -1i32;
}
