use crate::types::*;
use sha3::Digest;

extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64)
     -> *mut libc::c_void;
}

/* *
  *  Function to compute SHA3-384 on the input message.
  *  The output length is fixed to 48 bytes.
  */

pub fn sha3_384(mut input: *const u8,
                mut inputByteLen: u32,
                mut output: *mut u8) {
    let mut hasher = sha3::Sha3_384::new();

    unsafe {
        let slice = std::slice::from_raw_parts(input, inputByteLen as usize);
        hasher.input(slice);
        let result = hasher.result();
        std::ptr::copy(result.as_ptr(), output, result.len());
    }
}

/*----------------------------------------------------------------------------*/
/* Initializes a dedicated DRBG context to avoid conflicts with the global one
 * declared by NIST for KATs. Provides the output of the DRBG in output, for
 * the given length */
/*----------------------------------------------------------------------------*/
/*              end PSEUDO-RAND GENERATOR ROUTINES for rnd.h                  */
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub static mut DRBG_ctx: AES256_CTR_DRBG_struct =
    AES256_CTR_DRBG_struct{key: [0; 32], v: [0; 16], reseed_counter: 0,};
/*
 seedexpander_init()
 ctx            - stores the current state of an instance of the seed expander
 seed           - a 32 byte random value
 diversifier    - an 8 byte diversifier
 maxlen         - maximum number of bytes (less than 2**32) generated under this seed and diversifier
 */
#[no_mangle]
pub unsafe fn seedexpander_init(mut ctx: *mut AES_XOF_struct,
                                           seed: *const u8,
                                           diversifier: *const u8,
                                           mut maxlen: u64)
 -> i32 {
    if maxlen >= 0x100000000i64 as u64 { return -1i32 }
    (*ctx).length_remaining = maxlen;
    memset((*ctx).key.as_mut_ptr() as *mut libc::c_void, 0i32,
           32i32 as u64);
    let mut max_accessible_seed_len: i32 =
        if 32i32 < 32i32 { 32i32 } else { 32i32 };
    memcpy((*ctx).key.as_mut_ptr() as *mut libc::c_void,
           seed as *const libc::c_void,
           max_accessible_seed_len as u64);
    memcpy((*ctx).ctr.as_mut_ptr() as *mut libc::c_void,
           diversifier as *const libc::c_void, 8i32 as u64);
    (*ctx).ctr[11] =
        maxlen.wrapping_rem(256i32 as u64) as u8;
    maxlen >>= 8i32;
    (*ctx).ctr[10] =
        maxlen.wrapping_rem(256i32 as u64) as u8;
    maxlen >>= 8i32;
    (*ctx).ctr[9] =
        maxlen.wrapping_rem(256i32 as u64) as u8;
    maxlen >>= 8i32;
    (*ctx).ctr[8] =
        maxlen.wrapping_rem(256i32 as u64) as u8;
    memset((*ctx).ctr.as_mut_ptr().offset(12) as *mut libc::c_void, 0i32,
           4i32 as u64);
    (*ctx).buffer_pos = 16i32;
    memset((*ctx).buffer.as_mut_ptr() as *mut libc::c_void, 0i32,
           16i32 as u64);
    return 0i32;
}
/*
 seedexpander()
    ctx  - stores the current state of an instance of the seed expander
    x    - returns the XOF data
    xlen - number of bytes to return
 */
#[no_mangle]
pub unsafe fn seedexpander(mut ctx: *mut AES_XOF_struct,
                                      mut x: *mut u8,
                                      mut xlen: u64)
 -> i32 {
    let mut offset: u64 = 0;
    if x.is_null() { return -2i32 }
    if xlen >= (*ctx).length_remaining { return -3i32 }
    (*ctx).length_remaining = (*ctx).length_remaining.wrapping_sub(xlen);

    while xlen > 0i32 as u64 {
        if xlen <= (16i32 - (*ctx).buffer_pos) as u64 {
            // buffer has what we need
            memcpy(x.offset(offset as isize) as *mut libc::c_void,
                   (*ctx).buffer.as_mut_ptr().offset((*ctx).buffer_pos as
                                                         isize) as
                       *const libc::c_void, xlen);
            (*ctx).buffer_pos =
                ((*ctx).buffer_pos as u64).wrapping_add(xlen) as
                    i32 as i32;
            return 0i32
        }
        // take what's in the buffer
        memcpy(x.offset(offset as isize) as *mut libc::c_void,
               (*ctx).buffer.as_mut_ptr().offset((*ctx).buffer_pos as isize)
                   as *const libc::c_void,
               (16i32 - (*ctx).buffer_pos) as u64);
        xlen =
            xlen.wrapping_sub((16i32 - (*ctx).buffer_pos) as u64);
        offset =
            offset.wrapping_add((16i32 - (*ctx).buffer_pos) as u64);
        AES256_ECB((*ctx).key.as_mut_ptr(), (*ctx).ctr.as_mut_ptr(),
                   (*ctx).buffer.as_mut_ptr());
        (*ctx).buffer_pos = 0i32;
        //increment the counter
        let mut i: i32 = 15i32;
        while i >= 12i32 {
            if (*ctx).ctr[i as usize] as i32 == 0xffi32 {
                (*ctx).ctr[i as usize] = 0i32 as u8;
                i -= 1
            } else {
                (*ctx).ctr[i as usize] =
                    (*ctx).ctr[i as usize].wrapping_add(1);
                break ;
            }
        }
    }
    return 0i32;
}
// Use whatever AES implementation you have. This uses AES from openSSL library
//    key - 256-bit AES key
//    ptx - a 128-bit plaintext value
//    ctx - a 128-bit ciphertext value

unsafe fn AES256_ECB(key: *const u8,
                     mut ptx: *mut u8,
                     mut ctx: *mut u8) {

    let mut cipher = mbedtls::cipher::Cipher::<mbedtls::cipher::Encryption, mbedtls::cipher::TraditionalNoIv, _>::new(
        mbedtls::cipher::raw::CipherId::Aes,
        mbedtls::cipher::raw::CipherMode::ECB,
        256).unwrap();

    let key = std::slice::from_raw_parts(key, 32);

    //cipher.set_padding(mbedtls::cipher::raw::CipherPadding::None).unwrap();
    let cipher = cipher.set_key(&key).unwrap();

    let inp = std::slice::from_raw_parts(ptx, 16);
    let outp = std::slice::from_raw_parts_mut(ctx, 16);

    cipher.encrypt(&inp, outp).unwrap();
}
#[no_mangle]
pub unsafe fn randombytes_init(entropy_input: *const u8,
                                          personalization_string: *const u8) {
    let mut seed_material: [u8; 48] = [0; 48];
    memcpy(seed_material.as_mut_ptr() as *mut libc::c_void,
           entropy_input as *const libc::c_void, 48i32 as u64);
    if !personalization_string.is_null() {
        let mut i: i32 = 0i32;
        while i < 48i32 {
            seed_material[i as usize] =
                (seed_material[i as usize] as i32 ^
                     *personalization_string.offset(i as isize) as
                         i32) as u8;
            i += 1
        }
    }
    memset(DRBG_ctx.key.as_mut_ptr() as *mut libc::c_void, 0i32,
           32i32 as u64);
    memset(DRBG_ctx.v.as_mut_ptr() as *mut libc::c_void, 0i32,
           16i32 as u64);
    AES256_CTR_DRBG_Update(seed_material.as_mut_ptr(),
                           DRBG_ctx.key.as_mut_ptr(),
                           DRBG_ctx.v.as_mut_ptr());
    DRBG_ctx.reseed_counter = 1i32;
}
#[no_mangle]
pub unsafe fn randombytes(mut x: *mut u8,
                                     mut xlen: u64)
 -> i32 {
    let mut block: [u8; 16] = [0; 16];
    let mut i: i32 = 0i32;
    while xlen > 0i32 as u64 {
        //increment v
        let mut j: i32 = 15i32;
        while j >= 0i32 {
            if DRBG_ctx.v[j as usize] as i32 == 0xffi32 {
                DRBG_ctx.v[j as usize] = 0i32 as u8;
                j -= 1
            } else {
                DRBG_ctx.v[j as usize] =
                    DRBG_ctx.v[j as usize].wrapping_add(1);
                break ;
            }
        }
        AES256_ECB(DRBG_ctx.key.as_mut_ptr(), DRBG_ctx.v.as_mut_ptr(),
                   block.as_mut_ptr());
        if xlen > 15i32 as u64 {
            memcpy(x.offset(i as isize) as *mut libc::c_void,
                   block.as_mut_ptr() as *const libc::c_void,
                   16i32 as u64);
            i += 16i32;
            xlen = xlen.wrapping_sub(16i32 as u64)
        } else {
            memcpy(x.offset(i as isize) as *mut libc::c_void,
                   block.as_mut_ptr() as *const libc::c_void,
                   xlen as u64);
            xlen = 0i32 as u64
        }
    }
    AES256_CTR_DRBG_Update(0 as *mut u8, DRBG_ctx.key.as_mut_ptr(),
                           DRBG_ctx.v.as_mut_ptr());
    DRBG_ctx.reseed_counter += 1;
    return 0i32;
}

unsafe fn AES256_CTR_DRBG_Update(mut provided_data: *mut u8,
                                 mut key: *mut u8,
                                 mut v: *mut u8) {
    let mut temp: [u8; 48] = [0; 48];
    let mut i: i32 = 0i32;
    while i < 3i32 {
        //increment v
        let mut j: i32 = 15i32;
        while j >= 0i32 {
            if *v.offset(j as isize) as i32 == 0xffi32 {
                *v.offset(j as isize) = 0i32 as u8;
                j -= 1
            } else {
                let ref mut fresh0 = *v.offset(j as isize);
                *fresh0 = (*fresh0).wrapping_add(1);
                break ;
            }
        }
        AES256_ECB(key, v, temp.as_mut_ptr().offset((16i32 * i) as isize));
        i += 1
    }
    if !provided_data.is_null() {
        let mut i_0: i32 = 0i32;
        while i_0 < 48i32 {
            temp[i_0 as usize] =
                (temp[i_0 as usize] as i32 ^
                     *provided_data.offset(i_0 as isize) as i32) as
                    u8;
            i_0 += 1
        }
    }
    memcpy(key as *mut libc::c_void, temp.as_mut_ptr() as *const libc::c_void,
           32i32 as u64);
    memcpy(v as *mut libc::c_void,
           temp.as_mut_ptr().offset(32) as *const libc::c_void,
           16i32 as u64);
}
#[no_mangle]
pub unsafe fn deterministic_random_byte_generator(output: *mut u8,
                                                             output_len: u64,
                                                             seed: *const u8,
                                                             seed_length: u64) {
    /* DRBG context initialization */
    let mut ctx: AES256_CTR_DRBG_struct =
        AES256_CTR_DRBG_struct{key: [0; 32], v: [0; 16], reseed_counter: 0,};
    let mut seed_material: [u8; 48] = [0; 48];
    memset(seed_material.as_mut_ptr() as *mut libc::c_void, 0i32,
           48i32 as u64);
    memcpy(seed_material.as_mut_ptr() as *mut libc::c_void,
           seed as *const libc::c_void, seed_length as u64);
    memset(ctx.key.as_mut_ptr() as *mut libc::c_void, 0i32,
           32i32 as u64);
    memset(ctx.v.as_mut_ptr() as *mut libc::c_void, 0i32,
           16i32 as u64);
    AES256_CTR_DRBG_Update(seed_material.as_mut_ptr(), ctx.key.as_mut_ptr(),
                           ctx.v.as_mut_ptr());
    ctx.reseed_counter = 1i32;
    /* Actual DRBG computation as from the randombytes(unsigned char *x,
    * unsigned long long xlen) from NIST */
    let mut block: [u8; 16] = [0; 16];
    let mut i: i32 = 0i32;
    let mut length_remaining: i32 = output_len as i32;
    while length_remaining > 0i32 {
        //increment v
        let mut j: i32 = 15i32;
        while j >= 0i32 {
            if ctx.v[j as usize] as i32 == 0xffi32 {
                ctx.v[j as usize] = 0i32 as u8;
                j -= 1
            } else {
                ctx.v[j as usize] = ctx.v[j as usize].wrapping_add(1);
                break ;
            }
        }
        AES256_ECB(ctx.key.as_mut_ptr(), ctx.v.as_mut_ptr(),
                   block.as_mut_ptr());
        if length_remaining > 15i32 {
            memcpy(output.offset(i as isize) as *mut libc::c_void,
                   block.as_mut_ptr() as *const libc::c_void,
                   16i32 as u64);
            i += 16i32;
            length_remaining -= 16i32
        } else {
            memcpy(output.offset(i as isize) as *mut libc::c_void,
                   block.as_mut_ptr() as *const libc::c_void,
                   length_remaining as u64);
            length_remaining = 0i32
        }
    }
    AES256_CTR_DRBG_Update(0 as *mut u8, ctx.key.as_mut_ptr(),
                           ctx.v.as_mut_ptr());
    ctx.reseed_counter += 1;
}
/* *****  End of NIST supplied code ****************/
// end deterministic_random_byte_generator
#[no_mangle]
pub unsafe fn seedexpander_from_trng(mut ctx: *mut AES_XOF_struct,
                                                trng_entropy: *const u8)
 /* TRNG_BYTE_LENGTH wide buffer */
 {
    /*the NIST seedexpander will however access 32B from this buffer */
    let mut prng_buffer_size: u32 =
        if 32i32 < 32i32 { 32i32 } else { 32i32 } as u32;
    let mut prng_buffer: [u8; 32] =
        [0i32 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    memcpy(prng_buffer.as_mut_ptr() as *mut libc::c_void,
           trng_entropy as *const libc::c_void,
           if (32i32 as u32) < prng_buffer_size {
               32i32 as u32
           } else { prng_buffer_size } as u64);
    /* if extra entropy is provided, add it to the diversifier */
    let mut diversifier: [u8; 8] =
        [0i32 as u8, 0i32 as u8, 0i32 as u8,
         0i32 as u8, 0i32 as u8, 0i32 as u8,
         0i32 as u8, 0i32 as u8];
    /* the required seed expansion will be quite small, set the max number of
    * bytes conservatively to 10 MiB*/
    seedexpander_init(ctx, prng_buffer.as_mut_ptr(), diversifier.as_mut_ptr(),
                      (10i32 * 1024i32 * 1024i32) as u64);
}
