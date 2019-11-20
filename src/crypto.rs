use crate::types::*;
use sha3::Digest;
use std::convert::TryInto;

extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
}

/* *
 *  Function to compute SHA3-384 on the input message.
 *  The output length is fixed to 48 bytes.
 */

pub fn sha3_384(input: *const u8, inputByteLen: u32, output: *mut u8) {
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

pub unsafe fn seedexpander_from_trng(trng_entropy: &[u8]) -> Result<AES_XOF_struct> {
    if trng_entropy.len() != 32 {
        return Err(Error::Custom(
            "Unexpected seed input size to seed expander".into(),
        ));
    }

    /* the required seed expansion will be quite small, set the max number of
     * bytes conservatively to 10 MiB*/
    let maxlen = (10 * 1024 * 1024) as u32;

    let mlb = maxlen.to_be_bytes();
    let ctr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, mlb[0], mlb[1], mlb[2], mlb[3], 0, 0, 0, 0];

    let mut cipher = Box::new(mbedtls::cipher::raw::Cipher::setup(
        mbedtls::cipher::raw::CipherId::Aes,
        mbedtls::cipher::raw::CipherMode::CTR,
        256)?);

    cipher.set_key(mbedtls::cipher::raw::Operation::Encrypt, &trng_entropy)?;

    cipher.set_iv(&ctr)?;

    let ctx = AES_XOF_struct {
        ctr: cipher,
    };

    Ok(ctx)
}

pub unsafe fn seedexpander(ctx: &mut AES_XOF_struct, x: &mut [u8]) -> Result<()> {

    let mut output = vec![0u8; x.len() + 16];

    ctx.ctr.update(&x, &mut output)?;

    x.copy_from_slice(&output[0..x.len()]);

    return Ok(());
}
// Use whatever AES implementation you have. This uses AES from openSSL library
//    key - 256-bit AES key
//    ptx - a 128-bit plaintext value
//    ctx - a 128-bit ciphertext value

unsafe fn AES256_ECB(key: *const u8, ptx: *const u8, ctx: *mut u8) {
    let cipher = mbedtls::cipher::Cipher::<
        mbedtls::cipher::Encryption,
        mbedtls::cipher::TraditionalNoIv,
        _,
    >::new(
        mbedtls::cipher::raw::CipherId::Aes,
        mbedtls::cipher::raw::CipherMode::ECB,
        256,
    )
    .unwrap();

    let key = std::slice::from_raw_parts(key, 32);

    //cipher.set_padding(mbedtls::cipher::raw::CipherPadding::None).unwrap();
    let cipher = cipher.set_key(&key).unwrap();

    let inp = std::slice::from_raw_parts(ptx, 16);
    let outp = std::slice::from_raw_parts_mut(ctx, 16);

    cipher.encrypt(&inp, outp).unwrap();
}

pub static mut DRBG_ctx: AES256_CTR_DRBG_struct = AES256_CTR_DRBG_struct {
    key: [0; 32],
    v: [0; 16],
    reseed_counter: 0,
};

pub unsafe fn randombytes_init(entropy_input: *const u8) {
    let mut seed_material: [u8; 48] = [0; 48];
    memcpy(
        seed_material.as_mut_ptr() as *mut libc::c_void,
        entropy_input as *const libc::c_void,
        48i32 as u64,
    );
    memset(DRBG_ctx.key.as_mut_ptr() as *mut libc::c_void, 0, 32);
    memset(
        DRBG_ctx.v.as_mut_ptr() as *mut libc::c_void,
        0i32,
        16,
    );
    AES256_CTR_DRBG_Update(
        seed_material.as_ptr(),
        DRBG_ctx.key.as_mut_ptr(),
        DRBG_ctx.v.as_mut_ptr(),
    );
    DRBG_ctx.reseed_counter = 1i32;
}

pub unsafe fn randombytes(x: *mut u8, mut xlen: u64) -> i32 {
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
                DRBG_ctx.v[j as usize] = DRBG_ctx.v[j as usize].wrapping_add(1);
                break;
            }
        }
        AES256_ECB(
            DRBG_ctx.key.as_ptr(),
            DRBG_ctx.v.as_ptr(),
            block.as_mut_ptr(),
        );
        if xlen > 15i32 as u64 {
            memcpy(
                x.offset(i as isize) as *mut libc::c_void,
                block.as_mut_ptr() as *const libc::c_void,
                16i32 as u64,
            );
            i += 16i32;
            xlen = xlen.wrapping_sub(16i32 as u64)
        } else {
            memcpy(
                x.offset(i as isize) as *mut libc::c_void,
                block.as_mut_ptr() as *const libc::c_void,
                xlen as u64,
            );
            xlen = 0i32 as u64
        }
    }
    AES256_CTR_DRBG_Update(
        ::std::ptr::null(),
        DRBG_ctx.key.as_mut_ptr(),
        DRBG_ctx.v.as_mut_ptr(),
    );
    DRBG_ctx.reseed_counter += 1;
    return 0i32;
}

unsafe fn AES256_CTR_DRBG_Update(provided_data: *const u8, key: *mut u8, v: *mut u8) {
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
                break;
            }
        }
        AES256_ECB(key, v, temp.as_mut_ptr().offset((16i32 * i) as isize));
        i += 1
    }
    if !provided_data.is_null() {
        let mut i_0: i32 = 0i32;
        while i_0 < 48i32 {
            temp[i_0 as usize] =
                (temp[i_0 as usize] as i32 ^ *provided_data.offset(i_0 as isize) as i32) as u8;
            i_0 += 1
        }
    }
    memcpy(
        key as *mut libc::c_void,
        temp.as_mut_ptr() as *const libc::c_void,
        32i32 as u64,
    );
    memcpy(
        v as *mut libc::c_void,
        temp.as_mut_ptr().offset(32) as *const libc::c_void,
        16i32 as u64,
    );
}

pub unsafe fn deterministic_random_byte_generator(
    output: *mut u8,
    output_len: u64,
    seed: *const u8,
    seed_length: u64) {
    /* DRBG context initialization */
    let mut ctx: AES256_CTR_DRBG_struct = AES256_CTR_DRBG_struct {
        key: [0; 32],
        v: [0; 16],
        reseed_counter: 0,
    };
    let mut seed_material: [u8; 48] = [0; 48];
    memcpy(
        seed_material.as_mut_ptr() as *mut libc::c_void,
        seed as *const libc::c_void,
        seed_length as u64,
    );
    AES256_CTR_DRBG_Update(
        seed_material.as_ptr(),
        ctx.key.as_mut_ptr(),
        ctx.v.as_mut_ptr(),
    );
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
                break;
            }
        }
        AES256_ECB(ctx.key.as_ptr(), ctx.v.as_ptr(), block.as_mut_ptr());
        if length_remaining > 15i32 {
            memcpy(
                output.offset(i as isize) as *mut libc::c_void,
                block.as_mut_ptr() as *const libc::c_void,
                16i32 as u64,
            );
            i += 16i32;
            length_remaining -= 16i32
        } else {
            memcpy(
                output.offset(i as isize) as *mut libc::c_void,
                block.as_mut_ptr() as *const libc::c_void,
                length_remaining as u64,
            );
            length_remaining = 0i32
        }
    }
    AES256_CTR_DRBG_Update(::std::ptr::null(), ctx.key.as_mut_ptr(), ctx.v.as_mut_ptr());
    ctx.reseed_counter += 1;
}
/* *****  End of NIST supplied code ****************/
// end deterministic_random_byte_generator

