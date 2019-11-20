use crate::types::*;
use sha3::Digest;
use std::convert::TryInto;

extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
}

pub fn sha3_384(input: &[u8]) -> Vec<u8> {
    let mut hasher = sha3::Sha3_384::new();
    hasher.input(input);
    hasher.result().as_slice().to_owned()
}

pub fn seedexpander_from_trng(trng_entropy: &[u8]) -> Result<AES_XOF_struct> {
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

pub fn seedexpander(ctx: &mut AES_XOF_struct, x: &mut [u8]) -> Result<()> {
    let mut output = vec![0u8; x.len() + 16];
    ctx.ctr.update(&x, &mut output)?;
    x.copy_from_slice(&output[0..x.len()]);
    return Ok(());
}

unsafe fn AES256_ECB(key: &[u8], ptx: &[u8], ctx: &mut [u8]) {
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

    //cipher.set_padding(mbedtls::cipher::raw::CipherPadding::None).unwrap();
    let cipher = cipher.set_key(&key).unwrap();

    cipher.encrypt(ptx, ctx).unwrap();
}

pub static mut DRBG_ctx: AES256_CTR_DRBG_struct = AES256_CTR_DRBG_struct {
    key: [0; 32],
    v: [0; 16],
    reseed_counter: 0,
};

pub unsafe fn randombytes_init(entropy_input: &[u8]) {
    DRBG_ctx.key.copy_from_slice(&[0u8; 32]);
    DRBG_ctx.v.copy_from_slice(&[0u8; 16]);
    DRBG_ctx.reseed_counter = 1;

    AES256_CTR_DRBG_Update(
        entropy_input.as_ptr(),
        &mut DRBG_ctx.key,
        &mut DRBG_ctx.v);
}

pub unsafe fn randombytes(x: &mut [u8]) {
    let mut xlen = x.len();

    let mut block: [u8; 16] = [0; 16];
    let mut i: usize = 0;
    while xlen > 0 {
        //increment v
        let mut j: i32 = 15;
        while j >= 0 {
            if DRBG_ctx.v[j as usize] == 0xff {
                DRBG_ctx.v[j as usize] = 0u8;
                j -= 1
            } else {
                DRBG_ctx.v[j as usize] = DRBG_ctx.v[j as usize].wrapping_add(1);
                break;
            }
        }
        AES256_ECB(
            &DRBG_ctx.key,
            &DRBG_ctx.v,
            &mut block
        );

        if xlen >= 16 {
            &x[i..(i+16)].copy_from_slice(&block);
            i += 16;
            xlen -= 16; // can't wrap
        } else {
            &x[i..(i+xlen)].copy_from_slice(&block[0..xlen]);
            xlen = 0
        }
    }
    AES256_CTR_DRBG_Update(::std::ptr::null(), &mut DRBG_ctx.key, &mut DRBG_ctx.v);
    DRBG_ctx.reseed_counter += 1;
}

unsafe fn AES256_CTR_DRBG_Update(provided_data: *const u8, key: &mut [u8], v: &mut [u8]) {
    let mut temp: [u8; 48] = [0; 48];
    for block in 0..3 {
        //increment v
        let mut j: i32 = 15i32;
        while j >= 0i32 {
            if v[j as usize] == 0xffu8 {
                v[j as usize] = 0x00u8;
                j -= 1
            } else {
                let ref mut fresh0 = v[j as usize];
                *fresh0 = (*fresh0).wrapping_add(1);
                break;
            }
        }
        AES256_ECB(key, v, &mut temp[16*block..(16*(block+1))]);
    }
    if !provided_data.is_null() {
        for i in 0..48 {
            temp[i] ^= *provided_data.offset(i as isize);
        }
    }
    key.copy_from_slice(&temp[0..32]);
    v.copy_from_slice(&temp[32..48]);
}

pub fn deterministic_random_byte_generator(seed: &[u8], olen: usize) -> Result<Vec<u8>> {
    let mut output = vec![0u8; olen];

    unsafe {
        x_deterministic_random_byte_generator(output.as_mut_ptr(), output.len() as u64,
                                              seed.as_ptr(), seed.len() as u64);
    }

    Ok(output)
}

pub unsafe fn x_deterministic_random_byte_generator(
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
        &mut ctx.key,
        &mut ctx.v);
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
        AES256_ECB(&ctx.key, &ctx.v, &mut block);
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
    AES256_CTR_DRBG_Update(::std::ptr::null(), &mut ctx.key, &mut ctx.v);
    ctx.reseed_counter += 1;
}
/* *****  End of NIST supplied code ****************/
// end deterministic_random_byte_generator

