use crate::types::*;
use sha3::Digest;

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
    let ctr: [u8; 16] = [
        0, 0, 0, 0, 0, 0, 0, 0, mlb[0], mlb[1], mlb[2], mlb[3], 0, 0, 0, 0,
    ];

    let mut cipher = Box::new(mbedtls::cipher::raw::Cipher::setup(
        mbedtls::cipher::raw::CipherId::Aes,
        mbedtls::cipher::raw::CipherMode::CTR,
        256,
    )?);

    cipher.set_key(mbedtls::cipher::raw::Operation::Encrypt, &trng_entropy)?;

    cipher.set_iv(&ctr)?;

    let ctx = AES_XOF_struct { ctr: cipher };

    Ok(ctx)
}

pub fn seedexpander(ctx: &mut AES_XOF_struct, x: &mut [u8]) -> Result<()> {
    let mut output = vec![0u8; x.len() + 16];
    ctx.ctr.update(&x, &mut output)?;
    x.copy_from_slice(&output[0..x.len()]);
    return Ok(());
}

fn AES256_ECB(key: &[u8], ptx: &[u8], ctx: &mut [u8]) {
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

pub fn randombytes_ctx(ctx: &mut AES256_CTR_DRBG_struct, x: &mut [u8]) {
    let mut xlen = x.len();

    let mut block: [u8; 16] = [0; 16];
    let mut i: usize = 0;
    while xlen > 0 {
        //increment v
        for j in (0..16).rev() {
            if ctx.v[j] == 0xff {
                ctx.v[j] = 0x00;
            } else {
                ctx.v[j] += 1;
                break;
            }
        }
        AES256_ECB(&ctx.key, &ctx.v, &mut block);

        if xlen >= 16 {
            &x[i..(i + 16)].copy_from_slice(&block);
            i += 16;
            xlen -= 16; // can't wrap
        } else {
            &x[i..(i + xlen)].copy_from_slice(&block[0..xlen]);
            xlen = 0
        }
    }
    AES256_CTR_DRBG_Update(&[], &mut ctx.key, &mut ctx.v);
    ctx.reseed_counter += 1;
}

pub fn randombytes(x: &mut [u8]) {
    unsafe { randombytes_ctx(&mut DRBG_ctx, x) }
}

pub static mut DRBG_ctx: AES256_CTR_DRBG_struct = AES256_CTR_DRBG_struct {
    key: [0; 32],
    v: [0; 16],
    reseed_counter: 0,
};

pub fn randombytes_init(entropy_input: &[u8]) {
    unsafe {
        DRBG_ctx.key.copy_from_slice(&[0u8; 32]);
        DRBG_ctx.v.copy_from_slice(&[0u8; 16]);
        DRBG_ctx.reseed_counter = 1;
        AES256_CTR_DRBG_Update(&entropy_input, &mut DRBG_ctx.key, &mut DRBG_ctx.v);
    }
}

fn AES256_CTR_DRBG_Update(provided_data: &[u8], key: &mut [u8], v: &mut [u8]) {
    let mut temp: [u8; 48] = [0; 48];
    for block in 0..3 {
        //increment v
        for j in (0..16).rev() {
            if v[j] == 0xff {
                v[j] = 0x00;
            } else {
                v[j] += 1;
                break;
            }
        }
        AES256_ECB(key, v, &mut temp[16 * block..(16 * (block + 1))]);
    }
    for i in 0..provided_data.len() {
        temp[i] ^= provided_data[i];
    }
    key.copy_from_slice(&temp[0..32]);
    v.copy_from_slice(&temp[32..48]);
}

pub fn deterministic_random_byte_generator(seed: &[u8], olen: usize) -> Result<Vec<u8>> {
    let mut output = vec![0u8; olen];
    drbg(&mut output, seed)?;
    Ok(output)
}

pub fn drbg(output: &mut [u8], seed: &[u8]) -> Result<()> {
    /* DRBG context initialization */
    let mut ctx: AES256_CTR_DRBG_struct = AES256_CTR_DRBG_struct {
        key: [0; 32],
        v: [0; 16],
        reseed_counter: 0,
    };
    AES256_CTR_DRBG_Update(&seed, &mut ctx.key, &mut ctx.v);
    ctx.reseed_counter = 1i32;

    randombytes_ctx(&mut ctx, output);

    Ok(())
}
