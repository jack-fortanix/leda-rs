use crate::consts::*;
use crate::mceliece_cca2_decrypt::decrypt_Kobara_Imai;
use crate::mceliece_cca2_encrypt::encrypt_Kobara_Imai;
use crate::mceliece_keygen::key_gen_mceliece;
use crate::types::*;
use std::convert::TryInto;

fn leda_decode_pk(pk: &[u8]) -> Result<LedaPublicKey> {
    if pk.len() != 8 * NUM_DIGITS_GF2X_ELEMENT {
        return Err(Error::InvalidKey);
    }

    let mut key = LedaPublicKey {
        Mtr: [0; NUM_DIGITS_GF2X_ELEMENT],
    };

    for i in 0..NUM_DIGITS_GF2X_ELEMENT {
        let word: [u8; 8] = pk[(8 * i)..(8 * i + 8)].try_into().expect("8 bytes");
        key.Mtr[i] = u64::from_le_bytes(word);
    }

    Ok(key)
}

fn leda_encode_pk(pk: &LedaPublicKey) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 8 * NUM_DIGITS_GF2X_ELEMENT];

    for i in 0..NUM_DIGITS_GF2X_ELEMENT {
        let word: [u8; 8] = pk.Mtr[i].to_le_bytes();
        buf[(8 * i)..(8 * i + 8)].copy_from_slice(&word);
    }

    Ok(buf)
}

fn leda_encode_sk(sk: &LedaPrivateKey) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 34];

    buf[0..32].copy_from_slice(&sk.prng_seed);
    buf[32] = sk.rejections;
    buf[33] = sk.secondIterThreshold;

    Ok(buf)
}

fn leda_decode_sk(sk: &[u8]) -> Result<LedaPrivateKey> {
    if sk.len() != 34 {
        return Err(Error::InvalidKey);
    }

    let mut key = LedaPrivateKey {
        prng_seed: [0u8; 32],
        rejections: 0,
        secondIterThreshold: 0,
    };

    key.prng_seed.copy_from_slice(&sk[0..32]);
    key.rejections = sk[32];
    key.secondIterThreshold = sk[33];

    Ok(key)
}

pub fn leda_gen_keypair(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if seed.len() != 32 {
        return Err(Error::Custom("Leda seed must be exactly 32 bytes".into()));
    }

    let (pk, sk) = key_gen_mceliece(seed)?;

    Ok((leda_encode_sk(&sk)?, leda_encode_pk(&pk)?))
}

pub fn leda_encrypt(msg: &[u8], pk: &[u8], rng: impl FnMut(&mut [u8])) -> Result<Vec<u8>> {
    let pk = leda_decode_pk(pk)?;
    encrypt_Kobara_Imai(&pk, msg, rng)
}

pub fn leda_decrypt(ctext: &[u8], sk: &[u8]) -> Result<Vec<u8>> {
    let sk = leda_decode_sk(sk)?;
    decrypt_Kobara_Imai(&sk, ctext)
}
