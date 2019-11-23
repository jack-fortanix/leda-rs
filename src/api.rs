use crate::mceliece_cca2_decrypt::decrypt_Kobara_Imai;
use crate::mceliece_cca2_encrypt::encrypt_Kobara_Imai;
use crate::mceliece_keygen::key_gen_mceliece;
use crate::types::*;
use crate::consts::*;
use std::convert::TryInto;

fn load_leda_pk(pk: &[u8]) -> Result<LedaPublicKey> {
    if pk.len() != 8 * NUM_DIGITS_GF2X_ELEMENT {
        return Err(Error::InvalidKey);
    }

    let mut key = LedaPublicKey { Mtr: [0; NUM_DIGITS_GF2X_ELEMENT ] };

    for i in 0..NUM_DIGITS_GF2X_ELEMENT {
        let word : [u8; 8] = pk[(8*i)..(8*i+8)].try_into().expect("8 bytes");
        key.Mtr[i] = u64::from_le_bytes(word);
    }

    Ok(key)
}

fn load_leda_sk(sk: &[u8]) -> Result<LedaPrivateKey> {
    if sk.len() != 34 {
        return Err(Error::InvalidKey);
    }

    let mut key = LedaPrivateKey {
        prng_seed: [0u8; 32],
        rejections: 0,
        secondIterThreshold: 0
    };

    key.prng_seed.copy_from_slice(&sk[0..32]);
    key.rejections = sk[32];
    key.secondIterThreshold = sk[33];

    Ok(key)
}

pub fn leda_gen_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0u8; 7240];
    let mut sk = vec![0u8; 34];

    let mut seed = vec![0u8; 32];
    crate::crypto::randombytes(&mut seed);

    unsafe {
    key_gen_mceliece(
        &seed,
        &mut *(pk.as_mut_ptr() as *mut LedaPublicKey),
        &mut *(sk.as_mut_ptr() as *mut LedaPrivateKey),
    );
    }

    Ok((sk, pk))
}

pub fn leda_encrypt(msg: &[u8], pk: &[u8]) -> Result<Vec<u8>> {
    let pk = load_leda_pk(pk)?;
    unsafe { encrypt_Kobara_Imai(&pk, msg) }
}

pub fn leda_decrypt(ctext: &[u8], sk: &[u8]) -> Result<Vec<u8>> {
    let sk = load_leda_sk(sk)?;
    unsafe { decrypt_Kobara_Imai(&sk, ctext) }
}
