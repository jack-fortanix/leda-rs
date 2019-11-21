use crate::mceliece_cca2_decrypt::decrypt_Kobara_Imai;
use crate::mceliece_cca2_encrypt::encrypt_Kobara_Imai;
use crate::mceliece_keygen::key_gen_mceliece;
use crate::types::*;

pub fn leda_gen_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pk = vec![0u8; 7240];
    let mut sk = vec![0u8; 34];
    unsafe {
        let mut seed = vec![0u8; 32];
        crate::crypto::randombytes(&mut seed);

        key_gen_mceliece(
            &seed,
            &mut *(pk.as_mut_ptr() as *mut publicKeyMcEliece_t),
            &mut *(sk.as_mut_ptr() as *mut privateKeyMcEliece_t),
        );
    }

    Ok((sk, pk))
}

pub fn leda_encrypt(msg: &[u8], pk: &[u8]) -> Result<Vec<u8>> {
    unsafe { encrypt_Kobara_Imai(&*(pk.as_ptr() as *const publicKeyMcEliece_t), msg) }
}

pub fn leda_decrypt(ctext: &[u8], sk: &[u8]) -> Result<Vec<u8>> {
    unsafe { decrypt_Kobara_Imai(&*(sk.as_ptr() as *const privateKeyMcEliece_t), ctext) }
}
