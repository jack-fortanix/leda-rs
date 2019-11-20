use crate::consts::*;
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

    let clen = if msg.len() <= MAX_BYTES_IN_IWORD {
        N0 * NUM_DIGITS_GF2X_ELEMENT * DIGIT_SIZE_B
    } else {
        let leftover_len = msg.len() - MAX_BYTES_IN_IWORD;
        N0 * NUM_DIGITS_GF2X_ELEMENT * DIGIT_SIZE_B + leftover_len
    };

    let mut ctext = vec![0u8; clen];

    unsafe {
        encrypt_Kobara_Imai(
            ctext.as_mut_ptr(),
            pk.as_ptr() as *mut publicKeyMcEliece_t,
            msg,
        )?;

        return Ok(ctext);
    }
}

pub fn leda_decrypt(ctext: &[u8], sk: &[u8]) -> Result<Vec<u8>> {
    let r = unsafe {
        decrypt_Kobara_Imai(
            sk.as_ptr() as *const privateKeyMcEliece_t,
            ctext.len() as u64,
            ctext.as_ptr(),
        )
    };
    Ok(r)
}
