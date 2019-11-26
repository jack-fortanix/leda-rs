use crate::constant_weight_codec::{binary_to_constant_weight_approximate, bitstream_read};
use crate::crypto::*;
use crate::gf2x_arith::*;
use crate::gf2x_arith_mod_xPplusOne::*;
use crate::types::*;
use crate::consts::*;

extern "C" {
    #[no_mangle]
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
}

fn encrypt_McEliece(pk: &LedaPublicKey, ptx: &[DIGIT], err: &[DIGIT]) -> Vec<DIGIT> {
    let mut codeword = vec![0 as DIGIT; N0*NUM_DIGITS_GF2X_ELEMENT];
    codeword[0..(N0-1)*NUM_DIGITS_GF2X_ELEMENT].copy_from_slice(ptx);

    for i in 0..(N0-1) {
        let mut saux: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
        gf2x_mod_mul(
            &mut saux,
            &pk.Mtr[i*NUM_DIGITS_GF2X_ELEMENT..(i+1)*NUM_DIGITS_GF2X_ELEMENT],
            &ptx[i*NUM_DIGITS_GF2X_ELEMENT..(i+1)*NUM_DIGITS_GF2X_ELEMENT]);

        gf2x_mod_add_2(&mut codeword[(N0-1)*NUM_DIGITS_GF2X_ELEMENT..N0*NUM_DIGITS_GF2X_ELEMENT],
                       &saux);
    }
    for i in 0..N0 {
        gf2x_mod_add_2(&mut codeword[i*NUM_DIGITS_GF2X_ELEMENT..(i+1)*NUM_DIGITS_GF2X_ELEMENT],
                       &err[i*NUM_DIGITS_GF2X_ELEMENT..(i+1)*NUM_DIGITS_GF2X_ELEMENT]);
    }
    codeword
}
// end encrypt_McEliece
/*----------------------------------------------------------------------------*/

fn char_right_bit_shift_n(data: &mut [u8], amount: usize) {
    assert!(amount < 8);

    let mask : u8 = (1 << amount) - 1;

    for j in (1..data.len()).rev() {
        data[j] >>= amount;
        data[j] |= (data[j-1] & mask) << (8 - amount);
    }
    data[0] >>= amount;
}
/*----------------------------------------------------------------------------*/
/*  shifts the input stream so that the bytewise pad is on the left before
 * conversion */
fn bytestream_into_poly_seq(
    mut polySeq: &mut [DIGIT],
    mut numPoly: usize,
    mut S: &mut [u8]) -> Result<()> {

    let padsize = if K % 8 != 0 { 8 - (K % 8) } else { 0 };
    char_right_bit_shift_n(S, padsize);
    if numPoly == 0 || S.len() < ((numPoly * P + 7) / 8) {
        return Err(Error::Custom("Error in bytestream_into_poly_seq".into()));
    }
    let slack_bits = S.len()*8 - numPoly*P;
    let mut bitCursor: u32 = slack_bits as u32;
    for polyIdx in 0..numPoly {
        for exponent in 0..P {
            let buffer = unsafe { bitstream_read(S.as_mut_ptr(), 1i32 as u32, &mut bitCursor) };
            gf2x_set_coeff(&mut polySeq[NUM_DIGITS_GF2X_ELEMENT*polyIdx..], exponent, buffer);
        }
    }
    Ok(())
}

// return 0 i.e., insuccess, if bitLenPtx > (N0-1)*P + be - bc - bh or bitLenPtx <= 0
// end bytestream_into_poly_seq
/*----------------------------------------------------------------------------*/

pub fn digits_to_bytes(d: &[DIGIT]) -> Vec<u8> {
    let mut out = vec![0u8; d.len() * 8];

    for i in 0..d.len() {
        let word : [u8; 8] = d[i].to_le_bytes();
        out[(8*i)..(8*i+8)].copy_from_slice(&word);
    }

    return out;
}

pub fn encrypt_Kobara_Imai(pk: &LedaPublicKey, msg: &[u8]) -> Result<Vec<u8>> {
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

    // Longer is supported by LEDA spec using a different encoding,
    // but with our parameters, this supports up to 7K which seems plenty

    if msg.len() > MAX_BYTES_IN_IWORD {
        return Err(Error::Custom("Plaintext is too long for Leda-PKC".into()));
    }

    let clen = N0 * NUM_DIGITS_GF2X_ELEMENT * DIGIT_SIZE_B;

    // pull randombytes upwards:

    /* Generate PRNG pad */

    let mut secretSeed: [u8; 32] = [0; 32];
    randombytes(&mut secretSeed);

    let bytePtxLen: u32 = msg.len() as u32;

    let paddedSequenceLen = (K+7)/8;

    let prngSequence =
        deterministic_random_byte_generator(&secretSeed, paddedSequenceLen)?;

    let mut ctext = vec![0u8; clen];

    ctext[32..40].copy_from_slice(&(bytePtxLen as u64).to_le_bytes());
    ctext[40..40 + bytePtxLen as usize].copy_from_slice(&msg);

    for i in 0..paddedSequenceLen {
        ctext[i] ^= prngSequence[i];
    }
    ctext[paddedSequenceLen-1] &= !(0xFF >> (K % 8));

    /* prepare buffer which will be translated in the information word */

    let mut iwordBuffer: [u8; (K+7)/8] = [0; (K+7)/8];
    iwordBuffer.copy_from_slice(&ctext[0..(K+7)/8]);
    /* transform into an information word poly sequence */
    let mut informationWord: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    bytestream_into_poly_seq(&mut informationWord,
                             N0 - 1,
                             &mut iwordBuffer)?;
    /* prepare hash of padded sequence, before leftover is moved to its final place */
    let hashDigest = sha3_384(&ctext[0..paddedSequenceLen]);
    /* move leftover padded string (if present) onto its final position*/
unsafe {
    /*prepare CWEnc input as zero extended seed ^ hash of */
    let mut cwEncInputBuffer: [u8; 1072] = [0; 1072];
    cwEncInputBuffer[0..48].copy_from_slice(&hashDigest);
    for i in 0..32 {
        cwEncInputBuffer[i] ^= secretSeed[i];
    }
    let mut cwEncodedError: [DIGIT; N0*NUM_DIGITS_GF2X_ELEMENT] = [0; N0*NUM_DIGITS_GF2X_ELEMENT];
    /* continue drawing fresh randomness in case the constant weight encoding
     * fails */
    let mut binaryToConstantWeightOk: i32 = 0i32;
    loop {
        /* blank cwenc destination buffer */
        cwEncodedError.copy_from_slice(&[0; N0*NUM_DIGITS_GF2X_ELEMENT]);
        /* draw filler randomness for cwenc input from an independent random*/
        randombytes(&mut secretSeed);
        drbg(&mut cwEncInputBuffer[48..1072], &secretSeed)?;
        binaryToConstantWeightOk = binary_to_constant_weight_approximate(
            &mut cwEncodedError,
            cwEncInputBuffer.as_mut_ptr(),
            48i32 + 1024i32,
        );
        if !(binaryToConstantWeightOk == 0i32) {
            break;
        }
    }

    let mut codeword = encrypt_McEliece(&*pk, &informationWord, &cwEncodedError);

    /* output composition looks like codeword || left bytepad leftover
     * and is thus long as ROUND_UP(leftover_bits,8)+
     * N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B */
    // the output byte stream is made of N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B bytes
    Ok(digits_to_bytes(&codeword))
        }
}
/*----------------------------------------------------------------------------*/
// end encrypt_Kobara_Imai
