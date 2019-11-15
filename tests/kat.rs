
use rustc_serialize::hex::ToHex;
use leda_rs::*;

fn dump(n: &str, b: &[u8], l: usize) {
    println!("{} = [{}] {}", n, l, (b[0..l].to_hex()));
}

#[test]
pub fn kat() {

    let mut pk = vec![0u8; 7240];
    let mut sk: [u8; 34] = [0; 34];
    unsafe { crypto_encrypt_keypair(pk.as_mut_ptr(), sk.as_mut_ptr()); }
    dump("pk", &pk, 7240);
    dump("sk", &sk, 34);
    let ptext: [u8; 5] = [1, 2, 3, 4, 5];
    dump("ptext", &ptext, 5);
    let mut ctext = vec![0u8; 14485];
    let mut mlen: u64 = 5;
    let mut clen: u64 = 0;
    unsafe { crypto_encrypt(ctext.as_mut_ptr(), &mut clen, ptext.as_ptr(), mlen,
                            pk.as_mut_ptr()); }
    dump("ctext", &ctext, clen as usize);
    let mut decr: [u8; 16] =
        [0i32 as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut dlen: u64 = 16;
    unsafe { crypto_encrypt_open(decr.as_mut_ptr(), &mut dlen, ctext.as_mut_ptr(),
                                 clen, sk.as_mut_ptr()); }
    dump("recovered", &decr, dlen as usize);
}
