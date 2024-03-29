use rustc_serialize::hex::{ToHex, FromHex};
use core::str::FromStr;
use leda_rs::*;

/*
fn dump(n: &str, b: &[u8], l: usize) {
    println!("{} = [{}] {}", n, l, (b[0..l].to_hex()));
}

#[test]
pub fn trial() {
    return;
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
*/

#[derive(Debug)]
struct LedaKat {
    count: usize,
    seed: Vec<u8>,
    mlen: usize,
    msg: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    clen: usize,
    ctext: Vec<u8>,
}

impl FromStr for LedaKat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<LedaKat, Self::Err> {

        let mut count = None;
        let mut seed = None;
        let mut mlen = None;
        let mut msg = None;
        let mut pk = None;
        let mut sk = None;
        let mut clen = None;
        let mut ctext = None;

        for line in s.split("\n") {
            let kv = line.split(" = ").collect::<Vec<_>>();

            if kv.len() == 2 {
                match kv[0] {
                    "count" => { count = Some(kv[1].parse::<usize>().unwrap()); }
                    "mlen" => { mlen = Some(kv[1].parse::<usize>().unwrap()); }
                    "clen" => { clen = Some(kv[1].parse::<usize>().unwrap()); }
                    "seed" => { seed = Some(kv[1].from_hex().unwrap()); }
                    "pk" => { pk = Some(kv[1].from_hex().unwrap()); }
                    "sk" => { sk = Some(kv[1].from_hex().unwrap()); }
                    "msg" => { msg = Some(kv[1].from_hex().unwrap()); }
                    "c" => { ctext = Some(kv[1].from_hex().unwrap()); }
                    x => { panic!(format!("unknown field {}", x)); }
                }
            }
        }

        Ok(LedaKat {
            count: count.unwrap(),
            seed: seed.unwrap(),
            mlen: mlen.unwrap(),
            msg: msg.unwrap(),
            pk: pk.unwrap(),
            sk: sk.unwrap(),
            clen: clen.unwrap(),
            ctext: ctext.unwrap()
        })
    }
}

#[test]
pub fn all_kats() {
    let kats = String::from_utf8(include_bytes!("data/PQCencryptKAT_34_0.rsp").to_vec()).unwrap();

    for kat in kats.split("\n\n") {
        let kat = LedaKat::from_str(kat).unwrap();

        println!("Leda count {}", kat.count);

        let mut drbg_ctx = AES256_CTR_DRBG_struct {
            key: [0; 32],
            v: [0; 16],
            reseed_counter: 0,
        };

        randombytes_ctx_init(&mut drbg_ctx, &kat.seed);

        let mut kp_seed = vec![0u8; 32];
        randombytes_ctx(&mut drbg_ctx, &mut kp_seed);

        let (sk,pk) = leda_gen_keypair(&kp_seed).unwrap();

        assert_eq!(sk.to_hex(), kat.sk.to_hex());
        assert_eq!(pk.to_hex(), kat.pk.to_hex());

        let ctext = leda_encrypt(&kat.msg, &kat.pk, |v| randombytes_ctx(&mut drbg_ctx, v)).unwrap();

        assert_eq!(ctext.len(), kat.clen);
        assert_eq!(ctext.to_hex(), kat.ctext.to_hex());

        let recovered = leda_decrypt(&ctext, &kat.sk).unwrap();

        assert_eq!(recovered.to_hex(), kat.msg.to_hex());

        let mut invalid_ctext = ctext.clone();

        let idx = ((ctext[30] as usize)*239+ctext[32] as usize) % ctext.len();
        invalid_ctext[idx] ^= 1;

        let result = leda_decrypt(&invalid_ctext, &kat.sk);

        match result {
            Err(Error::DecryptionFailed) => { }
            Err(_) => { panic!("Unexpected error") }
            Ok(r) => { assert_eq!(r.to_hex(), kat.msg.to_hex()); }
        }
    }
}
