use crate::types::*;


pub unsafe fn poly_to_byte_seq(mut bs: *mut u8,
                                          mut y: *mut DIGIT) {
    let mut i: i32 = 0i32;
    while i < (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) {
        let mut a: DIGIT = *y.offset(i as isize);
        let mut v: i32 = 0i32;
        let mut u: i32 = 8i32 - 1i32;
        while u >= 0i32 {
            *bs.offset((i * 8i32 + v) as isize) = (a >> u * 8i32) as u8;
            v += 1;
            u -= 1
        }
        i += 1
    }
}


pub unsafe fn byte_seq_to_poly(mut y: *mut DIGIT,
                                          mut bs: *mut u8) {
    let mut b: i32 = 0i32;
    while b < (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * 8i32 {
        let mut a: DIGIT = 0i32 as DIGIT;
        let mut v: i32 = 0i32;
        let mut u: i32 = 8i32 - 1i32;
        while u >= 0i32 {
            a =
                (a as
                     u64).wrapping_add((*bs.offset((b + v) as isize)
                                                      as DIGIT) << u * 8i32)
                    as DIGIT as DIGIT;
            v += 1;
            u -= 1
        }
        *y.offset((b / 8i32) as isize) = a;
        b += 8i32
    };
}
