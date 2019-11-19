/*****************************************************************************
 *  Integer sorting routine code imported and adapted from djbsort
 *  https://sorting.cr.yp.to/index.html
 *  Original code available as public domain, the same licensing applies to
 *  the modifications made to adapt it to the LEDAcrypt codebase.
*****************************************************************************/

#[inline]
fn int32_MINMAX(a: i32, b: i32) -> (i32, i32) {
    let ab: i32 = b ^ a;
    let mut c: i32 = b - a;
    c ^= ab & (c ^ b);
    c >>= 31;
    c &= ab;
    return (a ^ c, b ^ c);
}

pub unsafe fn int32_sort(x: *mut i32, n: isize) {
    let mut top: isize = 0;
    let mut p: isize = 0;
    let mut q: isize = 0;
    let mut r: isize = 0;
    let mut i: isize = 0;
    let mut j: isize = 0;

    if n < 2 {
        return;
    }
    top = 1;
    while top < n - top {
        top += top
    }
    p = top;
    while p >= 1 {
        i = 0;
        while i + 2 * p <= n {
            j = i;
            while j < i + p {
                let mut ab: i32 = *x.offset((j + p) as isize) ^ *x.offset(j as isize);
                let mut c: i32 = *x.offset((j + p) as isize) - *x.offset(j as isize);
                c ^= ab & (c ^ *x.offset((j + p) as isize));
                c >>= 31i32;
                c &= ab;
                let ref mut fresh0 = *x.offset(j as isize);
                *fresh0 ^= c;
                let ref mut fresh1 = *x.offset((j + p) as isize);
                *fresh1 ^= c;
                j += 1
            }
            i += 2 * p
        }
        j = i;
        while j < n - p {
            let mut ab_0: i32 = *x.offset((j + p) as isize) ^ *x.offset(j as isize);
            let mut c_0: i32 = *x.offset((j + p) as isize) - *x.offset(j as isize);
            c_0 ^= ab_0 & (c_0 ^ *x.offset((j + p) as isize));
            c_0 >>= 31i32;
            c_0 &= ab_0;
            let ref mut fresh2 = *x.offset(j as isize);
            *fresh2 ^= c_0;
            let ref mut fresh3 = *x.offset((j + p) as isize);
            *fresh3 ^= c_0;
            j += 1
        }
        i = 0;
        j = 0;
        q = top;
        while q > p {
            let mut current_block_73: u64;
            if j != i {
                loop {
                    if j == n - q {
                        current_block_73 = 5722677567366458307;
                        break;
                    }
                    let mut a: i32 = *x.offset((j + p) as isize);
                    r = q;
                    while r > p {
                        let mut ab_1: i32 = *x.offset((j + r) as isize) ^ a;
                        let mut c_1: i32 = *x.offset((j + r) as isize) - a;
                        c_1 ^= ab_1 & (c_1 ^ *x.offset((j + r) as isize));
                        c_1 >>= 31i32;
                        c_1 &= ab_1;
                        a ^= c_1;
                        let ref mut fresh4 = *x.offset((j + r) as isize);
                        *fresh4 ^= c_1;
                        r >>= 1i32
                    }
                    *x.offset((j + p) as isize) = a;
                    j += 1;
                    if !(j == i + p) {
                        continue;
                    }
                    i += 2 * p;
                    current_block_73 = 12556861819962772176;
                    break;
                }
            } else {
                current_block_73 = 12556861819962772176;
            }
            match current_block_73 {
                12556861819962772176 => {
                    while i + p <= n - q {
                        j = i;
                        while j < i + p {
                            let mut a_0: i32 = *x.offset((j + p) as isize);
                            r = q;
                            while r > p {
                                let mut ab_2: i32 = *x.offset((j + r) as isize) ^ a_0;
                                let mut c_2: i32 = *x.offset((j + r) as isize) - a_0;
                                c_2 ^= ab_2 & (c_2 ^ *x.offset((j + r) as isize));
                                c_2 >>= 31i32;
                                c_2 &= ab_2;
                                a_0 ^= c_2;
                                let ref mut fresh5 = *x.offset((j + r) as isize);
                                *fresh5 ^= c_2;
                                r >>= 1i32
                            }
                            *x.offset((j + p) as isize) = a_0;
                            j += 1
                        }
                        i += 2 * p
                    }
                    /* now i + p > n - q */
                    j = i;
                    while j < n - q {
                        let mut a_1: i32 = *x.offset((j + p) as isize);
                        r = q;
                        while r > p {
                            let mut ab_3: i32 = *x.offset((j + r) as isize) ^ a_1;
                            let mut c_3: i32 = *x.offset((j + r) as isize) - a_1;
                            c_3 ^= ab_3 & (c_3 ^ *x.offset((j + r) as isize));
                            c_3 >>= 31i32;
                            c_3 &= ab_3;
                            a_1 ^= c_3;
                            let ref mut fresh6 = *x.offset((j + r) as isize);
                            *fresh6 ^= c_3;
                            r >>= 1i32
                        }
                        *x.offset((j + p) as isize) = a_1;
                        j += 1
                    }
                }
                _ => {}
            }
            q >>= 1i32
        }
        p >>= 1i32
    }
}
