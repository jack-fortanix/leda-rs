/*****************************************************************************
 *  Integer sorting routine code imported and adapted from djbsort
 *  https://sorting.cr.yp.to/index.html
 *  Original code available as public domain, the same licensing applies to
 *  the modifications made to adapt it to the LEDAcrypt codebase.
*****************************************************************************/

#[inline]
fn int32_MINMAX(a: &mut i32, b: &mut i32) {
    let ab: i32 = *b ^ *a;
    let mut c: i32 = *b - *a;
    c ^= ab & (c ^ *b);
    c >>= 31;
    c &= ab;
    *a ^= c;
    *b ^= c;
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
                int32_MINMAX(&mut *x.offset(j), &mut *x.offset(j + p));
                j += 1
            }
            i += 2 * p
        }
        j = i;
        while j < n - p {
            int32_MINMAX(&mut *x.offset(j), &mut *x.offset(j + p));
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
                        int32_MINMAX(&mut a, &mut *x.offset(j + r));
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
                                int32_MINMAX(&mut a_0, &mut *x.offset(j + r));
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
                            int32_MINMAX(&mut a_1, &mut *x.offset(j + r));
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
