/*****************************************************************************
 *  Integer sorting routine code imported and adapted from djbsort
 *  https://sorting.cr.yp.to/index.html
 *  Original code available as public domain, the same licensing applies to
 *  the modifications made to adapt it to the LEDAcrypt codebase.
*****************************************************************************/

#[inline]
fn int32_MINMAX(mut a: i32, mut b: i32) -> (i32, i32) {
    let ab: i32 = b ^ a;
    let mut c: i32 = b - a;
    c ^= ab & (c ^ b);
    c >>= 31;
    c &= ab;
    a ^= c;
    b ^= c;
    return (a, b);
}

pub fn uint32_sort(x: &mut [u32]) {
    let sl = unsafe { std::slice::from_raw_parts_mut(x.as_mut_ptr() as *mut i32, x.len()) };
    int32_sort(sl);
}

pub fn int32_sort(x: &mut [i32]) {
    let n = x.len();
    let mut top: usize = 0;
    let mut p: usize = 0;
    let mut q: usize = 0;
    let mut r: usize = 0;
    let mut i: usize = 0;
    let mut j: usize = 0;

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
                let (xj, xjp) = int32_MINMAX(x[j], x[j + p]);
                x[j] = xj;
                x[j + p] = xjp;
                j += 1
            }
            i += 2 * p
        }
        j = i;
        while j < n - p {
            let (xj, xjp) = int32_MINMAX(x[j], x[j + p]);
            x[j] = xj;
            x[j + p] = xjp;
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
                    let mut a: i32 = x[j + p];
                    r = q;
                    while r > p {
                        let (na, xjp) = int32_MINMAX(a, x[j + p]);
                        a = na;
                        x[j + p] = xjp;
                        r >>= 1i32
                    }
                    x[j + p] = a;
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
                            let mut a_0: i32 = x[j + p];
                            r = q;
                            while r > p {
                                let (na, xjr) = int32_MINMAX(a_0, x[j + r]);
                                a_0 = na;
                                x[j + r] = xjr;
                                r >>= 1i32
                            }
                            x[j + p] = a_0;
                            j += 1
                        }
                        i += 2 * p
                    }
                    /* now i + p > n - q */
                    j = i;
                    while j < n - q {
                        let mut a_1: i32 = x[j + p];
                        r = q;
                        while r > p {
                            let (na, xjr) = int32_MINMAX(a_1, x[j + r]);
                            a_1 = na;
                            x[j + r] = xjr;
                            r >>= 1i32
                        }
                        x[j + p] = a_1;
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
