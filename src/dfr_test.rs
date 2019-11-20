use crate::djbsort::int32_sort;

/*---------------------------------------------------------------------------*/
/* Tests if the current code attains the desired DFR. If that is the case,
 * computes the threshold for the second iteration of the decoder and stores
 * it in the globally accessible vector*/

pub unsafe fn DFR_test(LSparse: *mut [u32; 121], secondIterThreshold: *mut u8) -> i32 {
    let mut LSparse_loc: [[u32; 121]; 2] = [[0; 121]; 2]; /* vector of N_0 sparse blocks */
    /* transpose blocks of L, we need its columns */
    let mut i: usize = 0;
    while i < 2 {
        let mut j = 0;
        while j < crate::consts::DV * crate::consts::M {
            if (*LSparse.offset(i as isize))[j as usize] != 0 as u32 {
                LSparse_loc[i as usize][j as usize] = (crate::consts::P as u32)
                    .wrapping_sub((*LSparse.offset(i as isize))[j as usize]);
            }
            j += 1
        }
        int32_sort(
            LSparse_loc[i].as_mut_ptr() as *mut i32,
            (crate::consts::DV * crate::consts::M) as isize,
        );
        i += 1
    }
    /* Gamma matrix: an N0 x N0 block circulant matrix with block size p
     * gamma[a][b][c] stores the intersection of the first column of the a-th
     * block of L  with the c-th column of the b-th block of L */
    /* Gamma computation can be accelerated employing symmetry and QC properties */

    let mut gamma = vec![
        vec![vec![0i32; crate::consts::P], vec![0i32; crate::consts::P]],
        vec![vec![0i32; crate::consts::P], vec![0i32; crate::consts::P]],
    ];

    let mut i_0: i32 = 0i32;
    while i_0 < 2i32 {
        let mut j_0: i32 = 0i32;
        while j_0 < 2i32 {
            let mut k: i32 = 0i32;
            while k < 11i32 * 11i32 {
                let mut l: i32 = 0i32;
                while l < 11i32 * 11i32 {
                    gamma[i_0 as usize][j_0 as usize][(crate::consts::P as i32 as u32)
                        .wrapping_add(LSparse_loc[i_0 as usize][k as usize])
                        .wrapping_sub(LSparse_loc[j_0 as usize][l as usize])
                        .wrapping_rem(crate::consts::P as i32 as u32)
                        as usize] += 1;
                    l += 1
                }
                k += 1
            }
            j_0 += 1
        }
        i_0 += 1
    }
    let mut i_1: i32 = 0i32;
    while i_1 < 2i32 {
        let mut j_1: i32 = 0i32;
        while j_1 < 2i32 {
            gamma[i_1 as usize][j_1 as usize][0] = 0i32;
            j_1 += 1
        }
        i_1 += 1
    }
    /* build histogram of values in gamma */
    let mut gammaHist: [[u32; 122]; 2] = [[0; 122], [0; 122]];
    let mut i_2: i32 = 0i32;
    while i_2 < 2i32 {
        let mut j_2: i32 = 0i32;
        while j_2 < 2i32 {
            let mut k_0: i32 = 0i32;
            while k_0 < crate::consts::P as i32 {
                gammaHist[i_2 as usize][gamma[i_2 as usize][j_2 as usize][k_0 as usize] as usize] =
                    gammaHist[i_2 as usize]
                        [gamma[i_2 as usize][j_2 as usize][k_0 as usize] as usize]
                        .wrapping_add(1);
                k_0 += 1
            }
            j_2 += 1
        }
        i_2 += 1
    }
    let mut maxMut: [i32; 2] = [0; 2];
    let mut maxMutMinusOne: [i32; 2] = [0; 2];
    let mut allBlockMaxSumst: i32 = 0;
    let mut allBlockMaxSumstMinusOne: i32 = 0;
    let mut gammaBlockRowIdx: i32 = 0i32;
    while gammaBlockRowIdx < 2i32 {
        let mut toAdd: i32 = 5i32 - 1i32;
        maxMutMinusOne[gammaBlockRowIdx as usize] = 0i32;
        let mut histIdx: i32 = 11i32 * 11i32;
        while histIdx > 0i32 && toAdd > 0i32 {
            if gammaHist[gammaBlockRowIdx as usize][histIdx as usize] > toAdd as u32 {
                maxMutMinusOne[gammaBlockRowIdx as usize] += histIdx * toAdd;
                toAdd = 0i32
            } else {
                maxMutMinusOne[gammaBlockRowIdx as usize] =
                    (maxMutMinusOne[gammaBlockRowIdx as usize] as u32).wrapping_add(
                        (histIdx as u32)
                            .wrapping_mul(gammaHist[gammaBlockRowIdx as usize][histIdx as usize]),
                    ) as i32 as i32;
                toAdd = (toAdd as u32)
                    .wrapping_sub(gammaHist[gammaBlockRowIdx as usize][histIdx as usize])
                    as i32 as i32;
                histIdx -= 1
            }
        }
        maxMut[gammaBlockRowIdx as usize] = histIdx + maxMutMinusOne[gammaBlockRowIdx as usize];
        gammaBlockRowIdx += 1
    }
    /*seek max values across all gamma blocks */
    allBlockMaxSumst = maxMut[0];
    allBlockMaxSumstMinusOne = maxMutMinusOne[0];
    let mut gammaBlockRowIdx_0: i32 = 0i32;
    while gammaBlockRowIdx_0 < 2i32 {
        allBlockMaxSumst = if allBlockMaxSumst < maxMut[gammaBlockRowIdx_0 as usize] {
            maxMut[gammaBlockRowIdx_0 as usize]
        } else {
            allBlockMaxSumst
        };
        allBlockMaxSumstMinusOne =
            if allBlockMaxSumstMinusOne < maxMutMinusOne[gammaBlockRowIdx_0 as usize] {
                maxMutMinusOne[gammaBlockRowIdx_0 as usize]
            } else {
                allBlockMaxSumstMinusOne
            };
        gammaBlockRowIdx_0 += 1
    }
    if 11i32 * 11i32 > allBlockMaxSumstMinusOne + allBlockMaxSumst {
        *secondIterThreshold = (allBlockMaxSumst + 1i32) as u8;
        return 1i32;
    }
    return 0i32;
}
