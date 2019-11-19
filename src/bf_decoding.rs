use crate::consts::*;
use crate::gf2x_arith::*;
use crate::types::*;

pub unsafe fn bf_decoding(
    out: *mut DIGIT,
    HtrPosOnes: *const [u32; 11],
    QtrPosOnes: *const [u32; 11],
    privateSyndrome: *mut DIGIT,
    thresholds: &[i32],
) -> i32
//  1 polynomial
{
    let mut currQBlkPos: [u32; 11] = [0; 11];
    let mut currQBitPos: [u32; 11] = [0; 11];
    let mut currSyndrome: [DIGIT; 905] = [0; 905];
    let mut check: i32 = 0;
    let mut iteration: i32 = 0i32;
    loop {
        gf2x_copy(currSyndrome.as_mut_ptr(), privateSyndrome as *const DIGIT);
        let mut unsatParityChecks: [u8; 115798] = [0; 115798];
        let mut i: i32 = 0i32;
        while i < 2i32 {
            let mut valueIdx: i32 = 0i32;
            while valueIdx < crate::consts::P as i32 {
                let mut HtrOneIdx: i32 = 0i32;
                while HtrOneIdx < 11i32 {
                    let tmp: u32 = if (*HtrPosOnes.offset(i as isize))[HtrOneIdx as usize]
                        .wrapping_add(valueIdx as u32)
                        >= crate::consts::P as i32 as u32
                    {
                        (*HtrPosOnes.offset(i as isize))[HtrOneIdx as usize]
                            .wrapping_add(valueIdx as u32)
                            .wrapping_sub(crate::consts::P as i32 as u32)
                    } else {
                        (*HtrPosOnes.offset(i as isize))[HtrOneIdx as usize]
                            .wrapping_add(valueIdx as u32)
                    };
                    if gf2x_get_coeff(currSyndrome.as_mut_ptr() as *const DIGIT, tmp) != 0 {
                        unsatParityChecks[(i * crate::consts::P as i32 + valueIdx) as usize] =
                            unsatParityChecks[(i * crate::consts::P as i32 + valueIdx) as usize]
                                .wrapping_add(1)
                    }
                    HtrOneIdx += 1
                }
                valueIdx += 1
            }
            i += 1
        }
        /* iteration based threshold determination*/
        let corrt_syndrome_based: i32 = thresholds[iteration as usize];
        //Computation of correlation  with a full Q matrix
        let mut i_0: i32 = 0i32; // end for i
        while i_0 < 2i32 {
            let mut j: i32 = 0i32; // position in the column of QtrPosOnes[][...]
            while j < crate::consts::P as i32 {
                let mut currQoneIdx: i32 = 0i32;
                let mut endQblockIdx: i32 = 0i32;
                let mut correlation: i32 = 0i32;
                let mut blockIdx: i32 = 0i32;
                while blockIdx < 2i32 {
                    endQblockIdx += qBlockWeights[blockIdx as usize][i_0 as usize] as i32;
                    let currblockoffset: i32 = blockIdx * crate::consts::P as i32;
                    while currQoneIdx < endQblockIdx {
                        let mut tmp_0: i32 =
                            (*QtrPosOnes.offset(i_0 as isize))[currQoneIdx as usize]
                                .wrapping_add(j as u32) as i32;
                        tmp_0 = if tmp_0 >= crate::consts::P as i32 {
                            (tmp_0) - crate::consts::P as i32
                        } else {
                            tmp_0
                        };
                        currQBitPos[currQoneIdx as usize] = tmp_0 as u32;
                        currQBlkPos[currQoneIdx as usize] = blockIdx as u32;
                        correlation += unsatParityChecks[(tmp_0 + currblockoffset) as usize] as i32;
                        currQoneIdx += 1
                    }
                    blockIdx += 1
                }
                /* Correlation based flipping */
                if correlation >= corrt_syndrome_based {
                    gf2x_toggle_coeff(
                        out.offset(
                            ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)
                                * i_0) as isize,
                        ),
                        j as u32,
                    );
                    let mut v: i32 = 0i32;
                    while v < 11i32 {
                        let mut syndromePosToFlip: u32 = 0;
                        let mut HtrOneIdx_0: i32 = 0i32;
                        while HtrOneIdx_0 < 11i32 {
                            syndromePosToFlip = (*HtrPosOnes
                                .offset(currQBlkPos[v as usize] as isize))
                                [HtrOneIdx_0 as usize]
                                .wrapping_add(currQBitPos[v as usize]);
                            syndromePosToFlip =
                                if syndromePosToFlip >= crate::consts::P as i32 as u32 {
                                    syndromePosToFlip.wrapping_sub(crate::consts::P as i32 as u32)
                                } else {
                                    syndromePosToFlip
                                };
                            gf2x_toggle_coeff(privateSyndrome, syndromePosToFlip);
                            HtrOneIdx_0 += 1
                        }
                        v += 1
                    }
                    // end for v
                }
                j += 1
            }
            i_0 += 1
            // end for j
        }
        iteration = iteration + 1i32;
        check = 0i32;
        while check < (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) && {
            let fresh0 = check;
            check = check + 1;
            (*privateSyndrome.offset(fresh0 as isize)) == 0i32 as u64
        } {}
        if !(iteration < 2i32
            && check < (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32))
        {
            break;
        }
    }
    return (check == (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) as i32;
}
// end QdecodeSyndromeThresh_bitFlip_sparse
