use crate::consts::*;
use crate::gf2x_arith::*;
use crate::types::*;

pub fn bf_decoding(
    out: &mut [DIGIT],
    HtrPosOnes: &[[u32; 11]; 2],
    QtrPosOnes: &[[u32; 11]; 2],
    privateSyndrome: &mut [DIGIT],
    thresholds: &[i32],
) -> i32
//  1 polynomial
{
    let mut currQBlkPos: [u32; 11] = [0; 11];
    let mut currQBitPos: [u32; 11] = [0; 11];
    let mut currSyndrome: [DIGIT; NUM_DIGITS_GF2X_ELEMENT] = [0; NUM_DIGITS_GF2X_ELEMENT];
    let mut iteration: i32 = 0i32;
    loop {
        gf2x_copy(&mut currSyndrome, privateSyndrome);
        let mut unsatParityChecks: [u8; 115798] = [0; 115798];
        for i in 0..N0 {
            for valueIdx in 0..P32 {
                for HtrOneIdx in 0..DV {
                    let tmp = (HtrPosOnes[i][HtrOneIdx] + valueIdx) % P32;
                    if gf2x_get_coeff(&currSyndrome, tmp) != 0 {
                        unsatParityChecks[(i * P + valueIdx as usize)] += 1;
                    }
                }
            }
        }
        /* iteration based threshold determination*/
        let corrt_syndrome_based: i32 = thresholds[iteration as usize];
        //Computation of correlation  with a full Q matrix
        for i in 0..N0 {
            let mut j: i32 = 0i32; // position in the column of QtrPosOnes[][...]
            while j < crate::consts::P as i32 {
                let mut currQoneIdx: i32 = 0i32;
                let mut endQblockIdx: i32 = 0i32;
                let mut correlation: i32 = 0i32;
                let mut blockIdx: i32 = 0i32;
                while blockIdx < 2i32 {
                    endQblockIdx += qBlockWeights[blockIdx as usize][i] as i32;
                    let currblockoffset: i32 = blockIdx * crate::consts::P as i32;
                    while currQoneIdx < endQblockIdx {
                        let mut tmp_0: i32 =
                            QtrPosOnes[i][currQoneIdx as usize].wrapping_add(j as u32) as i32;
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
                    gf2x_toggle_coeff(&mut out[NUM_DIGITS_GF2X_ELEMENT * i..], j as u32);
                    for v in 0..DV {
                        let mut syndromePosToFlip: u32 = 0;
                        for HtrOneIdx in 0..DV {
                            syndromePosToFlip = HtrPosOnes[currQBlkPos[v] as usize]
                                [HtrOneIdx]
                                .wrapping_add(currQBitPos[v]);
                            syndromePosToFlip =
                                if syndromePosToFlip >= P32 {
                                    syndromePosToFlip.wrapping_sub(P32)
                                } else {
                                    syndromePosToFlip
                                };
                            gf2x_toggle_coeff(privateSyndrome, syndromePosToFlip);
                        }
                    }
                    // end for v
                }
                j += 1
            }
            // end for j
        }
        iteration = iteration + 1i32;
        let mut check = 0i32;
        while check < (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) && {
            let fresh0 = check;
            check = check + 1;
            (privateSyndrome[fresh0 as usize]) == 0i32 as u64
        } {}
        if !(iteration < 2i32
            && check < (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32))
        {
            return (check == (crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) as i32;
        }
    }
}
// end QdecodeSyndromeThresh_bitFlip_sparse
