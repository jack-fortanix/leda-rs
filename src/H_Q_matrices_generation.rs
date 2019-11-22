use crate::consts::*;
use crate::gf2x_arith_mod_xPplusOne::rand_circulant_sparse_block;
use crate::types::*;

pub fn generateHPosOnes(HPosOnes: &mut [[u32; DV]; N0], keys_expander: &mut AES_XOF_struct) {
    for i in 0..N0 {
        /* Generate a random block of Htr */
        rand_circulant_sparse_block(
            &mut HPosOnes[i],
            DV,
            keys_expander,
        );
    }
}

pub fn generateQPosOnes(QPosOnes: &mut [[u32; DV]; N0], keys_expander: &mut AES_XOF_struct) {
    for i in 0..N0 {
        let mut placed_ones: usize = 0;
        for j in 0..2 {
            rand_circulant_sparse_block(
                &mut QPosOnes[i][placed_ones as usize..],
                qBlockWeights[i][j] as usize,
                keys_expander,
            );
            placed_ones += qBlockWeights[i][j] as usize;
        }
    }
}

pub unsafe fn transposeHPosOnes(HtrPosOnes: &mut [[u32; DV]; N0], HPosOnes: &[[u32; DV]; N0]) {
    let P32 = P as u32;
    for i in 0..N0 {
        /* Obtain directly the sparse representation of the block of H */
        for k in 0..DV {
            HtrPosOnes[i][k] = (P32 - HPosOnes[i][k]) % P32; /* transposes indexes */
        }
    }
}

// end transposeHPosOnes

pub unsafe fn transposeQPosOnes(QtrPosOnes: *mut [u32; 11], QPosOnes: *mut [u32; 11]) {
    let mut transposed_ones_idx: [u32; 2] = [0i32 as u32, 0]; // position in the column of QtrPosOnes[][...]
    let mut source_row_idx: u32 = 0i32 as u32;
    while source_row_idx < 2i32 as u32 {
        let mut currQoneIdx: i32 = 0i32;
        let mut endQblockIdx: i32 = 0i32;
        let mut blockIdx: i32 = 0i32;
        while blockIdx < 2i32 {
            endQblockIdx += qBlockWeights[source_row_idx as usize][blockIdx as usize] as i32;
            while currQoneIdx < endQblockIdx {
                (*QtrPosOnes.offset(blockIdx as isize))
                    [transposed_ones_idx[blockIdx as usize] as usize] = (crate::consts::P as i32
                    as u32)
                    .wrapping_sub((*QPosOnes.offset(source_row_idx as isize))[currQoneIdx as usize])
                    .wrapping_rem(crate::consts::P as i32 as u32);
                transposed_ones_idx[blockIdx as usize] =
                    transposed_ones_idx[blockIdx as usize].wrapping_add(1);
                currQoneIdx += 1
            }
            blockIdx += 1
        }
        source_row_idx = source_row_idx.wrapping_add(1)
    }
}

