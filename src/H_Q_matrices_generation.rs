use crate::consts::*;
use crate::gf2x_arith_mod_xPplusOne::rand_circulant_sparse_block;
use crate::types::*;

pub fn generateHPosOnes(HPosOnes: &mut [[u32; DV]; N0], keys_expander: &mut AES_XOF_struct) {
    for i in 0..N0 {
        /* Generate a random block of Htr */
        rand_circulant_sparse_block(&mut HPosOnes[i], DV, keys_expander);
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

pub fn transposeHPosOnes(HtrPosOnes: &mut [[u32; DV]; N0], HPosOnes: &[[u32; DV]; N0]) {
    for i in 0..N0 {
        /* Obtain directly the sparse representation of the block of H */
        for k in 0..DV {
            HtrPosOnes[i][k] = (P32 - HPosOnes[i][k]) % P32; /* transposes indexes */
        }
    }
}

pub fn transposeQPosOnes(QtrPosOnes: &mut [[u32; DV]; N0], QPosOnes: &[[u32; DV]; N0]) {
    let mut transposed_ones_idx: [u32; N0] = [0u32, 0]; // position in the column of QtrPosOnes[][...]

    for source_row_idx in 0..N0 {
        let mut currQoneIdx: usize = 0;
        let mut endQblockIdx: usize = 0;
        for blockIdx in 0..N0 {
            endQblockIdx += qBlockWeights[source_row_idx][blockIdx] as usize;

            while currQoneIdx < endQblockIdx {
                QtrPosOnes[blockIdx][transposed_ones_idx[blockIdx] as usize] =
                    (P32 - QPosOnes[source_row_idx][currQoneIdx]) % P32;

                transposed_ones_idx[blockIdx] += 1;
                currQoneIdx += 1
            }
        }
    }
}
