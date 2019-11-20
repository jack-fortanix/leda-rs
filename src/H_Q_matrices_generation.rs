use crate::consts::*;
use crate::gf2x_arith_mod_xPplusOne::rand_circulant_sparse_block;
use crate::types::*;

/*----------------------------------------------------------------------------*/

pub unsafe fn generateHPosOnes(HPosOnes: *mut [u32; 11], keys_expander: &mut AES_XOF_struct) {
    let mut i: i32 = 0i32;
    while i < 2i32 {
        /* Generate a random block of Htr */
        rand_circulant_sparse_block(
            &mut *(*HPosOnes.offset(i as isize)).as_mut_ptr().offset(0),
            11i32,
            keys_expander,
        );
        i += 1
    }
}
// end generateHtr_HtrPosOnes

pub unsafe fn transposeHPosOnes(HtrPosOnes: *mut [u32; 11], HPosOnes: *mut [u32; 11]) {
    let mut i: i32 = 0i32;
    while i < 2i32 {
        /* Obtain directly the sparse representation of the block of H */
        let mut k: i32 = 0i32;
        while k < 11i32 {
            (*HtrPosOnes.offset(i as isize))[k as usize] = (crate::consts::P as i32 as u32)
                .wrapping_sub((*HPosOnes.offset(i as isize))[k as usize])
                .wrapping_rem(crate::consts::P as i32 as u32);
            k += 1
            /* transposes indexes */
        }
        i += 1
        // end for k
    }
}
/*----------------------------------------------------------------------------*/
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
/*----------------------------------------------------------------------------*/
/* output*/
/*----------------------------------------------------------------------------*/
/* output*/
/*----------------------------------------------------------------------------*/
// end transposeHPosOnes
/*----------------------------------------------------------------------------*/

pub unsafe fn generateQPosOnes(QPosOnes: *mut [u32; 11], keys_expander: &mut AES_XOF_struct) {
    let mut i: i32 = 0i32;
    while i < 2i32 {
        let mut placed_ones: i32 = 0i32;
        let mut j: i32 = 0i32;
        while j < 2i32 {
            rand_circulant_sparse_block(
                &mut *(*QPosOnes.offset(i as isize))
                    .as_mut_ptr()
                    .offset(placed_ones as isize),
                qBlockWeights[i as usize][j as usize] as i32,
                keys_expander,
            );
            placed_ones += qBlockWeights[i as usize][j as usize] as i32;
            j += 1
        }
        i += 1
        // end for j
    }
    // end for i
}
/*----------------------------------------------------------------------------*/
// end generateQPosOnes
