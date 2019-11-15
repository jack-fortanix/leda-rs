#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    /*--------------------------------------------------------------------------*/
    #[no_mangle]
    fn rand_circulant_sparse_block(pos_ones: *mut uint32_t,
                                   countOnes: libc::c_int,
                                   seed_expander_ctx: *mut AES_XOF_struct);
}
pub type __uint32_t = libc::c_uint;
pub type uint32_t = __uint32_t;
#[derive ( Copy, Clone )]
#[repr(C)]
pub struct AES_XOF_struct {
    pub buffer: [libc::c_uchar; 16],
    pub buffer_pos: libc::c_int,
    pub length_remaining: libc::c_ulong,
    pub key: [libc::c_uchar; 32],
    pub ctr: [libc::c_uchar; 16],
}
/*----------------------------------------------------------------------------*/
// We employ the parameters for Category 4 also in the case where the required
// security level is Category 5, where Category 4 has the following parameters.
// #if CATEGORY == 4
//   #define TRNG_BYTE_LENGTH (40)
//   #define    HASH_FUNCTION sha3_384
//   #define HASH_BYTE_LENGTH (48)
// #endif
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
// Derived parameters, they are useful for QC-LDPC algorithms
// Circulant weight structure of the Q matrix, specialized per value of N0
static mut qBlockWeights: [[libc::c_uchar; 2]; 2] =
    [[6i32 as libc::c_uchar, 5i32 as libc::c_uchar],
     [5i32 as libc::c_uchar, 6i32 as libc::c_uchar]];
/* *
 *
 * <H_Q_matrices_generation.c>
 *
 * @version 2.0 (March 2019)
 *
 * Reference ISO-C11 Implementation of LEDAcrypt using GCC built-ins.
 *
 * In alphabetical order:
 *
 * @author Marco Baldi <m.baldi@univpm.it>
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Franco Chiaraluce <f.chiaraluce@univpm.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author Paolo Santini <p.santini@pm.univpm.it>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe extern "C" fn generateHPosOnes(mut HPosOnes: *mut [uint32_t; 11],
                                          mut keys_expander:
                                              *mut AES_XOF_struct) {
    let mut i: libc::c_int = 0i32;
    while i < 2i32 {
        /* Generate a random block of Htr */
        rand_circulant_sparse_block(&mut *(*HPosOnes.offset(i as
                                                                isize)).as_mut_ptr().offset(0),
                                    11i32, keys_expander);
        i += 1
    };
}
// end generateHtr_HtrPosOnes
#[no_mangle]
pub unsafe extern "C" fn transposeHPosOnes(mut HtrPosOnes:
                                               *mut [uint32_t; 11],
                                           mut HPosOnes:
                                               *mut [uint32_t; 11]) {
    let mut i: libc::c_int = 0i32;
    while i < 2i32 {
        /* Obtain directly the sparse representation of the block of H */
        let mut k: libc::c_int = 0i32;
        while k < 11i32 {
            (*HtrPosOnes.offset(i as isize))[k as usize] =
                (57899i32 as
                     libc::c_uint).wrapping_sub((*HPosOnes.offset(i as
                                                                      isize))[k
                                                                                  as
                                                                                  usize]).wrapping_rem(57899i32
                                                                                                           as
                                                                                                           libc::c_uint);
            k += 1
            /* transposes indexes */
        }
        i += 1
        // end for k
    };
}
/*----------------------------------------------------------------------------*/
// end transposeHPosOnes
#[no_mangle]
pub unsafe extern "C" fn transposeQPosOnes(mut QtrPosOnes:
                                               *mut [uint32_t; 11],
                                           mut QPosOnes:
                                               *mut [uint32_t; 11]) {
    let mut transposed_ones_idx: [libc::c_uint; 2] =
        [0i32 as libc::c_uint,
         0]; // position in the column of QtrPosOnes[][...]
    let mut source_row_idx: libc::c_uint = 0i32 as libc::c_uint;
    while source_row_idx < 2i32 as libc::c_uint {
        let mut currQoneIdx: libc::c_int = 0i32;
        let mut endQblockIdx: libc::c_int = 0i32;
        let mut blockIdx: libc::c_int = 0i32;
        while blockIdx < 2i32 {
            endQblockIdx +=
                qBlockWeights[source_row_idx as usize][blockIdx as usize] as
                    libc::c_int;
            while currQoneIdx < endQblockIdx {
                (*QtrPosOnes.offset(blockIdx as
                                        isize))[transposed_ones_idx[blockIdx
                                                                        as
                                                                        usize]
                                                    as usize] =
                    (57899i32 as
                         libc::c_uint).wrapping_sub((*QPosOnes.offset(source_row_idx
                                                                          as
                                                                          isize))[currQoneIdx
                                                                                      as
                                                                                      usize]).wrapping_rem(57899i32
                                                                                                               as
                                                                                                               libc::c_uint);
                transposed_ones_idx[blockIdx as usize] =
                    transposed_ones_idx[blockIdx as usize].wrapping_add(1);
                currQoneIdx += 1
            }
            blockIdx += 1
        }
        source_row_idx = source_row_idx.wrapping_add(1)
    };
}
/* *
 *
 * <H_Q_matrices_generation.h>
 *
 * @version 2.0 (March 2019)
 *
 * Reference ISO-C11 Implementation of LEDAcrypt using GCC built-ins.
 *
 * In alphabetical order:
 *
 * @author Marco Baldi <m.baldi@univpm.it>
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Franco Chiaraluce <f.chiaraluce@univpm.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author Paolo Santini <p.santini@pm.univpm.it>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/
/*----------------------------------------------------------------------------*/
/* output*/
/*----------------------------------------------------------------------------*/
/* output*/
/*----------------------------------------------------------------------------*/
// end transposeHPosOnes
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe extern "C" fn generateQPosOnes(mut QPosOnes: *mut [uint32_t; 11],
                                          mut keys_expander:
                                              *mut AES_XOF_struct) {
    let mut i: libc::c_int = 0i32;
    while i < 2i32 {
        let mut placed_ones: libc::c_int = 0i32;
        let mut j: libc::c_int = 0i32;
        while j < 2i32 {
            rand_circulant_sparse_block(&mut *(*QPosOnes.offset(i as
                                                                    isize)).as_mut_ptr().offset(placed_ones
                                                                                                    as
                                                                                                    isize),
                                        qBlockWeights[i as usize][j as usize]
                                            as libc::c_int, keys_expander);
            placed_ones +=
                qBlockWeights[i as usize][j as usize] as libc::c_int;
            j += 1
        }
        i += 1
        // end for j
    };
    // end for i
}
/*----------------------------------------------------------------------------*/
// end generateQPosOnes
