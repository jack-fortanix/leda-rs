#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: i32, _: u64)
     -> *mut libc::c_void;
}
/*
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/
/*
================================================================
The purpose of this source file is to demonstrate a readable and compact
implementation of all the Keccak instances approved in the FIPS 202 standard,
including the hash functions and the extendable-output functions (XOFs).

We focused on clarity and on source-code compactness,
rather than on the performance.

The advantages of this implementation are:
    + The source code is compact, after removing the comments, that is. :-)
    + There are no tables with arbitrary constants.
    + For clarity, the comments link the operations to the specifications using
        the same notation as much as possible.
    + There is no restriction in cryptographic features. In particular,
        the SHAKE128 and SHAKE256 XOFs can produce any output length.
    + The code does not use much RAM, as all operations are done in place.

The drawbacks of this implementation are:
    - There is no message queue. The whole message must be ready in a buffer.
    - It is not optimized for peformance.

The implementation is even simpler on a little endian platform. Just define the
LITTLE_ENDIAN symbol in that case.

For a more complete set of implementations, please refer to
the Keccak Code Package at https://github.com/gvanas/KeccakCodePackage

For more information, please refer to:
    * [Keccak Reference] http://keccak.noekeon.org/Keccak-reference-3.0.pdf
    * [Keccak Specifications Summary] http://keccak.noekeon.org/specs_summary.html

This file uses UTF-8 encoding, as some comments use Greek letters.
================================================================
*/
/* *
  * Function to compute the Keccak[r, c] sponge function over a given input.
  * @param  rate            The value of the rate r.
  * @param  capacity        The value of the capacity c.
  * @param  input           Pointer to the input message.
  * @param  inputByteLen    The number of input bytes provided in the input message.
  * @param  delimitedSuffix Bits that will be automatically appended to the end
  *                         of the input message, as in domain separation.
  *                         This is a byte containing from 0 to 7 bits
  *                         These <i>n</i> bits must be in the least significant bit positions
  *                         and must be delimited with a bit 1 at position <i>n</i>
  *                         (counting from 0=LSB to 7=MSB) and followed by bits 0
  *                         from position <i>n</i>+1 to position 7.
  *                         Some examples:
  *                             - If no bits are to be appended, then @a delimitedSuffix must be 0x01.
  *                             - If the 2-bit sequence 0,1 is to be appended (as for SHA3-*), @a delimitedSuffix must be 0x06.
  *                             - If the 4-bit sequence 1,1,1,1 is to be appended (as for SHAKE*), @a delimitedSuffix must be 0x1F.
  *                             - If the 7-bit sequence 1,1,0,1,0,0,0 is to be absorbed, @a delimitedSuffix must be 0x8B.
  * @param  output          Pointer to the buffer where to store the output.
  * @param  outputByteLen   The number of output bytes desired.
  * @pre    One must have r+c=1600 and the rate a multiple of 8 bits in this implementation.
  */
/*
================================================================
Technicalities
================================================================
*/
/*----------------------------------------------------------------------------*/
pub type UINT8 = u8;
pub type tKeccakLane = UINT64;
pub type UINT64 = u64;
/*----------------------------------------------------------------------------*/
/* * Function to load a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
unsafe extern "C" fn load64(mut x: *const UINT8) -> UINT64 {
    let mut i: i32 = 0;
    let mut u: UINT64 = 0i32 as UINT64;
    i = 7i32;
    while i >= 0i32 {
        u <<= 8i32;
        u |= *x.offset(i as isize) as u64;
        i -= 1
    }
    return u;
}
/*----------------------------------------------------------------------------*/
/* * Function to store a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
unsafe extern "C" fn store64(mut x: *mut UINT8, mut u: UINT64) {
    let mut i: u32 = 0;
    i = 0i32 as u32;
    while i < 8i32 as u32 {
        *x.offset(i as isize) = u as UINT8;
        u >>= 8i32;
        i = i.wrapping_add(1)
    };
}
/*----------------------------------------------------------------------------*/
/* * Function to XOR into a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
unsafe extern "C" fn xor64(mut x: *mut UINT8, mut u: UINT64) {
    let mut i: u32 = 0;
    i = 0i32 as u32;
    while i < 8i32 as u32 {
        let ref mut fresh0 = *x.offset(i as isize);
        *fresh0 = (*fresh0 as u64 ^ u) as UINT8;
        u >>= 8i32;
        i = i.wrapping_add(1)
    };
}
/*----------------------------------------------------------------------------*/
/*
================================================================
A readable and compact implementation of the Keccak-f[1600] permutation.
================================================================
*/
/*----------------------------------------------------------------------------*/
/* *
  * Function that computes the linear feedback shift register (LFSR) used to
  * define the round constants (see [Keccak Reference, Section 1.2]).
  */
unsafe extern "C" fn LFSR86540(mut LFSR: *mut UINT8) -> i32 {
    let mut result: i32 =
        (*LFSR as i32 & 0x1i32 != 0i32) as i32;
    if *LFSR as i32 & 0x80i32 != 0i32 {
        /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
        *LFSR = ((*LFSR as i32) << 1i32 ^ 0x71i32) as UINT8
    } else { *LFSR = ((*LFSR as i32) << 1i32) as UINT8 }
    return result;
}
/*----------------------------------------------------------------------------*/
/* *
 * Function that computes the Keccak-f[1600] permutation on the given state.
 */
unsafe extern "C" fn KeccakF1600_StatePermute(mut state: *mut libc::c_void) {
    let mut round: u32 = 0;
    let mut x: u32 = 0;
    let mut y: u32 = 0;
    let mut j: u32 = 0;
    let mut t: u32 = 0;
    let mut LFSRstate: UINT8 = 0x1i32 as UINT8;
    round = 0i32 as u32;
    while round < 24i32 as u32 {
        /* === θ step (see [Keccak Reference, Section 2.3.2]) === */
        let mut C: [tKeccakLane; 5] = [0; 5];
        let mut D: tKeccakLane = 0;
        /* Compute the parity of the columns */
        x = 0i32 as u32;
        while x < 5i32 as u32 {
            C[x as usize] =
                load64((state as
                            *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                    as
                                                    u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                    *
                                                                                                    0i32)
                                                                                                   as
                                                                                                   u32)
                                                                                    as
                                                                                    u64)
                                                   as isize)) ^
                    load64((state as
                                *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                        as
                                                        u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                        *
                                                                                                        1i32)
                                                                                                       as
                                                                                                       u32)
                                                                                        as
                                                                                        u64)
                                                       as isize)) ^
                    load64((state as
                                *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                        as
                                                        u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                        *
                                                                                                        2i32)
                                                                                                       as
                                                                                                       u32)
                                                                                        as
                                                                                        u64)
                                                       as isize)) ^
                    load64((state as
                                *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                        as
                                                        u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                        *
                                                                                                        3i32)
                                                                                                       as
                                                                                                       u32)
                                                                                        as
                                                                                        u64)
                                                       as isize)) ^
                    load64((state as
                                *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                        as
                                                        u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                        *
                                                                                                        4i32)
                                                                                                       as
                                                                                                       u32)
                                                                                        as
                                                                                        u64)
                                                       as isize));
            x = x.wrapping_add(1)
        }
        x = 0i32 as u32;
        while x < 5i32 as u32 {
            /* Compute the θ effect for a given column */
            D =
                C[x.wrapping_add(4i32 as
                                     u32).wrapping_rem(5i32 as
                                                                    u32)
                      as usize] ^
                    (C[x.wrapping_add(1i32 as
                                          u32).wrapping_rem(5i32 as
                                                                         u32)
                           as usize] << 1i32 ^
                         C[x.wrapping_add(1i32 as
                                              u32).wrapping_rem(5i32
                                                                             as
                                                                             u32)
                               as usize] >> 64i32 - 1i32);
            /* Add the θ effect to the whole column */
            y = 0i32 as u32;
            while y < 5i32 as u32 {
                xor64((state as
                           *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                   as
                                                   u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                   as
                                                                                                   u32).wrapping_mul(y))
                                                                                   as
                                                                                   u64)
                                                  as isize), D);
                y = y.wrapping_add(1)
            }
            x = x.wrapping_add(1)
        }
        /* === ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4]) === */
        let mut current: tKeccakLane = 0;
        let mut temp: tKeccakLane = 0;
        /* Start at coordinates (1 0) */
        x = 1i32 as u32;
        y = 0i32 as u32;
        current =
            load64((state as
                        *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                as
                                                u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                as
                                                                                                u32).wrapping_mul(y))
                                                                                as
                                                                                u64)
                                               as isize));
        /* Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23 */
        t = 0i32 as u32;
        while t < 24i32 as u32 {
            /* Compute the rotation constant r = (t+1)(t+2)/2 */
            let mut r: u32 =
                t.wrapping_add(1i32 as
                                   u32).wrapping_mul(t.wrapping_add(2i32
                                                                                 as
                                                                                 u32)).wrapping_div(2i32
                                                                                                                 as
                                                                                                                 u32).wrapping_rem(64i32
                                                                                                                                                as
                                                                                                                                                u32);
            /* Compute ((0 1)(2 3)) * (x y) */
            let mut Y: u32 =
                (2i32 as
                     u32).wrapping_mul(x).wrapping_add((3i32 as
                                                                     u32).wrapping_mul(y)).wrapping_rem(5i32
                                                                                                                     as
                                                                                                                     u32);
            x = y;
            y = Y;
            /* Swap current and state(x,y), and rotate */
            temp =
                load64((state as
                            *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                    as
                                                    u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                    as
                                                                                                    u32).wrapping_mul(y))
                                                                                    as
                                                                                    u64)
                                                   as isize));
            store64((state as
                         *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                 as
                                                 u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                 as
                                                                                                 u32).wrapping_mul(y))
                                                                                 as
                                                                                 u64)
                                                as isize),
                    current << r ^
                        current >> (64i32 as u32).wrapping_sub(r));
            current = temp;
            t = t.wrapping_add(1)
        }
        /* === χ step (see [Keccak Reference, Section 2.3.1]) === */
        let mut temp_0: [tKeccakLane; 5] = [0; 5];
        y = 0i32 as u32;
        while y < 5i32 as u32 {
            /* Take a copy of the plane */
            x = 0i32 as u32;
            while x < 5i32 as u32 {
                temp_0[x as usize] =
                    load64((state as
                                *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                        as
                                                        u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                        as
                                                                                                        u32).wrapping_mul(y))
                                                                                        as
                                                                                        u64)
                                                       as isize));
                x = x.wrapping_add(1)
            }
            /* Compute χ on the plane */
            x = 0i32 as u32;
            while x < 5i32 as u32 {
                store64((state as
                             *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                     as
                                                     u64).wrapping_mul(x.wrapping_add((5i32
                                                                                                     as
                                                                                                     u32).wrapping_mul(y))
                                                                                     as
                                                                                     u64)
                                                    as isize),
                        temp_0[x as usize] ^
                            !temp_0[x.wrapping_add(1i32 as
                                                       u32).wrapping_rem(5i32
                                                                                      as
                                                                                      u32)
                                        as usize] &
                                temp_0[x.wrapping_add(2i32 as
                                                          u32).wrapping_rem(5i32
                                                                                         as
                                                                                         u32)
                                           as usize]);
                x = x.wrapping_add(1)
            }
            y = y.wrapping_add(1)
        }
        /* === ι step (see [Keccak Reference, Section 2.3.5]) === */
        j = 0i32 as u32; /* 2^j-1 */
        while j < 7i32 as u32 {
            let mut bitPosition: u32 =
                ((1i32 << j) - 1i32) as u32;
            if LFSR86540(&mut LFSRstate) != 0 {
                xor64((state as
                           *mut UINT8).offset((::std::mem::size_of::<tKeccakLane>()
                                                   as
                                                   u64).wrapping_mul((0i32
                                                                                    +
                                                                                    5i32
                                                                                        *
                                                                                        0i32)
                                                                                   as
                                                                                   u64)
                                                  as isize),
                      (1i32 as tKeccakLane) << bitPosition);
            }
            j = j.wrapping_add(1)
        }
        round = round.wrapping_add(1)
    };
}
/*----------------------------------------------------------------------------*/
/*
================================================================
A readable and compact implementation of the Keccak sponge functions
that use the Keccak-f[1600] permutation.
================================================================
*/
#[no_mangle]
pub unsafe extern "C" fn Keccak(mut rate: u32,
                                mut capacity: u32,
                                mut input: *const u8,
                                mut inputByteLen: u64,
                                mut delimitedSuffix: u8,
                                mut output: *mut u8,
                                mut outputByteLen: u64) {
    let mut state: [UINT8; 200] = [0; 200];
    let mut rateInBytes: u32 =
        rate.wrapping_div(8i32 as u32);
    let mut blockSize: u32 = 0i32 as u32;
    let mut i: u32 = 0;
    if rate.wrapping_add(capacity) != 1600i32 as u32 ||
           rate.wrapping_rem(8i32 as u32) != 0i32 as u32 {
        return
    }
    /* === Initialize the state === */
    memset(state.as_mut_ptr() as *mut libc::c_void, 0i32,
           ::std::mem::size_of::<[UINT8; 200]>() as u64);
    /* === Absorb all the input blocks === */
    while inputByteLen > 0i32 as u64 {
        blockSize =
            if inputByteLen < rateInBytes as u64 {
                inputByteLen
            } else { rateInBytes as u64 } as u32;
        i = 0i32 as u32;
        while i < blockSize {
            state[i as usize] =
                (state[i as usize] as i32 ^
                     *input.offset(i as isize) as i32) as UINT8;
            i = i.wrapping_add(1)
        }
        input = input.offset(blockSize as isize);
        inputByteLen =
            inputByteLen.wrapping_sub(blockSize as u64);
        if blockSize == rateInBytes {
            KeccakF1600_StatePermute(state.as_mut_ptr() as *mut libc::c_void);
            blockSize = 0i32 as u32
        }
    }
    /* === Do the padding and switch to the squeezing phase === */
   /* Absorb the last few bits and add the first bit of padding (which coincides with the delimiter in delimitedSuffix) */
    state[blockSize as usize] =
        (state[blockSize as usize] as i32 ^
             delimitedSuffix as i32) as UINT8;
    /* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
    if delimitedSuffix as i32 & 0x80i32 != 0i32 &&
           blockSize == rateInBytes.wrapping_sub(1i32 as u32) {
        KeccakF1600_StatePermute(state.as_mut_ptr() as *mut libc::c_void);
    }
    /* Add the second bit of padding */
    state[rateInBytes.wrapping_sub(1i32 as u32) as usize] =
        (state[rateInBytes.wrapping_sub(1i32 as u32) as usize] as
             i32 ^ 0x80i32) as UINT8;
    /* Switch to the squeezing phase */
    KeccakF1600_StatePermute(state.as_mut_ptr() as *mut libc::c_void);
    /* === Squeeze out all the output blocks === */
    while outputByteLen > 0i32 as u64 {
        blockSize =
            if outputByteLen < rateInBytes as u64 {
                outputByteLen
            } else { rateInBytes as u64 } as u32;
        memcpy(output as *mut libc::c_void,
               state.as_mut_ptr() as *const libc::c_void,
               blockSize as u64);
        output = output.offset(blockSize as isize);
        outputByteLen =
            outputByteLen.wrapping_sub(blockSize as u64);
        if outputByteLen > 0i32 as u64 {
            KeccakF1600_StatePermute(state.as_mut_ptr() as *mut libc::c_void);
        }
    };
}
/*----------------------------------------------------------------------------*/
