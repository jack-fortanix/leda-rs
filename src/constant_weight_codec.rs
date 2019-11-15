#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(label_break_value)]
extern "C" {
    #[no_mangle]
    fn __assert_fail(__assertion: *const libc::c_char,
                     __file: *const libc::c_char, __line: libc::c_uint,
                     __function: *const libc::c_char) -> !;
}
pub type __u32 = libc::c_uint;
pub type __u64 = libc::c_ulong;
pub type u32 = __u32;
pub type u64 = __u64;
/* *
 *
 * <gf2x_limbs.h>
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
/*----------------------------------------------------------------------------*/
/* limb size definitions for the multi-precision GF(2^x) library              */
/*----------------------------------------------------------------------------*/
// gcc -DCPU_WORD_BITS=64 ...
pub type DIGIT = u64;
#[inline]
unsafe extern "C" fn gf2x_set_coeff(mut poly: *mut DIGIT,
                                    exponent: libc::c_uint,
                                    mut value: DIGIT) {
    let mut straightIdx: libc::c_int =
        (((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * (8i32 << 3i32)
              - 1i32) as libc::c_uint).wrapping_sub(exponent) as libc::c_int;
    let mut digitIdx: libc::c_int = straightIdx / (8i32 << 3i32);
    let mut inDigitIdx: libc::c_uint =
        (straightIdx % (8i32 << 3i32)) as libc::c_uint;
    let mut mask: DIGIT =
        !((1i32 as DIGIT) <<
              (((8i32 << 3i32) - 1i32) as
                   libc::c_uint).wrapping_sub(inDigitIdx));
    *poly.offset(digitIdx as isize) = *poly.offset(digitIdx as isize) & mask;
    *poly.offset(digitIdx as isize) =
        *poly.offset(digitIdx as isize) |
            (value & 1i32 as DIGIT) <<
                (((8i32 << 3i32) - 1i32) as
                     libc::c_uint).wrapping_sub(inDigitIdx);
}
#[inline]
unsafe extern "C" fn gf2x_get_coeff(mut poly: *const DIGIT,
                                    exponent: libc::c_uint) -> DIGIT {
    let mut straightIdx: libc::c_uint =
        (((57899i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32) * (8i32 << 3i32)
              - 1i32) as libc::c_uint).wrapping_sub(exponent);
    let mut digitIdx: libc::c_uint =
        straightIdx.wrapping_div((8i32 << 3i32) as libc::c_uint);
    let mut inDigitIdx: libc::c_uint =
        straightIdx.wrapping_rem((8i32 << 3i32) as libc::c_uint);
    return *poly.offset(digitIdx as isize) >>
               (((8i32 << 3i32) - 1i32) as
                    libc::c_uint).wrapping_sub(inDigitIdx) & 1i32 as DIGIT;
}
/* *
 *
 * <constant_weight_codec.c>
 *
 * @version 2.0 (March 2019)
 *
 * Reference ISO-C11 Implementation of the LEDAcrypt PKC cipher using GCC built-ins.
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
/* bits will be written to the output matching the same convention of the
 * bitstream read, i.e., in the same order as they appear in the natural
 * encoding of the u64, with the most significant bit being written
 * as the first one in the output bitstream, starting in the output_bit_cursor
 * position */
#[no_mangle]
pub unsafe extern "C" fn bitstream_write(mut output: *mut libc::c_uchar,
                                         amount_to_write: libc::c_uint,
                                         mut output_bit_cursor:
                                             *mut libc::c_uint,
                                         mut value_to_write: u64) {
    if amount_to_write == 0i32 as libc::c_uint { return }
    if amount_to_write >= 64i32 as libc::c_uint {
        panic!("invalid amount_to_write");
    }
    let mut bit_cursor_in_char: libc::c_uint =
        (*output_bit_cursor).wrapping_rem(8i32 as libc::c_uint);
    let mut byte_cursor: libc::c_uint =
        (*output_bit_cursor).wrapping_div(8i32 as libc::c_uint);
    let mut remaining_bits_in_char: libc::c_uint =
        (8i32 as libc::c_uint).wrapping_sub(bit_cursor_in_char);
    if amount_to_write <= remaining_bits_in_char {
        let mut cleanup_mask: u64 =
            !(((1i32 as u64) <<
                   amount_to_write).wrapping_sub(1i32 as libc::c_ulong) <<
                  remaining_bits_in_char.wrapping_sub(amount_to_write));
        let mut buffer: u64 =
            *output.offset(byte_cursor as isize) as u64;
        buffer =
            buffer & cleanup_mask |
                value_to_write <<
                    remaining_bits_in_char.wrapping_sub(amount_to_write);
        *output.offset(byte_cursor as isize) = buffer as libc::c_uchar;
        *output_bit_cursor =
            (*output_bit_cursor).wrapping_add(amount_to_write)
    } else {
        /*copy remaining_bits_in_char, allowing further copies to be byte aligned */
        let mut write_buffer: u64 =
            value_to_write >>
                amount_to_write.wrapping_sub(remaining_bits_in_char);
        let mut cleanup_mask_0: u64 =
            !((1i32 << remaining_bits_in_char) - 1i32) as u64;
        let mut buffer_0: u64 =
            *output.offset(byte_cursor as isize) as u64;
        buffer_0 = buffer_0 & cleanup_mask_0 | write_buffer;
        *output.offset(byte_cursor as isize) = buffer_0 as libc::c_uchar;
        *output_bit_cursor =
            (*output_bit_cursor).wrapping_add(remaining_bits_in_char);
        byte_cursor = (*output_bit_cursor).wrapping_div(8i32 as libc::c_uint);
        /*write out as many as possible full bytes*/
        let mut still_to_write: u64 =
            amount_to_write.wrapping_sub(remaining_bits_in_char) as
                u64; // end while
        while still_to_write > 8i32 as libc::c_ulong {
            write_buffer =
                value_to_write >>
                    still_to_write.wrapping_sub(8i32 as libc::c_ulong) &
                    0xffi32 as u64;
            *output.offset(byte_cursor as isize) =
                write_buffer as libc::c_uchar;
            *output_bit_cursor =
                (*output_bit_cursor).wrapping_add(8i32 as libc::c_uint);
            byte_cursor = byte_cursor.wrapping_add(1);
            still_to_write =
                (still_to_write as
                     libc::c_ulong).wrapping_sub(8i32 as libc::c_ulong) as
                    u64 as u64
        }
        /*once here, only the still_to_write-LSBs of value_to_write are to be written
       * with their MSB as the MSB of the output[byte_cursor] */
        if still_to_write > 0i32 as libc::c_ulong {
            write_buffer =
                value_to_write &
                    ((1i32 << still_to_write) - 1i32) as libc::c_ulong;
            let mut cleanup_mask_1: u64 =
                !((1i32 << still_to_write) - 1i32 <<
                      (8i32 as libc::c_ulong).wrapping_sub(still_to_write)) as
                    u64;
            write_buffer =
                write_buffer <<
                    (8i32 as libc::c_ulong).wrapping_sub(still_to_write);
            let ref mut fresh0 = *output.offset(byte_cursor as isize);
            *fresh0 =
                (*fresh0 as libc::c_ulong & cleanup_mask_1) as libc::c_uchar;
            let ref mut fresh1 = *output.offset(byte_cursor as isize);
            *fresh1 =
                (*fresh1 as libc::c_ulong | write_buffer) as libc::c_uchar;
            *output_bit_cursor =
                (*output_bit_cursor as
                     libc::c_ulong).wrapping_add(still_to_write) as
                    libc::c_uint as libc::c_uint
        }
    };
    // end else
}
// end bitstream_write
/*----------------------------------------------------------------------------*/
/*
 * Input bitstream read as called by constantWeightEncoding
 * supports reading at most 64 bit at once since the caller will need to add
 * them to the encoding. Given the estimates for log_2(d), this is plentiful
 */
#[no_mangle]
pub unsafe extern "C" fn bitstream_read(stream: *const libc::c_uchar,
                                        bit_amount: libc::c_uint,
                                        mut bit_cursor: *mut libc::c_uint)
 -> u64 {
    if bit_amount == 0i32 as libc::c_uint { return 0i32 as u64 }
    if bit_amount > 64i32 as libc::c_uint {
        panic!("invalid bit_amount");
    }
    let mut extracted_bits: u64 = 0i32 as u64;
    let mut bit_cursor_in_char: libc::c_int =
        (*bit_cursor).wrapping_rem(8i32 as libc::c_uint) as libc::c_int;
    let mut remaining_bits_in_char: libc::c_int = 8i32 - bit_cursor_in_char;
    if bit_amount <= remaining_bits_in_char as libc::c_uint {
        extracted_bits =
            *stream.offset((*bit_cursor).wrapping_div(8i32 as libc::c_uint) as
                               isize) as u64;
        let mut slack_bits: libc::c_int =
            (remaining_bits_in_char as libc::c_uint).wrapping_sub(bit_amount)
                as libc::c_int;
        extracted_bits = extracted_bits >> slack_bits;
        extracted_bits =
            extracted_bits &
                ((1i32 as u64) <<
                     bit_amount).wrapping_sub(1i32 as libc::c_ulong)
    } else {
        let mut byte_cursor: libc::c_uint =
            (*bit_cursor).wrapping_div(8i32 as libc::c_uint);
        let mut still_to_extract: libc::c_uint = bit_amount;
        if bit_cursor_in_char != 0i32 {
            extracted_bits =
                *stream.offset((*bit_cursor).wrapping_div(8i32 as
                                                              libc::c_uint) as
                                   isize) as u64;
            extracted_bits =
                extracted_bits &
                    ((1i32 as u64) <<
                         7i32 -
                             (bit_cursor_in_char -
                                  1i32)).wrapping_sub(1i32 as libc::c_ulong);
            still_to_extract =
                bit_amount.wrapping_sub((7i32 - (bit_cursor_in_char - 1i32))
                                            as libc::c_uint);
            byte_cursor = byte_cursor.wrapping_add(1)
        }
        while still_to_extract > 8i32 as libc::c_uint {
            extracted_bits =
                extracted_bits << 8i32 |
                    *stream.offset(byte_cursor as isize) as u64;
            byte_cursor = byte_cursor.wrapping_add(1);
            still_to_extract =
                still_to_extract.wrapping_sub(8i32 as libc::c_uint)
        }
        /* here byte cursor is on the byte where the still_to_extract MSbs are to be
       taken from */
        extracted_bits =
            extracted_bits << still_to_extract |
                *stream.offset(byte_cursor as isize) as u64 >>
                    (8i32 as libc::c_uint).wrapping_sub(still_to_extract)
    }
    *bit_cursor = (*bit_cursor).wrapping_add(bit_amount);
    return extracted_bits;
}
// end bitstream_read
/*----------------------------------------------------------------------------*/
/* returns the portion of the bitstream read, padded with zeroes if the
   bitstream has less bits than required. Updates the value of the bit cursor */
unsafe extern "C" fn bitstream_read_padded(stream: *const libc::c_uchar,
                                           bitAmount: libc::c_uint,
                                           bitstreamLength: libc::c_uint,
                                           bitCursor: *mut libc::c_uint)
 -> u64 {
    let mut readBitstreamFragment: u64 = 0;
    if (*bitCursor).wrapping_add(bitAmount) < bitstreamLength {
        readBitstreamFragment = bitstream_read(stream, bitAmount, bitCursor)
    } else {
        /*if remaining bits are not sufficient, pad with enough zeroes */
        let mut available_bits: libc::c_uint =
            bitstreamLength.wrapping_sub(*bitCursor);
        if available_bits != 0 {
            readBitstreamFragment =
                bitstream_read(stream, available_bits, bitCursor);
            readBitstreamFragment =
                readBitstreamFragment <<
                    bitAmount.wrapping_sub(available_bits)
        } else { readBitstreamFragment = 0i32 as u64 }
    }
    return readBitstreamFragment;
}
// end bitstream_read_padded
/*----------------------------------------------------------------------------*/
#[inline]
unsafe extern "C" fn estimate_d_u(mut d: *mut libc::c_uint,
                                  mut u: *mut libc::c_uint, n: libc::c_uint,
                                  t: libc::c_uint) {
    *d =
        (0.69315f64 *
             (n as libc::c_double - (t as libc::c_double - 1.0f64) / 2.0f64) /
             t as libc::c_double) as libc::c_uint;
    *u = 0i32 as libc::c_uint;
    let mut tmp: libc::c_uint = *d;
    while tmp != 0 {
        tmp >>= 1i32;
        *u = (*u).wrapping_add(1i32 as libc::c_uint)
    };
}
//end bitstream_read_padded
/*----------------------------------------------------------------------------*/
/* Encodes a bit string into a constant weight N0 polynomials vector*/
#[no_mangle]
pub unsafe extern "C" fn constant_weight_to_binary_approximate(bitstreamOut:
                                                                   *mut libc::c_uchar,
                                                               mut constantWeightIn:
                                                                   *const DIGIT) {
    let mut distancesBetweenOnes: [libc::c_uint; 199] =
        [0i32 as libc::c_uint, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    /*compute the array of inter-ones distances. Note that there
    is an implicit one out of bounds to compute the first distance from */
    let mut last_one_position: libc::c_uint = -1i32 as libc::c_uint;
    let mut idxDistances: libc::c_uint = 0i32 as libc::c_uint;
    let mut current_inspected_position: libc::c_uint = 0i32 as libc::c_uint;
    while current_inspected_position < (2i32 * 57899i32) as libc::c_uint {
        let mut current_inspected_exponent: libc::c_uint = 0;
        let mut current_inspected_poly: libc::c_uint = 0;
        current_inspected_exponent =
            current_inspected_position.wrapping_rem(57899i32 as libc::c_uint);
        current_inspected_poly =
            current_inspected_position.wrapping_div(57899i32 as libc::c_uint);
        if gf2x_get_coeff(constantWeightIn.offset(current_inspected_poly.wrapping_mul(((57899i32
                                                                                            +
                                                                                            (8i32
                                                                                                 <<
                                                                                                 3i32)
                                                                                            -
                                                                                            1i32)
                                                                                           /
                                                                                           (8i32
                                                                                                <<
                                                                                                3i32))
                                                                                          as
                                                                                          libc::c_uint)
                                                      as isize),
                          current_inspected_exponent) == 1i32 as libc::c_ulong
           {
            distancesBetweenOnes[idxDistances as usize] =
                current_inspected_position.wrapping_sub(last_one_position).wrapping_sub(1i32
                                                                                            as
                                                                                            libc::c_uint);
            last_one_position = current_inspected_position;
            idxDistances = idxDistances.wrapping_add(1)
        }
        current_inspected_position =
            current_inspected_position.wrapping_add(1)
    }
    if idxDistances == 199i32 as libc::c_uint {
    } else {
        __assert_fail(b"idxDistances == NUM_ERRORS_T\x00" as *const u8 as
                          *const libc::c_char,
                      b"constant_weight_codec.c\x00" as *const u8 as
                          *const libc::c_char, 212i32 as libc::c_uint,
                      (*::std::mem::transmute::<&[u8; 80],
                                                &[libc::c_char; 80]>(b"void constant_weight_to_binary_approximate(unsigned char *const, const DIGIT *)\x00")).as_ptr());
    }
    /* perform encoding of distances into binary string*/
    let mut onesStillToPlaceOut: libc::c_uint = 199i32 as libc::c_uint;
    let mut inPositionsStillAvailable: libc::c_uint =
        (2i32 * 57899i32) as libc::c_uint;
    let mut outputBitCursor: libc::c_uint = 0i32 as libc::c_uint;
    let mut d: libc::c_uint = 0;
    let mut u: libc::c_uint = 0;
    idxDistances = 0i32 as libc::c_uint;
    while idxDistances < 199i32 as libc::c_uint {
        estimate_d_u(&mut d, &mut u, inPositionsStillAvailable,
                     onesStillToPlaceOut);
        let mut quotient: libc::c_uint = 0;
        if d != 0i32 as libc::c_uint {
            quotient =
                distancesBetweenOnes[idxDistances as usize].wrapping_div(d)
        } else { return }
        /* write out quotient in unary, with the trailing 0, i.e., 1^*0 */
        bitstream_write(bitstreamOut,
                        quotient.wrapping_add(1i32 as libc::c_uint),
                        &mut outputBitCursor,
                        ((1i32 as u64) <<
                             quotient).wrapping_sub(1i32 as libc::c_ulong) <<
                            1i32); // clamp u-minus-one to zero
        let mut remainder: libc::c_uint =
            distancesBetweenOnes[idxDistances as usize].wrapping_rem(d);
        if remainder < ((1i32 << u) as libc::c_uint).wrapping_sub(d) {
            u =
                if u > 0i32 as libc::c_uint {
                    u.wrapping_sub(1i32 as libc::c_uint)
                } else { 0i32 as libc::c_uint };
            bitstream_write(bitstreamOut, u, &mut outputBitCursor,
                            remainder as u64);
        } else {
            bitstream_write(bitstreamOut, u, &mut outputBitCursor,
                            remainder.wrapping_add(((1i32 << u) as
                                                        libc::c_uint).wrapping_sub(d))
                                as u64);
        }
        inPositionsStillAvailable =
            inPositionsStillAvailable.wrapping_sub(distancesBetweenOnes[idxDistances
                                                                            as
                                                                            usize].wrapping_add(1i32
                                                                                                    as
                                                                                                    libc::c_uint));
        onesStillToPlaceOut = onesStillToPlaceOut.wrapping_sub(1);
        idxDistances = idxDistances.wrapping_add(1)
    };
}
/* *
 *
 * <constant_weight_codec.h>
 *
 * @version 2.0 (March 2019)
 *
 * Reference ISO-C11 Implementation of the LEDAcrypt PKC cipher using GCC built-ins.
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
// end constant_weight_to_binary_approximate
/*----------------------------------------------------------------------------*/
#[no_mangle]
pub unsafe extern "C" fn binary_to_constant_weight_approximate(mut constantWeightOut:
                                                                   *mut DIGIT,
                                                               bitstreamIn:
                                                                   *const libc::c_uchar,
                                                               bitLength:
                                                                   libc::c_int)
 -> libc::c_int {
    let mut distancesBetweenOnes: [u32; 199] =
        [0;
            199]; /* assuming trailing slack bits in the input
   stream. In case the slack bits in the input stream are leading, change to
   8- (bitLength %8) - 1 */
    let mut idxDistances: u32 = 0i32 as u32;
    let mut onesStillToPlaceOut: u32 = 199i32 as u32;
    let mut outPositionsStillAvailable: u32 =
        (2i32 * 57899i32) as u32;
    let mut bitstreamInCursor: libc::c_uint = 0i32 as libc::c_uint;
    idxDistances = 0i32 as u32;
    while idxDistances < 199i32 as libc::c_uint &&
              outPositionsStillAvailable > onesStillToPlaceOut {
        /* lack of positions should not be possible */
        if outPositionsStillAvailable < onesStillToPlaceOut ||
               outPositionsStillAvailable < 0i32 as libc::c_uint {
            return 0i32
        }
        /*estimate d and u */
        let mut d: libc::c_uint = 0;
        let mut u: libc::c_uint = 0;
        estimate_d_u(&mut d, &mut u, outPositionsStillAvailable,
                     onesStillToPlaceOut);
        /* read unary-encoded quotient, i.e. leading 1^* 0 */
        let mut quotient: libc::c_uint = 0i32 as libc::c_uint;
        while 1i32 as u64 ==
                  bitstream_read_padded(bitstreamIn, 1i32 as libc::c_uint,
                                        bitLength as libc::c_uint,
                                        &mut bitstreamInCursor) {
            quotient = quotient.wrapping_add(1)
        }
        /* decode truncated binary encoded integer */
        let mut distanceToBeComputed: u32 =
            if u > 0i32 as libc::c_uint {
                bitstream_read_padded(bitstreamIn,
                                      u.wrapping_sub(1i32 as libc::c_uint),
                                      bitLength as libc::c_uint,
                                      &mut bitstreamInCursor)
            } else { 0i32 as libc::c_ulong } as u32;
        if distanceToBeComputed >=
               ((1i32 << u) as libc::c_uint).wrapping_sub(d) {
            distanceToBeComputed =
                (distanceToBeComputed as
                     libc::c_uint).wrapping_mul(2i32 as libc::c_uint) as
                    u32 as u32;
            distanceToBeComputed =
                (distanceToBeComputed as
                     libc::c_ulong).wrapping_add(bitstream_read_padded(bitstreamIn,
                                                                       1i32 as
                                                                           libc::c_uint,
                                                                       bitLength
                                                                           as
                                                                           libc::c_uint,
                                                                       &mut bitstreamInCursor))
                    as u32 as u32;
            distanceToBeComputed =
                (distanceToBeComputed as
                     libc::c_uint).wrapping_sub(((1i32 << u) as
                                                     libc::c_uint).wrapping_sub(d))
                    as u32 as u32
        }
        distancesBetweenOnes[idxDistances as usize] =
            distanceToBeComputed.wrapping_add(quotient.wrapping_mul(d));
        outPositionsStillAvailable =
            (outPositionsStillAvailable as
                 libc::c_uint).wrapping_sub(distancesBetweenOnes[idxDistances
                                                                     as
                                                                     usize].wrapping_add(1i32
                                                                                             as
                                                                                             libc::c_uint))
                as u32 as u32;
        onesStillToPlaceOut = onesStillToPlaceOut.wrapping_sub(1);
        idxDistances = idxDistances.wrapping_add(1)
    }
    if outPositionsStillAvailable == onesStillToPlaceOut {
        while idxDistances < 199i32 as libc::c_uint {
            distancesBetweenOnes[idxDistances as usize] = 0i32 as u32;
            idxDistances = idxDistances.wrapping_add(1)
        }
    }
    if outPositionsStillAvailable < onesStillToPlaceOut { return 0i32 }
    if bitstreamInCursor < (48i32 * 8i32) as libc::c_uint { return 0i32 }
    /*encode ones according to distancesBetweenOnes into constantWeightOut */
    let mut current_one_position: libc::c_int = -1i32;
    let mut i: libc::c_int = 0i32;
    while i < 199i32 {
        current_one_position =
            (current_one_position as
                 libc::c_uint).wrapping_add(distancesBetweenOnes[i as
                                                                     usize].wrapping_add(1i32
                                                                                             as
                                                                                             libc::c_uint))
                as libc::c_int as libc::c_int;
        if current_one_position >= 2i32 * 57899i32 { return 0i32 }
        let mut polyIndex: libc::c_uint =
            (current_one_position / 57899i32) as libc::c_uint;
        let mut exponent: libc::c_uint =
            (current_one_position % 57899i32) as libc::c_uint;
        gf2x_set_coeff(constantWeightOut.offset((((57899i32 + (8i32 << 3i32) -
                                                       1i32) / (8i32 << 3i32))
                                                     as
                                                     libc::c_uint).wrapping_mul(polyIndex)
                                                    as isize), exponent,
                       1i32 as DIGIT);
        i += 1
    }
    return 1i32;
}
// end binary_to_constant_weight_approximate
