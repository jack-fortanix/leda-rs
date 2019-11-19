use crate::types::*;
use crate::gf2x_arith::*;


pub unsafe fn bitstream_write(mut output: *mut u8,
                                         amount_to_write: u32,
                                         mut output_bit_cursor:
                                             *mut u32,
                                         mut value_to_write: u64) {
    if amount_to_write == 0i32 as u32 { return }
    if amount_to_write >= 64i32 as u32 {
        panic!("invalid amount_to_write");
    }
    let mut bit_cursor_in_char: u32 =
        (*output_bit_cursor).wrapping_rem(8i32 as u32);
    let mut byte_cursor: u32 =
        (*output_bit_cursor).wrapping_div(8i32 as u32);
    let mut remaining_bits_in_char: u32 =
        (8i32 as u32).wrapping_sub(bit_cursor_in_char);
    if amount_to_write <= remaining_bits_in_char {
        let mut cleanup_mask: u64 =
            !(((1i32 as u64) <<
                   amount_to_write).wrapping_sub(1i32 as u64) <<
                  remaining_bits_in_char.wrapping_sub(amount_to_write));
        let mut buffer: u64 =
            *output.offset(byte_cursor as isize) as u64;
        buffer =
            buffer & cleanup_mask |
                value_to_write <<
                    remaining_bits_in_char.wrapping_sub(amount_to_write);
        *output.offset(byte_cursor as isize) = buffer as u8;
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
        *output.offset(byte_cursor as isize) = buffer_0 as u8;
        *output_bit_cursor =
            (*output_bit_cursor).wrapping_add(remaining_bits_in_char);
        byte_cursor = (*output_bit_cursor).wrapping_div(8i32 as u32);
        /*write out as many as possible full bytes*/
        let mut still_to_write: u64 =
            amount_to_write.wrapping_sub(remaining_bits_in_char) as
                u64; // end while
        while still_to_write > 8i32 as u64 {
            write_buffer =
                value_to_write >>
                    still_to_write.wrapping_sub(8i32 as u64) &
                    0xffi32 as u64;
            *output.offset(byte_cursor as isize) =
                write_buffer as u8;
            *output_bit_cursor =
                (*output_bit_cursor).wrapping_add(8i32 as u32);
            byte_cursor = byte_cursor.wrapping_add(1);
            still_to_write =
                (still_to_write as
                     u64).wrapping_sub(8i32 as u64) as
                    u64 as u64
        }
        /*once here, only the still_to_write-LSBs of value_to_write are to be written
       * with their MSB as the MSB of the output[byte_cursor] */
        if still_to_write > 0i32 as u64 {
            write_buffer =
                value_to_write &
                    ((1i32 << still_to_write) - 1i32) as u64;
            let mut cleanup_mask_1: u64 =
                !((1i32 << still_to_write) - 1i32 <<
                      (8i32 as u64).wrapping_sub(still_to_write)) as
                    u64;
            write_buffer =
                write_buffer <<
                    (8i32 as u64).wrapping_sub(still_to_write);
            let ref mut fresh0 = *output.offset(byte_cursor as isize);
            *fresh0 =
                (*fresh0 as u64 & cleanup_mask_1) as u8;
            let ref mut fresh1 = *output.offset(byte_cursor as isize);
            *fresh1 =
                (*fresh1 as u64 | write_buffer) as u8;
            *output_bit_cursor =
                (*output_bit_cursor as
                     u64).wrapping_add(still_to_write) as
                    u32 as u32
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

pub unsafe fn bitstream_read(stream: *const u8,
                                        bit_amount: u32,
                                        mut bit_cursor: *mut u32)
 -> u64 {
    if bit_amount == 0i32 as u32 { return 0i32 as u64 }
    if bit_amount > 64i32 as u32 {
        panic!("invalid bit_amount");
    }
    let mut extracted_bits: u64 = 0i32 as u64;
    let mut bit_cursor_in_char: i32 =
        (*bit_cursor).wrapping_rem(8i32 as u32) as i32;
    let mut remaining_bits_in_char: i32 = 8i32 - bit_cursor_in_char;
    if bit_amount <= remaining_bits_in_char as u32 {
        extracted_bits =
            *stream.offset((*bit_cursor).wrapping_div(8i32 as u32) as
                               isize) as u64;
        let mut slack_bits: i32 =
            (remaining_bits_in_char as u32).wrapping_sub(bit_amount)
                as i32;
        extracted_bits = extracted_bits >> slack_bits;
        extracted_bits =
            extracted_bits &
                ((1i32 as u64) <<
                     bit_amount).wrapping_sub(1i32 as u64)
    } else {
        let mut byte_cursor: u32 =
            (*bit_cursor).wrapping_div(8i32 as u32);
        let mut still_to_extract: u32 = bit_amount;
        if bit_cursor_in_char != 0i32 {
            extracted_bits =
                *stream.offset((*bit_cursor).wrapping_div(8i32 as
                                                              u32) as
                                   isize) as u64;
            extracted_bits =
                extracted_bits &
                    ((1i32 as u64) <<
                         7i32 -
                             (bit_cursor_in_char -
                                  1i32)).wrapping_sub(1i32 as u64);
            still_to_extract =
                bit_amount.wrapping_sub((7i32 - (bit_cursor_in_char - 1i32))
                                            as u32);
            byte_cursor = byte_cursor.wrapping_add(1)
        }
        while still_to_extract > 8i32 as u32 {
            extracted_bits =
                extracted_bits << 8i32 |
                    *stream.offset(byte_cursor as isize) as u64;
            byte_cursor = byte_cursor.wrapping_add(1);
            still_to_extract =
                still_to_extract.wrapping_sub(8i32 as u32)
        }
        /* here byte cursor is on the byte where the still_to_extract MSbs are to be
       taken from */
        extracted_bits =
            extracted_bits << still_to_extract |
                *stream.offset(byte_cursor as isize) as u64 >>
                    (8i32 as u32).wrapping_sub(still_to_extract)
    }
    *bit_cursor = (*bit_cursor).wrapping_add(bit_amount);
    return extracted_bits;
}
// end bitstream_read
/*----------------------------------------------------------------------------*/
/* returns the portion of the bitstream read, padded with zeroes if the
   bitstream has less bits than required. Updates the value of the bit cursor */
unsafe fn bitstream_read_padded(stream: *const u8,
                                           bitAmount: u32,
                                           bitstreamLength: u32,
                                           bitCursor: *mut u32)
 -> u64 {
    let mut readBitstreamFragment: u64 = 0;
    if (*bitCursor).wrapping_add(bitAmount) < bitstreamLength {
        readBitstreamFragment = bitstream_read(stream, bitAmount, bitCursor)
    } else {
        /*if remaining bits are not sufficient, pad with enough zeroes */
        let mut available_bits: u32 =
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
unsafe fn estimate_d_u(mut d: *mut u32,
                                  mut u: *mut u32, n: u32,
                                  t: u32) {
    *d =
        (0.69315f64 *
             (n as libc::c_double - (t as libc::c_double - 1.0f64) / 2.0f64) /
             t as libc::c_double) as u32;
    *u = 0i32 as u32;
    let mut tmp: u32 = *d;
    while tmp != 0 {
        tmp >>= 1i32;
        *u = (*u).wrapping_add(1i32 as u32)
    };
}
//end bitstream_read_padded
/*----------------------------------------------------------------------------*/
/* Encodes a bit string into a constant weight N0 polynomials vector*/

pub unsafe fn constant_weight_to_binary_approximate(bitstreamOut:
                                                                   *mut u8,
                                                               mut constantWeightIn:
                                                                   *const DIGIT) {
    let mut distancesBetweenOnes: [u32; 199] = [0; 199];
    /*compute the array of inter-ones distances. Note that there
    is an implicit one out of bounds to compute the first distance from */
    let mut last_one_position: u32 = -1i32 as u32;
    let mut idxDistances: u32 = 0i32 as u32;
    let mut current_inspected_position: u32 = 0i32 as u32;
    while current_inspected_position < (2i32 * crate::consts::P as i32) as u32 {
        let mut current_inspected_exponent: u32 = 0;
        let mut current_inspected_poly: u32 = 0;
        current_inspected_exponent =
            current_inspected_position.wrapping_rem(crate::consts::P as i32 as u32);
        current_inspected_poly =
            current_inspected_position.wrapping_div(crate::consts::P as i32 as u32);
        if gf2x_get_coeff(constantWeightIn.offset(current_inspected_poly.wrapping_mul(((crate::consts::P as i32
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
                                                                                          u32)
                                                      as isize),
                          current_inspected_exponent) == 1i32 as u64
           {
            distancesBetweenOnes[idxDistances as usize] =
                current_inspected_position.wrapping_sub(last_one_position).wrapping_sub(1i32
                                                                                            as
                                                                                            u32);
            last_one_position = current_inspected_position;
            idxDistances = idxDistances.wrapping_add(1)
        }
        current_inspected_position =
            current_inspected_position.wrapping_add(1)
    }
    if idxDistances != 199i32 as u32 {
        panic!("idxDistances != NUM_ERRORS_T");
    }
    /* perform encoding of distances into binary string*/
    let mut onesStillToPlaceOut: u32 = 199i32 as u32;
    let mut inPositionsStillAvailable: u32 =
        (2i32 * crate::consts::P as i32) as u32;
    let mut outputBitCursor: u32 = 0i32 as u32;
    let mut d: u32 = 0;
    let mut u: u32 = 0;
    idxDistances = 0i32 as u32;
    while idxDistances < 199i32 as u32 {
        estimate_d_u(&mut d, &mut u, inPositionsStillAvailable,
                     onesStillToPlaceOut);
        let mut quotient: u32 = 0;
        if d != 0i32 as u32 {
            quotient =
                distancesBetweenOnes[idxDistances as usize].wrapping_div(d)
        } else { return }
        /* write out quotient in unary, with the trailing 0, i.e., 1^*0 */
        bitstream_write(bitstreamOut,
                        quotient.wrapping_add(1i32 as u32),
                        &mut outputBitCursor,
                        ((1i32 as u64) <<
                             quotient).wrapping_sub(1i32 as u64) <<
                            1i32); // clamp u-minus-one to zero
        let mut remainder: u32 =
            distancesBetweenOnes[idxDistances as usize].wrapping_rem(d);
        if remainder < ((1i32 << u) as u32).wrapping_sub(d) {
            u =
                if u > 0i32 as u32 {
                    u.wrapping_sub(1i32 as u32)
                } else { 0i32 as u32 };
            bitstream_write(bitstreamOut, u, &mut outputBitCursor,
                            remainder as u64);
        } else {
            bitstream_write(bitstreamOut, u, &mut outputBitCursor,
                            remainder.wrapping_add(((1i32 << u) as
                                                        u32).wrapping_sub(d))
                                as u64);
        }
        inPositionsStillAvailable =
            inPositionsStillAvailable.wrapping_sub(distancesBetweenOnes[idxDistances
                                                                            as
                                                                            usize].wrapping_add(1i32
                                                                                                    as
                                                                                                    u32));
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

pub unsafe fn binary_to_constant_weight_approximate(mut constantWeightOut:
                                                                   *mut DIGIT,
                                                               bitstreamIn:
                                                                   *const u8,
                                                               bitLength:
                                                                   i32)
 -> i32 {
    let mut distancesBetweenOnes: [u32; 199] =
        [0;
            199]; /* assuming trailing slack bits in the input
   stream. In case the slack bits in the input stream are leading, change to
   8- (bitLength %8) - 1 */
    let mut idxDistances: u32 = 0i32 as u32;
    let mut onesStillToPlaceOut: u32 = 199i32 as u32;
    let mut outPositionsStillAvailable: u32 =
        (2i32 * crate::consts::P as i32) as u32;
    let mut bitstreamInCursor: u32 = 0i32 as u32;
    idxDistances = 0i32 as u32;
    while idxDistances < 199i32 as u32 &&
              outPositionsStillAvailable > onesStillToPlaceOut {
        /* lack of positions should not be possible */
        if outPositionsStillAvailable < onesStillToPlaceOut ||
               outPositionsStillAvailable < 0i32 as u32 {
            return 0i32
        }
        /*estimate d and u */
        let mut d: u32 = 0;
        let mut u: u32 = 0;
        estimate_d_u(&mut d, &mut u, outPositionsStillAvailable,
                     onesStillToPlaceOut);
        /* read unary-encoded quotient, i.e. leading 1^* 0 */
        let mut quotient: u32 = 0i32 as u32;
        while 1i32 as u64 ==
                  bitstream_read_padded(bitstreamIn, 1i32 as u32,
                                        bitLength as u32,
                                        &mut bitstreamInCursor) {
            quotient = quotient.wrapping_add(1)
        }
        /* decode truncated binary encoded integer */
        let mut distanceToBeComputed: u32 =
            if u > 0i32 as u32 {
                bitstream_read_padded(bitstreamIn,
                                      u.wrapping_sub(1i32 as u32),
                                      bitLength as u32,
                                      &mut bitstreamInCursor)
            } else { 0i32 as u64 } as u32;
        if distanceToBeComputed >=
               ((1i32 << u) as u32).wrapping_sub(d) {
            distanceToBeComputed =
                (distanceToBeComputed as
                     u32).wrapping_mul(2i32 as u32) as
                    u32 as u32;
            distanceToBeComputed =
                (distanceToBeComputed as
                     u64).wrapping_add(bitstream_read_padded(bitstreamIn,
                                                                       1i32 as
                                                                           u32,
                                                                       bitLength
                                                                           as
                                                                           u32,
                                                                       &mut bitstreamInCursor))
                    as u32 as u32;
            distanceToBeComputed =
                (distanceToBeComputed as
                     u32).wrapping_sub(((1i32 << u) as
                                                     u32).wrapping_sub(d))
                    as u32 as u32
        }
        distancesBetweenOnes[idxDistances as usize] =
            distanceToBeComputed.wrapping_add(quotient.wrapping_mul(d));
        outPositionsStillAvailable =
            (outPositionsStillAvailable as
                 u32).wrapping_sub(distancesBetweenOnes[idxDistances
                                                                     as
                                                                     usize].wrapping_add(1i32
                                                                                             as
                                                                                             u32))
                as u32 as u32;
        onesStillToPlaceOut = onesStillToPlaceOut.wrapping_sub(1);
        idxDistances = idxDistances.wrapping_add(1)
    }
    if outPositionsStillAvailable == onesStillToPlaceOut {
        while idxDistances < 199i32 as u32 {
            distancesBetweenOnes[idxDistances as usize] = 0i32 as u32;
            idxDistances = idxDistances.wrapping_add(1)
        }
    }
    if outPositionsStillAvailable < onesStillToPlaceOut { return 0i32 }
    if bitstreamInCursor < (48i32 * 8i32) as u32 { return 0i32 }
    /*encode ones according to distancesBetweenOnes into constantWeightOut */
    let mut current_one_position: i32 = -1i32;
    let mut i: i32 = 0i32;
    while i < 199i32 {
        current_one_position =
            (current_one_position as
                 u32).wrapping_add(distancesBetweenOnes[i as
                                                                     usize].wrapping_add(1i32
                                                                                             as
                                                                                             u32))
                as i32 as i32;
        if current_one_position >= 2i32 * crate::consts::P as i32 { return 0i32 }
        let mut polyIndex: u32 =
            (current_one_position / crate::consts::P as i32) as u32;
        let mut exponent: u32 =
            (current_one_position % crate::consts::P as i32) as u32;
        gf2x_set_coeff(constantWeightOut.offset((((crate::consts::P as i32 + (8i32 << 3i32) -
                                                       1i32) / (8i32 << 3i32))
                                                     as
                                                     u32).wrapping_mul(polyIndex)
                                                    as isize), exponent,
                       1i32 as DIGIT);
        i += 1
    }
    return 1i32;
}
// end binary_to_constant_weight_approximate
