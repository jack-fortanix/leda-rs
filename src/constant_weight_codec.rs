use crate::consts::*;
use crate::gf2x_arith::*;
use crate::types::*;

pub fn bitstream_write(
    output: &mut [u8],
    amount_to_write: u32,
    output_bit_cursor: &mut u32,
    value_to_write: u64,
) {
    if amount_to_write == 0 {
        return;
    }
    if amount_to_write >= 64 {
        panic!("invalid amount_to_write in bitstream_write");
    }

    let bit_cursor_in_char: u32 = output_bit_cursor.wrapping_rem(8i32 as u32);
    let mut byte_cursor: u32 = output_bit_cursor.wrapping_div(8i32 as u32);
    let remaining_bits_in_char: u32 = (8i32 as u32).wrapping_sub(bit_cursor_in_char);
    if amount_to_write <= remaining_bits_in_char {
        let cleanup_mask: u64 = !(((1i32 as u64) << amount_to_write).wrapping_sub(1i32 as u64)
            << remaining_bits_in_char.wrapping_sub(amount_to_write));
        let mut buffer: u64 = output[byte_cursor as usize] as u64;
        buffer = buffer & cleanup_mask
            | value_to_write << remaining_bits_in_char.wrapping_sub(amount_to_write);
        output[byte_cursor as usize] = buffer as u8;
        *output_bit_cursor += amount_to_write;
    } else {
        /*copy remaining_bits_in_char, allowing further copies to be byte aligned */
        let mut write_buffer: u64 =
            value_to_write >> amount_to_write.wrapping_sub(remaining_bits_in_char);
        let cleanup_mask_0: u64 = !((1i32 << remaining_bits_in_char) - 1i32) as u64;
        let mut buffer: u64 = output[byte_cursor as usize] as u64;
        buffer = buffer & cleanup_mask_0 | write_buffer;
        output[byte_cursor as usize] = buffer as u8;
        *output_bit_cursor += remaining_bits_in_char;
        byte_cursor = output_bit_cursor.wrapping_div(8i32 as u32);
        /*write out as many as possible full bytes*/
        let mut still_to_write: u64 = amount_to_write.wrapping_sub(remaining_bits_in_char) as u64; // end while
        while still_to_write > 8i32 as u64 {
            write_buffer =
                value_to_write >> still_to_write.wrapping_sub(8i32 as u64) & 0xffi32 as u64;
            output[byte_cursor as usize] = write_buffer as u8;
            *output_bit_cursor += 8;
            byte_cursor = byte_cursor.wrapping_add(1);
            still_to_write = (still_to_write as u64).wrapping_sub(8i32 as u64) as u64 as u64
        }
        /*once here, only the still_to_write-LSBs of value_to_write are to be written
         * with their MSB as the MSB of the output[byte_cursor] */
        if still_to_write > 0i32 as u64 {
            write_buffer = value_to_write & ((1i32 << still_to_write) - 1i32) as u64;
            let cleanup_mask_1: u64 = !((1i32 << still_to_write) - 1i32
                << (8i32 as u64).wrapping_sub(still_to_write))
                as u64;
            write_buffer = write_buffer << (8i32 as u64).wrapping_sub(still_to_write);
            output[byte_cursor as usize] &= cleanup_mask_1 as u8;
            output[byte_cursor as usize] |= write_buffer as u8;
            *output_bit_cursor =
                (*output_bit_cursor as u64).wrapping_add(still_to_write) as u32 as u32
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

pub fn bitstream_read(stream: &[u8], bit_amount: u32, bit_cursor: &mut u32) -> u64 {
    if bit_amount == 0 {
        return 0;
    }
    if bit_amount > 64 {
        panic!("invalid bit_amount in bitstream_read");
    }
    let mut extracted_bits: u64 = 0i32 as u64;
    let bit_cursor_in_char: i32 = (*bit_cursor).wrapping_rem(8i32 as u32) as i32;
    let remaining_bits_in_char: i32 = 8i32 - bit_cursor_in_char;
    if bit_amount <= remaining_bits_in_char as u32 {
        extracted_bits = stream[(*bit_cursor).wrapping_div(8i32 as u32) as usize] as u64;
        let slack_bits: i32 = (remaining_bits_in_char as u32).wrapping_sub(bit_amount) as i32;
        extracted_bits = extracted_bits >> slack_bits;
        extracted_bits = extracted_bits & ((1i32 as u64) << bit_amount).wrapping_sub(1i32 as u64)
    } else {
        let mut byte_cursor: u32 = (*bit_cursor).wrapping_div(8i32 as u32);
        let mut still_to_extract: u32 = bit_amount;
        if bit_cursor_in_char != 0 {
            extracted_bits = stream[(*bit_cursor).wrapping_div(8i32 as u32) as usize] as u64;
            extracted_bits = extracted_bits
                & ((1i32 as u64) << 7i32 - (bit_cursor_in_char - 1i32)).wrapping_sub(1i32 as u64);
            still_to_extract = bit_amount.wrapping_sub((7i32 - (bit_cursor_in_char - 1i32)) as u32);
            byte_cursor = byte_cursor.wrapping_add(1)
        }
        while still_to_extract > 8 {
            extracted_bits = extracted_bits << 8 | stream[byte_cursor as usize] as u64;
            byte_cursor = byte_cursor.wrapping_add(1);
            still_to_extract = still_to_extract.wrapping_sub(8i32 as u32)
        }
        /* here byte cursor is on the byte where the still_to_extract MSbs are to be
        taken from */
        extracted_bits = (extracted_bits << still_to_extract)
            | ((stream[byte_cursor as usize] as u64) >> (8 - still_to_extract));
    }
    *bit_cursor = (*bit_cursor).wrapping_add(bit_amount);
    return extracted_bits;
}
// end bitstream_read
/*----------------------------------------------------------------------------*/
/* returns the portion of the bitstream read, padded with zeroes if the
bitstream has less bits than required. Updates the value of the bit cursor */
fn bitstream_read_padded(stream: &[u8], bitAmount: u32, bitCursor: &mut u32) -> u64 {
    if (*bitCursor).wrapping_add(bitAmount) < stream.len() as u32 {
        return bitstream_read(stream, bitAmount, bitCursor);
    } else {
        /*if remaining bits are not sufficient, pad with enough zeroes */
        let available_bits: u32 = (stream.len() as u32) - *bitCursor;
        if available_bits != 0 {
            let readBitstreamFragment = bitstream_read(stream, available_bits, bitCursor);
            return readBitstreamFragment << (bitAmount - available_bits);
        } else {
            return 0;
        }
    }
}

fn estimate_d_u(n: u32, t: u32) -> (u32, u32) {
    let d = (0.69315f64 * (n as f64 - (t as f64 - 1.0f64) / 2.0f64) / t as f64) as u32;
    let mut u = 0u32;
    let mut tmp = d;
    while tmp != 0 {
        tmp >>= 1;
        u = u + 1;
    }
    return (d, u);
}

/* Encodes a bit string into a constant weight N0 polynomials vector*/
pub fn constant_weight_to_binary_approximate(bitstreamOut: &mut [u8], constantWeightIn: &[DIGIT]) {
    let mut distancesBetweenOnes: [u32; NUM_ERRORS] = [0; NUM_ERRORS];
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
        if gf2x_get_coeff(
            &constantWeightIn[current_inspected_poly.wrapping_mul(
                ((crate::consts::P as i32 + (8i32 << 3i32) - 1i32) / (8i32 << 3i32)) as u32,
            ) as usize..],
            current_inspected_exponent,
        ) == 1i32 as u64
        {
            distancesBetweenOnes[idxDistances as usize] = current_inspected_position
                .wrapping_sub(last_one_position)
                .wrapping_sub(1i32 as u32);
            last_one_position = current_inspected_position;
            idxDistances = idxDistances.wrapping_add(1)
        }
        current_inspected_position = current_inspected_position.wrapping_add(1)
    }
    if idxDistances != NUM_ERRORS as u32 {
        panic!("idxDistances != NUM_ERRORS_T");
    }
    /* perform encoding of distances into binary string*/
    let mut onesStillToPlaceOut: u32 = NUM_ERRORS as u32;
    let mut inPositionsStillAvailable: u32 = (2i32 * crate::consts::P as i32) as u32;
    let mut outputBitCursor: u32 = 0i32 as u32;
    idxDistances = 0i32 as u32;
    while idxDistances < NUM_ERRORS as u32 {
        let (d, u) = estimate_d_u(inPositionsStillAvailable, onesStillToPlaceOut);
        let mut quotient: u32 = 0;
        if d != 0i32 as u32 {
            quotient = distancesBetweenOnes[idxDistances as usize].wrapping_div(d)
        } else {
            return;
        }
        /* write out quotient in unary, with the trailing 0, i.e., 1^*0 */
        bitstream_write(
            bitstreamOut,
            quotient.wrapping_add(1i32 as u32),
            &mut outputBitCursor,
            ((1i32 as u64) << quotient).wrapping_sub(1i32 as u64) << 1i32,
        ); // clamp u-minus-one to zero
        let remainder: u32 = distancesBetweenOnes[idxDistances as usize].wrapping_rem(d);
        if remainder < ((1i32 << u) as u32).wrapping_sub(d) {
            let u = if u > 0i32 as u32 {
                u.wrapping_sub(1i32 as u32)
            } else {
                0i32 as u32
            };
            bitstream_write(bitstreamOut, u, &mut outputBitCursor, remainder as u64);
        } else {
            bitstream_write(
                bitstreamOut,
                u,
                &mut outputBitCursor,
                remainder.wrapping_add(((1i32 << u) as u32).wrapping_sub(d)) as u64,
            );
        }
        inPositionsStillAvailable = inPositionsStillAvailable
            .wrapping_sub(distancesBetweenOnes[idxDistances as usize].wrapping_add(1i32 as u32));
        onesStillToPlaceOut = onesStillToPlaceOut.wrapping_sub(1);
        idxDistances = idxDistances.wrapping_add(1)
    }
}

pub fn binary_to_constant_weight_approximate(
    constantWeightOut: &mut [DIGIT],
    bitstreamIn: &[u8],
) -> bool {
    let mut distancesBetweenOnes: [u32; NUM_ERRORS] = [0; NUM_ERRORS];
    let mut idxDistances: u32 = 0i32 as u32;
    let mut onesStillToPlaceOut: u32 = NUM_ERRORS as u32;
    let mut outPositionsStillAvailable: u32 = (2i32 * crate::consts::P as i32) as u32;
    let mut bitstreamInCursor: u32 = 0i32 as u32;
    idxDistances = 0i32 as u32;
    while idxDistances < NUM_ERRORS as u32 && outPositionsStillAvailable > onesStillToPlaceOut {
        /* lack of positions should not be possible */
        if outPositionsStillAvailable < onesStillToPlaceOut
            || outPositionsStillAvailable < 0i32 as u32
        {
            return false;
        }
        /*estimate d and u */
        let (d, u) = estimate_d_u(outPositionsStillAvailable, onesStillToPlaceOut);
        /* read unary-encoded quotient, i.e. leading 1^* 0 */
        let mut quotient: u32 = 0i32 as u32;
        while 1i32 as u64 == bitstream_read_padded(&bitstreamIn, 1u32, &mut bitstreamInCursor) {
            quotient = quotient.wrapping_add(1)
        }
        /* decode truncated binary encoded integer */
        let mut distanceToBeComputed: u32 = if u > 0i32 as u32 {
            bitstream_read_padded(
                &bitstreamIn,
                u.wrapping_sub(1i32 as u32),
                &mut bitstreamInCursor,
            )
        } else {
            0i32 as u64
        } as u32;
        if distanceToBeComputed >= ((1i32 << u) as u32).wrapping_sub(d) {
            distanceToBeComputed =
                (distanceToBeComputed as u32).wrapping_mul(2i32 as u32) as u32 as u32;
            distanceToBeComputed = (distanceToBeComputed as u64).wrapping_add(
                bitstream_read_padded(&bitstreamIn, 1i32 as u32, &mut bitstreamInCursor),
            ) as u32 as u32;
            distanceToBeComputed = (distanceToBeComputed as u32)
                .wrapping_sub(((1i32 << u) as u32).wrapping_sub(d))
                as u32 as u32
        }
        distancesBetweenOnes[idxDistances as usize] =
            distanceToBeComputed.wrapping_add(quotient.wrapping_mul(d));
        outPositionsStillAvailable = (outPositionsStillAvailable as u32)
            .wrapping_sub(distancesBetweenOnes[idxDistances as usize].wrapping_add(1i32 as u32))
            as u32 as u32;
        onesStillToPlaceOut = onesStillToPlaceOut.wrapping_sub(1);
        idxDistances = idxDistances.wrapping_add(1)
    }
    if outPositionsStillAvailable == onesStillToPlaceOut {
        while idxDistances < NUM_ERRORS as u32 {
            distancesBetweenOnes[idxDistances as usize] = 0i32 as u32;
            idxDistances = idxDistances.wrapping_add(1)
        }
    }
    if outPositionsStillAvailable < onesStillToPlaceOut {
        return false;
    }
    if bitstreamInCursor < (48i32 * 8i32) as u32 {
        return false;
    }
    /*encode ones according to distancesBetweenOnes into constantWeightOut */
    let mut current_one_position: i32 = -1i32;
    for i in 0..NUM_ERRORS {
        current_one_position = (current_one_position as u32)
            .wrapping_add(distancesBetweenOnes[i].wrapping_add(1i32 as u32))
            as i32 as i32;
        if current_one_position >= 2 * crate::consts::P as i32 {
            return false;
        }
        let polyIndex = (current_one_position / crate::consts::P as i32) as usize;
        let exponent = (current_one_position % crate::consts::P as i32) as usize;
        gf2x_set_coeff(
            &mut constantWeightOut[NUM_DIGITS_GF2X_ELEMENT * polyIndex..],
            exponent,
            1 as DIGIT,
        );
    }
    return true;
}
