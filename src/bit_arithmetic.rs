use crate::Precisions;

const RHO_BITS: u8 = 6;
const RHO_MASK: u32 = (1u32 << RHO_BITS) - 1;

// rhoEncodedFlag returns the a bitmask which, when bitwise-and'd with a sparse entry, is 0 if and only if the entry is not rhoW-encoded.
pub(crate) fn rho_encoded_flag(precisions: &Precisions) -> u32 {
    1 << if precisions.sparse > precisions.dense + RHO_BITS {
        precisions.sparse
    } else {
        precisions.dense + RHO_BITS
    }
}

// encodeSparse returns a sparse entry for an index and rhoW value at the specified normal and sparse precisions.
pub(crate) fn encode_sparse(precisions: &Precisions, sparse_index: u32, sparse_rho_w: u8) -> u32 {
    // when all the bits included in sparseIndex but not normalIndex are 0, we store normalIndex and sparseRhoW
    // otherwise we store sparseIndex because it contains all zeroes counted by normalRhoW
    // see https://github.com/google/zetasketch/blob/443927e65960e0596714b11137d73dc76ba1d969/java/com/google/zetasketch/internal/hllplus/Encoding.java#L111
    if last_n_bits(sparse_index, precisions.sparse - precisions.dense) != 0 {
        // sparse index starts with 0 (because it's precision is < 32) and it consists of normal index + all the zeroes counted by rhoW + maybe more bits
        sparse_index
    } else {
        // this only removes zeros; we can reproduce sparseIndex as normalIndex << (sparsePrecision - normalPrecision)
        let dense_index = sparse_index >> (precisions.sparse - precisions.dense);
        rho_encoded_flag(precisions) | (dense_index << RHO_BITS) | (sparse_rho_w as u32)
    }
}

// decodeSparse returns an index and rhoW value for a given sparse entry at the specified normal and sparse precisions.
pub(crate) fn decode_sparse(precisions: &Precisions, encoded: u32) -> (u32, u8) {
    let rho_encoded_flag = rho_encoded_flag(precisions);
    if encoded & rho_encoded_flag == 0 {
        (
            encoded,
            leading_zeroes_after_first_n_bits_u32(encoded, 32 - precisions.sparse) + 1,
        )
    } else {
        (
            ((encoded ^ rho_encoded_flag) >> RHO_BITS) << (precisions.sparse - precisions.dense),
            (encoded & RHO_MASK) as u8,
        )
    }
}

// downgradeIndex takes the index a hash under oldPrecision and returns the index of that hash under a (lower) newPrecision.
pub(crate) fn downgrade_index(index: u32, old_precision: u8, new_precision: u8) -> u32 {
    return index >> (old_precision - new_precision);
}

// super::downgrade_rho_w takes the rhoW a hash under oldPrecision and returns the rhoW of that hash under a (lower) newPrecision.
pub(crate) fn downgrade_rho_w(index: u32, rho_w: u8, old_precision: u8, new_precision: u8) -> u8 {
    if rho_w == 0 {
        return 0;
    }
    let precision_reduction = old_precision - new_precision;
    if precision_reduction == 0 {
        return rho_w;
    }

    // the last precisionReduction bits of Index become the first precisionReduction bits of 2^(rhoW - 1)
    let moved_bits = index << (32 - old_precision + new_precision);
    // if they are 0's, rhoW now counts precisionReduction 0's in addition to the 0's it previously counted...
    if moved_bits == 0 {
        return rho_w + old_precision - new_precision;
    }
    // ...otherwise, rhoW now counts just the leading 0's of movedBits (+1 because that's rhoW's convention)
    (moved_bits.leading_zeros() + 1) as u8
}

pub(crate) fn leading_zeroes_after_first_n_bits_u64(hash: u64, n: u8) -> u8 {
    let first_n_bits_zeroed = if n == 0 {
        hash
    } else if n == 64 {
        0
    } else {
        (hash << n) >> n
    };
    (first_n_bits_zeroed.leading_zeros() as u8) - n
}

fn leading_zeroes_after_first_n_bits_u32(hash: u32, n: u8) -> u8 {
    let first_n_bits_zeroed = if n == 0 {
        hash
    } else if n == 64 {
        hash
    } else {
        (hash << n) >> n
    };
    (first_n_bits_zeroed.leading_zeros() as u8) - n
}

pub(crate) fn first_n_bits(hash: u64, n: u8) -> u64 {
    if n == 0 {
        0
    } else {
        hash >> (64 - n)
    }
}

fn last_n_bits(hash: u32, n: u8) -> u32 {
    hash & ((1u32 << n) - 1)
}

#[cfg(test)]
mod tests {

    #[test]
    fn encode_sparse_rho_encoded_zero() {
        let sparse_index = 0b0000000000_0000000000_000000000000; // sparse = normal + 10 0's
        let sparse_rho_w = 0b101010;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected = 0b000000000010000_0000000000_101010; // 1 + padding + normal + rhoW

        let actual = super::encode_sparse(&precisions, sparse_index, sparse_rho_w);

        assert_eq!(expected, actual);
    }

    #[test]
    fn encode_sparse_rho_encoded_nonzero() {
        let sparse_index = 0b000000000000_1111111111_0000000000; // sparse = normal + 10 0's
        let sparse_rho_w = 0b101010;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected = 0b000000000010000_1111111111_101010; // 1 + padding + normal + rhoW

        let actual = super::encode_sparse(&precisions, sparse_index, sparse_rho_w);

        assert_eq!(expected, actual);
    }

    #[test]
    fn encode_sparse_rho_encoded_halfzero() {
        let sparse_index = 0b000000000000_0000011111_0000000000; // sparse = normal + 10 0's
        let sparse_rho_w = 0b101010;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected = 0b000000000010000_0000011111_101010; // 1 + padding + normal + rhoW

        let actual = super::encode_sparse(&precisions, sparse_index, sparse_rho_w);

        assert_eq!(expected, actual);
    }

    #[test]
    fn encode_sparse_not_rho_encoded_zero() {
        let sparse_index = 0b00000000000_0000000000_1111111111; // sparse = normal + at least one nonzero
        let sparse_rho_w = 0b101010;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected = 0b00000000000_0000000000_1111111111; // sparse

        let actual = super::encode_sparse(&precisions, sparse_index, sparse_rho_w);

        assert_eq!(expected, actual);
    }

    #[test]
    fn encode_sparse_not_rho_encoded_nonzero() {
        let sparse_index = 0b000000000000_1111111111_11111111111; // sparse = normal + at least one nonzero
        let sparse_rho_w = 0b101010;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected = 0b000000000000_1111111111_11111111111; // sparse

        let actual = super::encode_sparse(&precisions, sparse_index, sparse_rho_w);

        assert_eq!(expected, actual);
    }

    #[test]
    fn encode_sparse_not_rho_encoded_half_zero() {
        let sparse_index = 0b000000000000_0000011111_1111111111; // sparse = normal + at least one nonzero
        let sparse_rho_w = 0b101010;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected = 0b000000000000_0000011111_1111111111; // sparse

        let actual = super::encode_sparse(&precisions, sparse_index, sparse_rho_w);

        assert_eq!(expected, actual);
    }

    #[test]
    fn decode_sparse_rho_encoded_zero() {
        let encoded = 0b000000000010000_0000000000_101010;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected_index = 0b0000000000_0000000000_000000000000;
        let expected_rho = 0b101010;

        let (actual_index, actual_rho) = super::decode_sparse(&precisions, encoded);

        assert_eq!(expected_index, actual_index);
        assert_eq!(expected_rho, actual_rho);
    }

    #[test]
    fn decode_sparse_rho_encoded_nonzero() {
        let encoded = 0b000000000010000_1111111111_101010;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected_index = 0b000000000000_1111111111_0000000000;
        let expected_rho = 0b101010;

        let (actual_index, actual_rho) = super::decode_sparse(&precisions, encoded);

        assert_eq!(expected_index, actual_index);
        assert_eq!(expected_rho, actual_rho);
    }

    #[test]
    fn decode_sparse_rho_encoded_halfzero() {
        let encoded = 0b000000000010000_0000011111_101010;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected_index = 0b000000000000_0000011111_0000000000;
        let expected_rho = 0b101010;

        let (actual_index, actual_rho) = super::decode_sparse(&precisions, encoded);

        assert_eq!(expected_index, actual_index);
        assert_eq!(expected_rho, actual_rho);
    }

    #[test]
    fn decode_sparse_not_rho_encoded_zero() {
        let encoded = 0b000000000000_0000000000_1111111111;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected_index = 0b000000000000_0000000000_1111111111;
        let expected_rho = 11; // rhoW counts 10 leading 0's of 0000000000_1111111111

        let (actual_index, actual_rho) = super::decode_sparse(&precisions, encoded);

        assert_eq!(expected_index, actual_index);
        assert_eq!(expected_rho, actual_rho);
    }

    #[test]
    fn decode_sparse_not_rho_encoded_nonzero() {
        let encoded = 0b000000000000_1111111111_1111111111;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected_index = 0b000000000000_1111111111_1111111111;
        let expected_rho = 1; // rhoW counts 0 leading 0's of 1111111111_1111111111

        let (actual_index, actual_rho) = super::decode_sparse(&precisions, encoded);

        assert_eq!(expected_index, actual_index);
        assert_eq!(expected_rho, actual_rho);
    }

    #[test]
    fn decode_sparse_not_rho_encoded_half_zero() {
        let encoded = 0b000000000000_0000011111_1111111111;
        let precisions = crate::Precisions {
            dense: 10,
            sparse: 20,
        };
        let expected_index = 0b000000000000_0000011111_1111111111;
        let expected_rho = 6; // rhoW counts 5 leading 0's of 0000011111_1111111111

        let (actual_index, actual_rho) = super::decode_sparse(&precisions, encoded);

        assert_eq!(expected_index, actual_index);
        assert_eq!(expected_rho, actual_rho);
    }

    #[test]
    fn leading_zeroes_zero_after_all() {
        assert_eq!(
            0,
            super::leading_zeroes_after_first_n_bits_u64(
                0b0000000000000000000000000000000000000000000000000000000000000000,
                64
            )
        )
    }

    #[test]
    fn leading_zeroes_none_a() {
        assert_eq!(
            0,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1111111111111111111111111111111111111111111111111111111111111111,
                0
            )
        )
    }

    #[test]
    fn leading_zeroes_none_b() {
        assert_eq!(
            0,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1000000000000000000000000000000000000000000000000000000000000000,
                0
            )
        )
    }

    #[test]
    fn leading_zeroes_one_a() {
        assert_eq!(
            1,
            super::leading_zeroes_after_first_n_bits_u64(
                0b0111111111111111111111111111111111111111111111111111111111111111,
                0
            )
        )
    }

    #[test]
    fn leading_zeroes_one_b() {
        assert_eq!(
            1,
            super::leading_zeroes_after_first_n_bits_u64(
                0b0100000000000000000000000000000000000000000000000000000000000000,
                0
            )
        )
    }

    #[test]
    fn leading_zeroes_all() {
        assert_eq!(
            64,
            super::leading_zeroes_after_first_n_bits_u64(
                0b0000000000000000000000000000000000000000000000000000000000000000,
                0
            )
        )
    }

    #[test]
    fn leading_zeroes_all_but_one() {
        assert_eq!(
            63,
            super::leading_zeroes_after_first_n_bits_u64(
                0b0000000000000000000000000000000000000000000000000000000000000001,
                0
            )
        )
    }

    #[test]
    fn leading_zeroes_half_a() {
        assert_eq!(
            32,
            super::leading_zeroes_after_first_n_bits_u64(
                0b0000000000000000000000000000000011111111111111111111111111111111,
                0
            )
        )
    }

    #[test]
    fn leading_zeroes_half_b() {
        assert_eq!(
            32,
            super::leading_zeroes_after_first_n_bits_u64(
                0b0000000000000000000000000000000010000000000000000000000000000000,
                0
            )
        )
    }

    #[test]
    fn leading_zeroes_after_ten_none_a() {
        assert_eq!(
            0,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1111111111111111111111111111111111111111111111111111111111111111,
                10
            )
        )
    }

    #[test]
    fn leading_zeroes_after_ten_none_b() {
        assert_eq!(
            0,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1111111111100000000000000000000000000000000000000000000000000000,
                10
            )
        )
    }

    #[test]
    fn leading_zeroes_after_ten_one_a() {
        assert_eq!(
            1,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1111111111011111111111111111111111111111111111111111111111111111,
                10
            )
        )
    }

    #[test]
    fn leading_zeroes_after_ten_one_b() {
        assert_eq!(
            1,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1111111111010000000000000000000000000000000000000000000000000000,
                10
            )
        )
    }

    #[test]
    fn leading_zeroes_after_ten_all() {
        assert_eq!(
            54,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1111111111000000000000000000000000000000000000000000000000000000,
                10
            )
        )
    }

    #[test]
    fn leading_zeroes_after_ten_all_but_one() {
        assert_eq!(
            53,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1111111111000000000000000000000000000000000000000000000000000001,
                10
            )
        )
    }

    #[test]
    fn leading_zeroes_after_ten_half_a() {
        assert_eq!(
            27,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1111111111000000000000000000000000000111111111111111111111111111,
                10
            )
        )
    }

    #[test]
    fn leading_zeroes_after_ten_half_b() {
        assert_eq!(
            27,
            super::leading_zeroes_after_first_n_bits_u64(
                0b1111111111000000000000000000000000000100000000000000000000000000,
                10
            )
        )
    }

    #[test]
    fn first_n_bits_none_a() {
        assert_eq!(
            0,
            super::first_n_bits(
                0b1111111111111111111111111111111111111111111111111111111111111111,
                0
            )
        )
    }

    #[test]
    fn first_n_bits_none_b() {
        assert_eq!(
            0,
            super::first_n_bits(
                0b1000000000000000000000000000000000000000000000000000000000000000,
                0
            )
        )
    }

    #[test]
    fn first_n_bits_none_c() {
        assert_eq!(
            0,
            super::first_n_bits(
                0b0111111111111111111111111111111111111111111111111111111111111111,
                0
            )
        )
    }

    #[test]
    fn first_n_bits_none_d() {
        assert_eq!(
            0,
            super::first_n_bits(
                0b0100000000000000000000000000000000000000000000000000000000000000,
                0
            )
        )
    }

    #[test]
    fn first_n_bits_none_e() {
        assert_eq!(
            0,
            super::first_n_bits(
                0b0000000000000000000000000000000000000000000000000000000000000000,
                0
            )
        )
    }

    #[test]
    fn first_n_bits_none_f() {
        assert_eq!(
            0,
            super::first_n_bits(
                0b0000000000000000000000000000000000000000000000000000000000000001,
                0
            )
        )
    }

    #[test]
    fn first_n_bits_none_g() {
        assert_eq!(
            0,
            super::first_n_bits(
                0b0000000000000000000000000000000011111111111111111111111111111111,
                0
            )
        )
    }

    #[test]
    fn first_n_bits_none_h() {
        assert_eq!(
            0,
            super::first_n_bits(
                0b0000000000000000000000000000000010000000000000000000000000000000,
                0
            )
        )
    }

    #[test]
    fn first_n_bits_ten_a() {
        assert_eq!(
            0b0000000000000000000000000000000000000000000000000000001111111111,
            super::first_n_bits(
                0b1111111111111111111111111111111111111111111111111111111111111111,
                10
            )
        )
    }

    #[test]
    fn first_n_bits_ten_b() {
        assert_eq!(
            0b0000000000000000000000000000000000000000000000000000001000000000,
            super::first_n_bits(
                0b1000000000000000000000000000000000000000000000000000000000000000,
                10
            )
        )
    }

    #[test]
    fn first_n_bits_ten_c() {
        assert_eq!(
            0b0000000000000000000000000000000000000000000000000000000111111111,
            super::first_n_bits(
                0b0111111111111111111111111111111111111111111111111111111111111111,
                10
            )
        )
    }

    #[test]
    fn first_n_bits_ten_d() {
        assert_eq!(
            0b0000000000000000000000000000000000000000000000000000000100000000,
            super::first_n_bits(
                0b0100000000000000000000000000000000000000000000000000000000000000,
                10
            )
        )
    }

    #[test]
    fn first_n_bits_ten_e() {
        assert_eq!(
            0b0000000000000000000000000000000000000000000000000000000000000000,
            super::first_n_bits(
                0b0000000000000000000000000000000000000000000000000000000000000000,
                10
            )
        )
    }

    #[test]
    fn first_n_bits_ten_f() {
        assert_eq!(
            0b0000000000000000000000000000000000000000000000000000000000000000,
            super::first_n_bits(
                0b0000000000000000000000000000000000000000000000000000000000000001,
                10
            )
        )
    }

    #[test]
    fn first_n_bits_ten_g() {
        assert_eq!(
            0b0000000000000000000000000000000000000000000000000000000000000000,
            super::first_n_bits(
                0b0000000000000000000000000000000011111111111111111111111111111111,
                10
            )
        )
    }

    #[test]
    fn first_n_bits_ten_h() {
        assert_eq!(
            0b0000000000000000000000000000000000000000000000000000000000000000,
            super::first_n_bits(
                0b0000000000000000000000000000000010000000000000000000000000000000,
                10
            )
        )
    }

    #[test]
    fn test_downgrade_index_no_downgrade() {
        assert_eq!(0b1010101010, super::downgrade_index(0b1010101010, 18, 18))
    }

    #[test]
    fn test_downgrade_index_downgrade() {
        assert_eq!(
            0b1010101010,
            super::downgrade_index(0b1010101010_10101010, 18, 10)
        )
    }

    #[test]
    fn test_downgrade_rho_wzero() {
        assert_eq!(0, super::downgrade_rho_w(0b1010101010_10101010, 0, 18, 10))
    }

    #[test]
    fn test_downgrade_rho_wno_downgrade() {
        assert_eq!(
            55,
            super::downgrade_rho_w(0b1010101010_10101010, 55, 18, 18)
        )
    }

    #[test]
    fn test_downgrade_rho_wall_nonzero_moved_bits() {
        assert_eq!(1, super::downgrade_rho_w(0b1010101010_10101010, 55, 18, 10))
    }

    #[test]
    fn test_downgrade_rho_wleading_nonzero_moved_bits() {
        assert_eq!(1, super::downgrade_rho_w(0b1010101010_10000000, 55, 18, 10))
    }

    #[test]
    fn test_downgrade_rho_wtrailing_nonzero_moved_bits() {
        assert_eq!(8, super::downgrade_rho_w(0b1010101010_00000001, 55, 18, 10))
    }

    #[test]
    fn test_downgrade_rho_wall_zero_moved_bits() {
        assert_eq!(
            55,
            super::downgrade_rho_w(0b1010101010_00000000, 47, 18, 10)
        )
    }
}
