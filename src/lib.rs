// Yonder lies the logic for the interpretation and manipulation of the sparse representation of sketches.
// "...for there is no folly of the beast of the earth which is not infinitely outdone by the madness of men." -Herman Melville, Moby Dick

// ENCODING OF RHOW VALUES FOR INDEXES

// Sketches feature two precisions, normalPrecision and sparsePrecision (henceforth p and sp). The higher sparse precision is used until falling back to the lower normal precision.
// For a given precision, any hash can be mapped to an index, rhoW pair. Sketches have two precisions, so we consider sparseIndex, sparseRhoW, normalIndex, and normalRhoW.
// HyperLogLog++ uses Linear Counting to produce estimates for sparse sketches. In Linear Counting, the precise value of rhoW doesn't matter, only whether it is 0.
// Therefore, sparseRhoW carries no information beyond being nonzero. Sparse entries for indexes with a zero value for rhoW are not stored, so estimates are a function of the count of nonzero entries.

// However, sparse representations need to be able to be downgraded to normal representations. The encoding was chosen such that sparseIndex, normalIndex, and normalRhow can be reproduced, but not sparseRhoW as it is not needed.
// The sparse representation consists of one 32-bit value per index. The encoding of a value takes one of two forms depending on whether normalRhoW (henceforth just rhoW) can be determined from sparseIndex. Consider the following:

// p=15, sp=20
//  101010100100010 00110 111011001001
// |<------------->| normalIndex
// |<------------------->| sparseIndex
// normalRhoW counts the leading zeroes of the bits after the first normalIndex bits, plus one. rhoW = 2 + 1 = 3
// sparseIndex contains all the bits required to determine rhoW.

// p=15, sp=20
//  101010100100010 00000 001011001001
// |<------------->| normalIndex
// |<------------------->| sparseIndex
// normalRhoW counts the leading zeroes of the bits after the first normalIndex bits, plus one. rhoW = 7 + 1 = 8
// sparseIndex does not contain all the bits required to determine rhoW because the zeroes counted by rhoW go past sparseIndex.

// When rhoW can be determined from sparseIndex, its encoding is just sparseIndex. Otherwise, it uses a so-called 'rhoW-encoding', which is its normalIndex with a 6-bit value for rhoW appended (6 because 6 bits is sufficient to count 64 zeroes).
// RhoW-encoded values only need to store normalIndex because a value is only rhoW-encoded when the additional bits in sparseIndex are all zero, so sparseIndex can be reproduced from normalIndex.
// A rhoW-encoded-flag bit is chosen to be the least significant bit which is still more significant than any bit that would be set in either encoding, and is set to 1 for rhoW-encoded values.
// It is chosen as the most significant bit so that, when sparse entries are sorted numerically, rhoW-encoded values are separated from non-rhoW-encoded values.

// Non-RhoW-Encoded Example
// p=15, sp=20
//  101010100100010 00110 111011001001
// |<------------->| normalIndex
// |<------------------->| sparseIndex
// normalRhoW CAN be determined from sparseIndex, so non-rhoW-encoding is used:
//  0000000000 0 0 10101010010001000110
// |<-------->| padding
//            |^| rhoW-encoded flag, bit 22 because rhoW-encoding would use 21 bits (15 for normalIndex + 6 for rhoW)
//              |^| padding
//                |<------------------>| sparseIndex

// RhoW-Encoded Example
// p=15, sp=20
//  101010100100010 00000 001011001001
// |<------------->| normalIndex
// |<------------------->| sparseIndex
// normalRhoW counts the leading zeroes of the bits after the first normalIndex bits, plus one. rhoW = 7 + 1 = 8
// normalRhoW can NOT be determined from sparseIndex, so rhoW-encoding is used:
//  0000000000 1 101010100100010 000100
// |<-------->| padding
//            |^| rhoW-encoded flag, bit 22 because rhoW-encoding would use 21 bits (15 for normalIndex + 6 for rhoW)
//              |<------------->| normalIndex
//                              |<---->| rhoW (0b000100 = 8)

// OPERATIONS FOR PROCESSING NEW VALUES

// Here, hllppzeta and Zetasketch diverge slightly in implementation. The sparse representation in hllppzeta is stored in a format which uses more memory but makes operations simpler.
// Because hllppzeta uses more memory, it falls back to normal representation sooner, and therefore can produce slightly different estimates. All other properties and interoperabilities are preserved.

// In hllppzeta, sparse entries are stored sorted by value (non-rhoW-encoded values first sorted by index, then rhoW-encoded values sorted first by index then by rhoW).
// To process a new value, we encode it and binary search for where it would be inserted in our sparse entry list.
// If it is non-rhoW-encoded, it is just a sparseIndex, and should be inserted if an exact match is not found.
// If it is rhoW-encoded, it is sorted first by index then by rhoW, so it may be either preceded or followed by a value with a matching index. If not, it is inserted as the first rhoW value for this index.
// If followed by a value with a matching index, that value has a higher rhoW, and this can be ignored. If preceded by a value with a matching index, this value has a higher rhoW, and the other should be overwritten.

// In Zetasketch, sparse entries are stored sorted by value, then difference-encoded, then varint-encoded (using the version of varint that doesn't give small sizes for negative values because all differences are positive because the sort order is ascending).
// Random access in this representation is expensive because difference-decoding must be done for the whole list up to the element required, so Zetasketch processes new values by adding them to a buffer.
// When the buffer size exceeds a threshold or an estimate or merge is required, the buffer is sorted, merged with the difference-decoded sparse representation (merge-sort-style), and the sparse representation is difference-encoded again.

// A list of values difference-encoded is just the first value in the list followed each value minus the previous unencoded value.
// A list of values difference-decoded is just the first value in the list followed each value plus the previous encoded value.
// For example, [2, 3, 5, 7] difference-encoded is [2, 1, 2, 2] and [2, 1, 2, 2] difference-decoded is [2, 3, 5, 7].
// To varint-encode a value (the varint-encoding variant optimized for unsigned values), take its bits 7 at a time, least significant to most significant, and append them to a list of bytes. Set the most significant bit in each byte except the last.
// To varint-decode a value, while the next byte has its most significant bit set, append the other 7 bits in the bytes to your value.
// For example, the 32-bit value 1010 1010010 0010001 1011101 1001001 varint-encoded is the byte list [11001001 11011101 10010001 11010010 10001010] and the 32-bit value 0000000000000000000000000 1001001 varint-encoded is the byte list [01001001].

// For compatibility, hllppzeta implements difference-encoding and varint-encoding in its serialization logic rather than storing the sparse representation that way during use.

pub const MIN_PRECISION: u8 = 10;
pub const MAX_DENSE_PRECISION: u8 = 18;
pub const MAX_SPARSE_PRECISION: u8 = 25;

#[derive(Clone, Debug)]
pub struct HyperLogLogPlusPlus {
    pub precisions: Precisions,
    sketch: Sketch,
}

#[derive(Clone, Copy, Debug)]
pub struct Precisions {
    dense: u8,
    sparse: u8,
}

#[derive(Clone, Debug)]
enum Sketch {
    Dense(Vec<u8>),
    Sparse(Vec<u32>),
}

impl HyperLogLogPlusPlus {
    // Creates a "zero-valued" HyperLogLog++ sketch ideal as a starting point for merging sketches. This is just an empty max-precision sketch.
    pub fn new() -> Self {
        Self::new_with_precision(MAX_DENSE_PRECISION, MAX_SPARSE_PRECISION).unwrap()
    }

    // NewSketch creates a HyperLogLog++ sketch with 2^precision buckets.
    pub fn new_with_precision(dense_precision: u8, sparse_precision: u8) -> Result<Self, String> {
        if MIN_PRECISION > dense_precision
            || dense_precision > MAX_DENSE_PRECISION
            || dense_precision > sparse_precision
            || sparse_precision > MAX_SPARSE_PRECISION
        {
            Err(format!("must have {} <= normalPrecision <= {} and normalPrecision <= sparsePrecision <= {}; got dense_precision={} and sparse_precision={}", MIN_PRECISION, MAX_DENSE_PRECISION, MAX_SPARSE_PRECISION, dense_precision, sparse_precision))
        } else {
            Ok(HyperLogLogPlusPlus {
                precisions: Precisions {
                    dense: dense_precision,
                    sparse: sparse_precision,
                },
                sketch: Sketch::Sparse(Vec::new()),
            })
        }
    }

    pub fn add_hash(&mut self, hash: u64) {
        let precision = self.get_precision();
        let index = bit_arithmetic::first_n_bits(hash, precision);
        let rho_w = bit_arithmetic::leading_zeroes_after_first_n_bits_u64(hash, precision) + 1;
        self.set_if_larger(index as u32, rho_w);
        self.check_convert_to_dense();
    }

    fn check_convert_to_dense(&mut self) {
        if let Sketch::Sparse(ref sparse_sketch) = self.sketch {
            let sparse_data_size_bytes = sparse_sketch.len() * 4;
            let dense_data_size_bytes = 1 << self.precisions.dense;
            // Zetasketch converts from sparse to normal when the data size of the sparse representation > .75 * the data size of the normal representation.
            // (see https://github.com/google/zetasketch/blob/443927e65960e0596714b11137d73dc76ba1d969/java/com/google/zetasketch/internal/hllplus/SparseRepresentation.java#L55).
            if sparse_data_size_bytes > dense_data_size_bytes * 3 / 4 {
                *self = self.as_dense();
            }
        }
    }

    pub fn merge(&mut self, other: &Self) {
        // Okay, listen up. The sparse representation has a longer index and therefore starts counting leading zeroes at a different point in the hash.
        // rhoW is 1 + the count of leading zeroes after normalPrecision bits. rhoW' is 1 + the count of leading zeroes after sparsePrecision bits (note rhoW vs rhoW', normal vs sparse).
        // For space efficiency reasons, the sparse representation doesn't actually store rhoW' or enough information to reproduce it. It only stores enough information to reproduce rhoW.
        // Getting an estimate for a sparse representation uses linear counting and therefore the values of rhoW' don't matter (only how many are nonzero).
        // However, downgrading the precision of a sparse sketch to a precision higher than its normal precision is a no-go since rhoW isn't stored for this level of precision.
        if self.precisions.dense > other.precisions.dense
            || self.get_precision() > other.get_precision()
        {
            // precisions are incompatible; replace self with a new sketch and merge current sketch and other sketch into new sketch
            let replacement_dense_precision = self.precisions.dense.min(other.precisions.dense);
            let replacement_sparse_precision = self.precisions.sparse.min(other.precisions.sparse);
            let mut replacement = HyperLogLogPlusPlus::new_with_precision(
                replacement_dense_precision,
                replacement_sparse_precision,
            )
            .unwrap();
            if !self.is_sparse() || !other.is_sparse() {
                replacement = replacement.as_dense()
            }
            merge::merge_from_same_or_higher_precision(&mut replacement, &self);
            merge::merge_from_same_or_higher_precision(&mut replacement, &other);
            replacement.check_convert_to_dense();
            *self = replacement
        } else {
            // precisions are compatible; merge other sketch into current sketch
            merge::merge_from_same_or_higher_precision(self, other);
        }
    }

    // GetEstimate returns the estimated count of distinct elements added to a sketch.
    pub fn get_estimate(&self) -> u64 {
        let precision = self.get_precision();
        let num_buckets = (1u64 << precision) as f64;
        let zero_count = self.zero_count();
        let linear_count = num_buckets * (num_buckets / (zero_count as f64)).ln();
        if let Sketch::Dense(ref dense_sketch) = self.sketch {
            if linear_count > get_estimate::linear_counting_threshold(precision).unwrap() {
                // unwrap is safe because dense precisions are checked to be 10 <= precision <= 18
                // use HyperLogLog for high cardinality dense representations, otherwise use linear counting
                let raw_estimate = get_estimate::alpha(precision)
                    * num_buckets
                    * get_estimate::exp_harmonic_mean(&dense_sketch);
                let closest_biases = get_estimate::closest_biases(&raw_estimate, precision);
                let bias_estimate = get_estimate::estimate_bias(&closest_biases);
                (raw_estimate - bias_estimate).round() as u64
            } else {
                linear_count.round() as u64
            }
        } else {
            linear_count.round() as u64
        }
    }

    // IsSparse returns whether a sketch uses a normal, fixed-size representation or a sparse, variable-size representation.
    pub fn is_sparse(&self) -> bool {
        match self.sketch {
            Sketch::Dense(_) => false,
            Sketch::Sparse(_) => true,
        }
    }

    // ConvertToNormal converts a sketch with a sparse representation to a normal representation sketch with the same values (but downgraded to normalPrecision).
    // Does nothing if the sketch already uses a normal representation. This can change the estimates.
    pub fn as_dense(&self) -> Self {
        if !self.is_sparse() {
            self.clone()
        } else {
            let mut replacement = HyperLogLogPlusPlus {
                precisions: self.precisions,
                sketch: Sketch::Dense(vec![0; 1 << self.precisions.dense]),
            };
            merge::merge_from_same_or_higher_precision(&mut replacement, self);
            replacement
        }
    }

    // ConvertToPrecision downgrades the normal and/or sparse precision to the values specified. If those values are incompatible with the current values, the highest valid values will be used instead.
    pub fn as_precision(&mut self) -> Self {
        let mut replacement = Self::new();
        if !self.is_sparse() {
            replacement = replacement.as_dense()
        }
        replacement.merge(&self);
        replacement
    }

    // getPrecision returns the effective precision of a sketch, taking into account which representation it is currently using.
    fn get_precision(&self) -> u8 {
        if self.is_sparse() {
            self.precisions.sparse
        } else {
            self.precisions.dense
        }
    }

    // setIfLarger sets a normal-representation sketch's value of rhoW at an index if the value is larger than any existing value for that index.
    fn set_if_larger(&mut self, index: u32, value: u8) {
        match self.sketch {
            Sketch::Dense(ref mut dense_sketch) => {
                if value > dense_sketch[(index as usize)] {
                    dense_sketch[(index as usize)] = value;
                }
            }
            Sketch::Sparse(ref mut sparse_sketch) => {
                // 0 values are implicit and would throw off our fast zeroCountSparse() function
                if value == 0 {
                    return;
                }

                let encoded_to_insert =
                    bit_arithmetic::encode_sparse(&self.precisions, index, value);
                if encoded_to_insert & bit_arithmetic::rho_encoded_flag(&self.precisions) == 0 {
                    // Alright. So this is the encoding chosen if rhoW can be determined from sparseIndex, and the encoding is just the sparseIndex.
                    // That means anything with this sparseIndex has the same rhoW, so if we've seen this sparseIndex we throw it away, otherwise we insert it.

                    // find index of matching sparse entry or the index to insert new sparse entry (cumbersome because there's no sort.SearchInts equivalent for []uint32)
                    // because the rhoEncodedFlag is the most significant bit, sort.Search will quickly exclude rhoEncoded entries (it uses binary search)
                    if let Err(search_index) = sparse_sketch.binary_search(&encoded_to_insert) {
                        sparse_sketch.insert(search_index, encoded_to_insert)
                    }
                } else {
                    // This is the encoding chosen if rhoW can't be determined from sparseIndex, and the encoding is a flag, optional padding, the normal index, and rhoW.
                    // rhoW isn't determined by the index, so instead of an exact match, we need to find the entry matching our index and overwrite if ours is larger, otherwise insert.
                    // The order of fields in the encoding was chosen so that sorting entries by encoding sorts first by index then by rhoW, so we can still search efficiently.
                    if let Err(search_index) = sparse_sketch.binary_search(&encoded_to_insert) {
                        // no exactly matching entry found
                        // check if the entry at the point to insert has the same index - if so it has a higher rhoW because of sort order so we do nothing
                        if search_index != sparse_sketch.len() {
                            let (next_index, _) = bit_arithmetic::decode_sparse(
                                &self.precisions,
                                sparse_sketch[search_index],
                            );
                            if index as u32 == next_index {
                                return;
                            }
                        }
                        // check if the entry just before the point to insert has the same index - if so it has a smaller rhoW because of sort order so we overwrite
                        if search_index != 0 {
                            let (previous_index, _) = bit_arithmetic::decode_sparse(
                                &self.precisions,
                                sparse_sketch[search_index - 1],
                            );
                            if index as u32 == previous_index {
                                sparse_sketch[search_index - 1] = encoded_to_insert;
                                return;
                            }
                        }
                        // no index-matching entry found
                        sparse_sketch.insert(search_index, encoded_to_insert);
                    }
                }
            }
        }
    }

    // zeroCount returns the count of zero-valued indexes in a sketch using a normal representation.
    fn zero_count(&self) -> u32 {
        match &self.sketch {
            Sketch::Dense(dense_sketch) => {
                dense_sketch.iter().filter(|&&v| v == 0u8).count() as u32
            }
            Sketch::Sparse(sparse_sketch) => {
                (1u32 << self.precisions.sparse) - (sparse_sketch.len() as u32)
            }
        }
    }
}

fn float_cmp(a: f64, b: f64) -> bool {
    (a - b).abs() <= ((a.abs() + b.abs()) / 2.0) * 0.0001
}

mod bit_arithmetic;
mod get_estimate;
mod merge;

#[cfg(test)]
mod tests {
    use crate::bit_arithmetic::encode_sparse;

    #[test]
    fn set_if_larger_normal_smaller() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();

        match hllpp.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[420] = 70;
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        hllpp.set_if_larger(420, 69);

        match hllpp.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(70u8, dense_data[420]);
                assert_eq!(70u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_normal_larger() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        match hllpp.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[420] = 68;
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        hllpp.set_if_larger(420, 69);

        match hllpp.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(69u8, dense_data[420]);
                assert_eq!(69u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_zero() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();

        hllpp.set_if_larger(0b00000000000000000000000000000001, 0b000000);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(0, sparse_data.len());
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_not_rho_encoded_none_exist() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();

        hllpp.set_if_larger(0b00000000000000000000000000000001, 0b111111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(1, sparse_data.len());
                assert_eq!(0b00000000000000000000000000000001, sparse_data[0]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_not_rho_encoded_not_exists_smallest() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                sparse_data.push(0b00000000000000000000000000000010);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        hllpp.set_if_larger(0b00000000000000000000000000000001, 0b111111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(2, sparse_data.len());
                assert_eq!(0b00000000000000000000000000000001, sparse_data[0]);
                assert_eq!(0b00000000000000000000000000000010, sparse_data[1]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_not_rho_encoded_not_exists_largest() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                sparse_data.push(0b00000000000000000000000000000001);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        hllpp.set_if_larger(0b00000000000000000000000000000010, 0b111111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(2, sparse_data.len());
                assert_eq!(0b00000000000000000000000000000001, sparse_data[0]);
                assert_eq!(0b00000000000000000000000000000010, sparse_data[1]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_not_rho_encoded_exists() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                sparse_data.push(0b00000000000000000000000000000001);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        hllpp.set_if_larger(0b00000000000000000000000000000001, 0b111111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(1, sparse_data.len());
                assert_eq!(0b00000000000000000000000000000001, sparse_data[0]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_rho_encoded_empty() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();

        hllpp.set_if_larger(0b00000000_000000000_000000000000000, 0b111111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(1, sparse_data.len());
                assert_eq!(0b000000_1_000000000_0000000000_111111, sparse_data[0]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_rho_encoded_not_exists_smallest() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                sparse_data.push(0b000000_1_000000000_0000000001_111111);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        hllpp.set_if_larger(0b00000000_000000000_000000000000000, 0b111111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(2, sparse_data.len());
                assert_eq!(0b000000_1_000000000_0000000000_111111, sparse_data[0]);
                assert_eq!(0b000000_1_000000000_0000000001_111111, sparse_data[1]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_rho_encoded_not_exists_largest() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                sparse_data.push(0b000000_1_000000000_0000000000_111111);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        hllpp.set_if_larger(0b00000000_000000001_000000000000000, 0b111111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(2, sparse_data.len());
                assert_eq!(0b000000_1_000000000_0000000000_111111, sparse_data[0]);
                assert_eq!(0b000000_1_000000000_0000000001_111111, sparse_data[1]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_rho_encoded_exists_smaller() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                sparse_data.push(0b000000_1_000000000_0000000001_111111);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        hllpp.set_if_larger(0b00000000_000000001_000000000000000, 0b000111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(1, sparse_data.len());
                assert_eq!(0b000000_1_000000000_0000000001_111111, sparse_data[0]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_rho_encoded_exists_equal() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                sparse_data.push(0b000000_1_000000000_0000000001_111111);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        hllpp.set_if_larger(0b00000000_000000001_000000000000000, 0b111111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(1, sparse_data.len());
                assert_eq!(0b000000_1_000000000_0000000001_111111, sparse_data[0]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn set_if_larger_sparse_rho_encoded_exists_larger() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                sparse_data.push(0b000000_1_000000000_0000000001_000111);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        hllpp.set_if_larger(0b00000000_000000001_000000000000000, 0b111111);

        match hllpp.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(1, sparse_data.len());
                assert_eq!(0b000000_1_000000000_0000000001_111111, sparse_data[0]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn zero_count_normal_none() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        match hllpp.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                for i in 0..dense_data.len() {
                    dense_data[i] = 69;
                }
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
        assert_eq!(0, hllpp.zero_count());
    }

    #[test]
    fn zero_count_normal_one() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        match hllpp.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                for i in 1..dense_data.len() {
                    dense_data[i] = 69;
                }
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
        assert_eq!(1, hllpp.zero_count());
    }

    #[test]
    fn zero_count_normal_all() {
        let hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        assert_eq!(1024, hllpp.zero_count());
    }

    #[test]
    fn zero_count_sparse_none() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 10).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                for i in 0..1024 {
                    sparse_data.push(encode_sparse(&hllpp.precisions, i, 69));
                }
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        assert_eq!(0, hllpp.zero_count());
    }

    #[test]
    fn zero_count_sparse_one() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 10).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                for i in 1..1024 {
                    sparse_data.push(encode_sparse(&hllpp.precisions, i, 69));
                }
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        assert_eq!(1, hllpp.zero_count());
    }

    #[test]
    fn zero_count_sparse_all() {
        let hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 10).unwrap();
        assert_eq!(1024, hllpp.zero_count());
    }

    #[test]
    fn convert_to_normal_empty_sketch() {
        let hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 20).unwrap();

        let hllpp = hllpp.as_dense();

        assert_eq!(10, hllpp.precisions.dense);
        assert_eq!(20, hllpp.precisions.sparse);
        match hllpp.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(1 << 10, dense_data.len());
                assert_eq!(0u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn convert_to_normal_nonempty_sketch() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 20).unwrap();
        match hllpp.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // rhoW counts 10 additional 0's, rhoW = 10 + 10 = 20
                sparse_data.push(encode_sparse(
                    &hllpp.precisions,
                    0b0000000000_0000000000,
                    10,
                ));
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        let hllpp = hllpp.as_dense();

        assert_eq!(10, hllpp.precisions.dense);
        assert_eq!(20, hllpp.precisions.sparse);
        match hllpp.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(1 << 10, dense_data.len());
                assert_eq!(20u8, dense_data[0]);
                assert_eq!(20u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn new_sketch_all_valid_precisions() {
        for dense_precision in 10..18 {
            for sparse_precision in dense_precision..26 {
                super::HyperLogLogPlusPlus::new_with_precision(dense_precision, sparse_precision)
                    .unwrap();
            }
        }
    }

    #[test]
    fn new_sketch_normal_precision_too_low() {
        for dense_precision in 0..9 {
            for sparse_precision in dense_precision..26 {
                super::HyperLogLogPlusPlus::new_with_precision(dense_precision, sparse_precision)
                    .unwrap_err();
            }
        }
    }

    #[test]
    fn new_sketch_normal_precision_too_high() {
        for dense_precision in 19..25 {
            for sparse_precision in dense_precision..26 {
                super::HyperLogLogPlusPlus::new_with_precision(dense_precision, sparse_precision)
                    .unwrap_err();
            }
        }
    }

    #[test]
    fn new_sketch_sparse_precision_too_low() {
        for dense_precision in 10..18 {
            for sparse_precision in 0..dense_precision {
                super::HyperLogLogPlusPlus::new_with_precision(dense_precision, sparse_precision)
                    .unwrap_err();
            }
        }
    }

    #[test]
    fn new_sketch_sparse_precision_too_high() {
        for dense_precision in 10..18 {
            for sparse_precision in 26..30 {
                super::HyperLogLogPlusPlus::new_with_precision(dense_precision, sparse_precision)
                    .unwrap_err();
            }
        }
    }

    #[test]
    fn add_hash_one() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(15, 25)
            .unwrap()
            .as_dense();

        hllpp.add_hash(0b000000000000000_1111111111_111111111111111111111111111111111111111);

        match hllpp.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(1, dense_data[0]);
                assert_eq!(1u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn add_hash_three_same_bucket() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(15, 25)
            .unwrap()
            .as_dense();

        hllpp.add_hash(0b000000000000000_1111111111_111111111111111111111111111111111111111);
        hllpp.add_hash(0b000000000000000_0111111111_111111111111111111111111111111111111111);
        hllpp.add_hash(0b000000000000000_0011111111_111111111111111111111111111111111111111);

        match hllpp.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(3, dense_data[0]);
                assert_eq!(3u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn add_hash_three_different_buckets() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(15, 25)
            .unwrap()
            .as_dense();

        hllpp.add_hash(0b000000000000000_1111111111_111111111111111111111111111111111111111);
        hllpp.add_hash(0b000000000000001_0111111111_111111111111111111111111111111111111111);
        hllpp.add_hash(0b000000000000010_0011111111_111111111111111111111111111111111111111);

        match hllpp.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(1, dense_data[0]);
                assert_eq!(2, dense_data[1]);
                assert_eq!(3, dense_data[2]);
                assert_eq!(6u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn add_hash_collision() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(15, 25)
            .unwrap()
            .as_dense();

        hllpp.add_hash(0b000000000000000_1111111111_111111111111111111111111111111111111111);
        hllpp.add_hash(0b000000000000000_1111111111_111111111111111111111111111111111111111);

        match hllpp.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(1, dense_data[0]);
                assert_eq!(1u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn add_hash_convert_to_dense() {
        let mut hllpp = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();

        // threshold = .75 * 2^10 / 4 = 192
        for i in 0..193u64 {
            hllpp.add_hash(i << (64 - 10)) // each add in a separate bucket with sparse index i << (25-10) and normal index i;
        }

        match hllpp.sketch {
            crate::Sketch::Dense(dense_data) => {
                for i in 0..193 {
                    assert_eq!(55, dense_data[i]);
                }
                assert_eq!(55 * 193, dense_data.iter().map(|&d| d as i32).sum::<i32>());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn merge_normal_upgrade_precision() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(18, 25)
            .unwrap()
            .as_dense();
        let src = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        if let crate::Sketch::Sparse(_) = dst.sketch {
            panic!("expected dense sketch")
        }
    }

    #[test]
    fn merge_sparse_upgrade_precision() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(18, 25).unwrap();
        let src = super::HyperLogLogPlusPlus::new_with_precision(10, 20).unwrap();

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        if let crate::Sketch::Dense(_) = dst.sketch {
            panic!("expected sparse sketch")
        }
    }

    #[test]
    fn merge_sparse_upgrade_normal_precision() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(18, 20).unwrap();
        let src = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        if let crate::Sketch::Dense(_) = dst.sketch {
            panic!("expected sparse sketch")
        }
    }

    #[test]
    fn merge_normal_empty_sketches_same_precision() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        let src = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        if let crate::Sketch::Sparse(_) = dst.sketch {
            panic!("expected dense sketch")
        }
    }

    #[test]
    fn merge_sparse_empty_sketches_same_precision() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        let src = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        if let crate::Sketch::Dense(_) = dst.sketch {
            panic!("expected sparse sketch")
        }
    }

    #[test]
    fn merge_normal_empty_sketches_downgrade_precision() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        let src = super::HyperLogLogPlusPlus::new_with_precision(18, 25)
            .unwrap()
            .as_dense();

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        if let crate::Sketch::Sparse(_) = dst.sketch {
            panic!("expected dense sketch")
        }
    }

    #[test]
    fn merge_sparse_empty_sketches_downgrade_precision() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 20).unwrap();
        let src = super::HyperLogLogPlusPlus::new_with_precision(18, 25).unwrap();

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        if let crate::Sketch::Dense(_) = dst.sketch {
            panic!("expected sparse sketch")
        }
    }

    #[test]
    fn merge_sparse_to_normal_empty_sketches_downgrade_precision() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 20)
            .unwrap()
            .as_dense();
        let src = super::HyperLogLogPlusPlus::new_with_precision(18, 25).unwrap();

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        if let crate::Sketch::Sparse(_) = dst.sketch {
            panic!("expected dense sketch")
        }
    }

    #[test]
    fn merge_normal_to_same_precision_empty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();

        match src.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0] = 55;
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(55, dense_data[0]);
                assert_eq!(55u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn merge_sparse_to_same_precision_empty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();

        let encoded = encode_sparse(&src.precisions, 0, 55);

        match src.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                sparse_data.push(encoded);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(1, sparse_data.len());
                assert_eq!(encoded, sparse_data[0]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn merge_normal_to_downgrade_precision_empty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(18, 25)
            .unwrap()
            .as_dense();

        match src.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0b0000000000_00000000] = 47; // rhoW counts 8 additional 0's, rhoW = 47 + 8 = 55
                dense_data[0b1111111111_11111111] = 47; // rhoW counts 0 leading 0's of 11111111, rhoW = 0 + 1 = 1
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(55, dense_data[0b0000000000]);
                assert_eq!(1, dense_data[0b1111111111]);
                assert_eq!(56u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn merge_sparse_to_downgrade_precision_empty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 20).unwrap();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(18, 25).unwrap();

        // rhoW counts 5 additional 0's, rhoW = 47 + 5 = 52
        let encoded_a25 = encode_sparse(&src.precisions, 0b00000000000000000000_00000, 47);
        let encoded_a20 = encode_sparse(&dst.precisions, 0b00000000000000000000, 52);
        // rhoW counts 0 leading 0's of 11111, rhoW = 0 + 1 = 1
        let encoded_b25 = encode_sparse(&src.precisions, 0b11111111111111111111_11111, 47);
        let encoded_b20 = encode_sparse(&dst.precisions, 0b11111111111111111111, 1);

        match src.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // order reversed because encodedA25 is rhoW-encoded, so its most significant bit is set, so it is ordered higher than encodedB25
                sparse_data.push(encoded_b25);
                sparse_data.push(encoded_a25);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(2, sparse_data.len());
                assert_eq!(encoded_b20, sparse_data[0]);
                assert_eq!(encoded_a20, sparse_data[1]);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn merge_sparse_to_normal_to_downgrade_precision_empty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 20)
            .unwrap()
            .as_dense();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(18, 25).unwrap();

        // rhoW counts 15 additional 0's, rhoW = 37 + 15 = 52
        let encoded_a = encode_sparse(&src.precisions, 0b0000000000_000000000000000, 37);
        // rhoW counts 0 leading 0's of 111111111111111, rhoW = 0 + 1 = 1
        let encoded_b = encode_sparse(&src.precisions, 0b1111111111_111111111111111, 37);

        match src.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // order reversed because encodedA is rhoW-encoded, so its most significant bit is set, so it is ordered higher than encodedB
                sparse_data.push(encoded_b);
                sparse_data.push(encoded_a);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(52, dense_data[0b0000000000]);
                assert_eq!(1, dense_data[0b1111111111]);
                assert_eq!(53u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn merge_normal_to_same_precision_nonempty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();

        match dst.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0] = 1;
                dense_data[1] = 55;
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
        match src.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0] = 55;
                dense_data[1] = 1;
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(55, dense_data[0]); // max(1, 55) = 55
                assert_eq!(55, dense_data[1]); // max(55, 1) = 55
                assert_eq!(110u8, dense_data.iter().sum());
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn merge_sparse_to_same_precision_nonempty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(10, 25).unwrap();

        let encoded_into_a = encode_sparse(&dst.precisions, 0, 1);
        let encoded_into_b = encode_sparse(&dst.precisions, 1, 55);
        let encoded_from_a = encode_sparse(&src.precisions, 0, 55);
        let encoded_from_b = encode_sparse(&src.precisions, 1, 1);

        match dst.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // order reversed because encodedIntoA is rhoW-encoded, so its most significant bit is set, so it is ordered higher than encodedIntoB
                sparse_data.push(encoded_into_b);
                sparse_data.push(encoded_into_a);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
        match src.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // order reversed because encodedFromA is rhoW-encoded, so its most significant bit is set, so it is ordered higher than encodedFromB
                sparse_data.push(encoded_from_b);
                sparse_data.push(encoded_from_a);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(2, sparse_data.len());
                assert_eq!(encoded_into_b, sparse_data[0]); // max(1, 55) = 55
                assert_eq!(encoded_from_a, sparse_data[1]); // max(55, 1) = 55
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn merge_normal_to_downgrade_precision_nonempty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(18, 25)
            .unwrap()
            .as_dense();

        match dst.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0b0000000000] = 1;
                dense_data[0b0000000001] = 55;
                dense_data[0b0000000010] = 1;
                dense_data[0b0000000011] = 55;
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
        match src.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0b0000000000_00000000] = 47; // rhoW counts 8 additional 0's, rhoW = 47 + 8 = 55
                dense_data[0b0000000001_00000000] = 1; // rhoW counts 8 additional 0's, rhoW = 1 + 8 = 9
                dense_data[0b0000000010_00111111] = 47; // rhoW counts 2 leading 0's of 00111111, rhoW = 2 + 1 = 3
                dense_data[0b0000000011_11111111] = 1; // rhoW counts 0 leading 0's of 11111111, rhoW = 0 + 1 = 1
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(55, dense_data[0b0000000000]); // max(1, 55) = 55
                assert_eq!(55, dense_data[0b0000000001]); // max(55, 9) = 55
                assert_eq!(3, dense_data[0b0000000010]); // max(1, 3) = 3
                assert_eq!(55, dense_data[0b0000000011]); // max(55, 1) = 55
                assert_eq!(
                    55 + 55 + 3 + 55,
                    dense_data.iter().map(|&d| d as i32).sum::<i32>()
                );
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn merge_sparse_to_downgrade_precision_nonempty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 20).unwrap();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(18, 25).unwrap();

        let encoded_into_a = encode_sparse(&dst.precisions, 0b0000000000_0000000000, 1);
        let encoded_into_b = encode_sparse(&dst.precisions, 0b0000000000_0000000001, 55);
        let encoded_into_c = encode_sparse(&dst.precisions, 0b0000000000_0000000010, 1);
        let encoded_into_d = encode_sparse(&dst.precisions, 0b0000000000_0000000011, 55);
        // rhoW counts 5 additional 0's, rhoW = 47 + 5 = 52
        let encoded_from_a25 = encode_sparse(&src.precisions, 0b0000000000000_00000_00_00000, 47);
        let encoded_from_a20 = encode_sparse(&dst.precisions, 0b0000000000000_00000_00, 52);
        // rhoW counts 5 additional 0's, rhoW = 1 + 5 = 6
        let encoded_from_b25 = encode_sparse(&src.precisions, 0b0000000000000_00000_01_00000, 1);
        // rhoW counts 2 leading 0's of 00111111, rhoW = 2 + 1 = 3
        let encoded_from_c25 = encode_sparse(&src.precisions, 0b0000000000000_00000_10_00111, 47);
        let encoded_from_c20 = encode_sparse(&dst.precisions, 0b0000000000000_00000_10, 3);
        // rhoW counts 0 leading 0's of 11111111, rhoW = 0 + 1 = 1
        let encoded_from_d25 = encode_sparse(&src.precisions, 0b0000000000000_00000_11_11111, 1);

        match dst.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // encodedIntoA last because it is rhoW-encoded, so its most significant bit is set, so it is ordered higher than others
                sparse_data.push(encoded_into_b);
                sparse_data.push(encoded_into_c);
                sparse_data.push(encoded_into_d);
                sparse_data.push(encoded_into_a);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
        match src.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // encodedFromA last because it is rhoW-encoded, so its most significant bit is set, so it is ordered higher than others
                sparse_data.push(encoded_from_b25);
                sparse_data.push(encoded_from_c25);
                sparse_data.push(encoded_from_d25);
                sparse_data.push(encoded_from_a25);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(4, sparse_data.len());
                assert_eq!(encoded_into_b, sparse_data[0]); // max(1, 52) = 52
                assert_eq!(encoded_from_c20, sparse_data[1]); // max(55, 6) = 55
                assert_eq!(encoded_into_d, sparse_data[2]); // max(1, 3) = 3
                assert_eq!(encoded_from_a20, sparse_data[3]); // max(55, 1) = 55
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn merge_sparse_to_normal_to_downgrade_precision_nonempty_sketch() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 20)
            .unwrap()
            .as_dense();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(18, 25).unwrap();

        // rhoW counts 15 additional 0's, rhoW = 37 + 15 = 52
        let encoded_from_a = encode_sparse(&src.precisions, 0b0000000000_000000000000000, 37);
        // rhoW counts 15 additional 0's, rhoW = 1 + 15 = 16
        let encoded_from_b = encode_sparse(&src.precisions, 0b0000000001_000000000000000, 1);
        // rhoW counts 2 leading 0's of 00111111, rhoW = 2 + 1 = 3
        let encoded_from_c = encode_sparse(&src.precisions, 0b0000000010_001111111111111, 47);
        // rhoW counts 0 leading 0's of 11111111, rhoW = 0 + 1 = 1
        let encoded_from_d = encode_sparse(&src.precisions, 0b0000000011_111111111111111, 1);

        match dst.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0b0000000000] = 1;
                dense_data[0b0000000001] = 55;
                dense_data[0b0000000010] = 1;
                dense_data[0b0000000011] = 55;
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
        match src.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // encodedFromA last because it is rhoW-encoded, so its most significant bit is set, so it is ordered higher than others
                sparse_data.push(encoded_from_b);
                sparse_data.push(encoded_from_c);
                sparse_data.push(encoded_from_d);
                sparse_data.push(encoded_from_a);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(52, dense_data[0b0000000000]); // max(1, 52) = 52
                assert_eq!(55, dense_data[0b0000000001]); // max(55, 16) = 55
                assert_eq!(3, dense_data[0b0000000010]); // max(1, 3) = 3
                assert_eq!(55, dense_data[0b0000000011]); // max(55, 1) = 55
                assert_eq!(
                    52 + 55 + 3 + 55,
                    dense_data.iter().map(|&d| d as i32).sum::<i32>()
                );
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn merge_normal_to_downgrade_precision_nonempty_sketch_colliding_downgraded_values() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(18, 25)
            .unwrap()
            .as_dense();

        match dst.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0b0000000000] = 1;
                dense_data[0b0000000001] = 28;
                dense_data[0b0000000010] = 55;
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
        match src.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0b0000000000_00000000] = 2; // rhoW counts 8 additional 0's, rhoW = 2 + 8 = 10
                dense_data[0b0000000000_00000001] = 2; // rhoW counts 7 leading 0's of 00000001, rhoW = 7 + 1 = 8
                dense_data[0b0000000001_00000000] = 24; // rhoW counts 8 additional 0's, rhoW = 24 + 8 = 32
                dense_data[0b0000000001_00000001] = 24; // rhoW counts 7 leading 0's of 00000001, rhoW = 7 + 1 = 8
                dense_data[0b0000000010_00000000] = 46; // rhoW counts 8 additional 0's, rhoW = 46 + 8 = 54
                dense_data[0b0000000010_00000001] = 46; // rhoW counts 7 leading 0's of 00000001, rhoW = 7 + 1 = 8
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(25, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(10, dense_data[0b0000000000]); // max(1, 10, 8) = 10
                assert_eq!(32, dense_data[0b0000000001]); // max(28, 32, 8) = 32
                assert_eq!(55, dense_data[0b0000000010]); // max(55, 54, 8) = 55
                assert_eq!(
                    10 + 32 + 55,
                    dense_data.iter().map(|&d| d as i32).sum::<i32>()
                );
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn merge_sparse_to_downgrade_precision_nonempty_sketch_colliding_downgraded_values() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 20).unwrap();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(18, 25).unwrap();

        let encoded_into_a = encode_sparse(&dst.precisions, 0b0000000000_0000000000, 1);
        let encoded_into_b = encode_sparse(&dst.precisions, 0b0000000000_0000000001, 28);
        let encoded_into_c = encode_sparse(&dst.precisions, 0b0000000000_0000000010, 55);
        // rhoW counts 5 additional 0's, rhoW = 2 + 5 = 7
        let encoded_from_a25 = encode_sparse(&src.precisions, 0b0000000000_00000000_00_00000, 2);
        let encoded_from_a20 = encode_sparse(&dst.precisions, 0b0000000000_00000000_00, 7);
        // rhoW counts 4 leading 0's of 00001, rhoW = 4 + 1 = 5
        let encoded_from_b = encode_sparse(&src.precisions, 0b0000000000_00000000_00_00001, 2);
        // rhoW counts 5 additional 0's, rhoW = 24 + 5 = 29
        let encoded_from_c25 = encode_sparse(&src.precisions, 0b0000000000_00000000_01_00000, 24);
        let encoded_from_c20 = encode_sparse(&dst.precisions, 0b0000000000_00000000_01, 29);
        // rhoW counts 4 leading 0's of 00001, rhoW = 4 + 1 = 5
        let encoded_from_d = encode_sparse(&src.precisions, 0b0000000000_00000000_01_00001, 24);
        // rhoW counts 5 additional 0's, rhoW = 46 + 5 = 51
        let encoded_from_e = encode_sparse(&src.precisions, 0b0000000000_00000000_10_00000, 46);
        // rhoW counts 4 leading 0's of 00001, rhoW = 4 + 1 = 5
        let encoded_from_f = encode_sparse(&src.precisions, 0b0000000000_00000000_10_00001, 46);

        match dst.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // encodedIntoA last because it is rhoW-encoded, so its most significant bit is set, so it is ordered higher than others
                sparse_data.push(encoded_into_b);
                sparse_data.push(encoded_into_c);
                sparse_data.push(encoded_into_a);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
        match src.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // encodedFromA last because it is rhoW-encoded, so its most significant bit is set, so it is ordered higher than others
                sparse_data.push(encoded_from_b);
                sparse_data.push(encoded_from_c25);
                sparse_data.push(encoded_from_d);
                sparse_data.push(encoded_from_e);
                sparse_data.push(encoded_from_f);
                sparse_data.push(encoded_from_a25);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Sparse(sparse_data) => {
                assert_eq!(3, sparse_data.len());
                assert_eq!(encoded_from_c20, sparse_data[0]); // max(1, 7, 5) = 7
                assert_eq!(encoded_into_c, sparse_data[1]); // max(28, 29, 5) = 29
                assert_eq!(encoded_from_a20, sparse_data[2]); // max(55, 51, 5) = 55
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }
    }

    #[test]
    fn merge_sparse_to_normal_to_downgrade_precision_nonempty_sketch_colliding_downgraded_values() {
        let mut dst = super::HyperLogLogPlusPlus::new_with_precision(10, 20)
            .unwrap()
            .as_dense();
        let mut src = super::HyperLogLogPlusPlus::new_with_precision(18, 25).unwrap();

        // rhoW counts 15 additional 0's, rhoW = 2 + 15 = 17
        let encoded_from_a = encode_sparse(&src.precisions, 0b0000000000_000000000000000, 2);
        // rhoW counts 14 leading 0's of 000000000000001, rhoW = 14 + 1 = 15
        let encoded_from_b = encode_sparse(&src.precisions, 0b0000000000_000000000000001, 2);
        // rhoW counts 15 additional 0's, rhoW = 20 + 15 = 35
        let encoded_from_c = encode_sparse(&src.precisions, 0b0000000001_000000000000000, 20);
        // rhoW counts 14 leading 0's of 000000000000001, rhoW = 14 + 1 = 15
        let encoded_from_d = encode_sparse(&src.precisions, 0b0000000001_000000000000001, 20);
        // rhoW counts 15 additional 0's, rhoW = 36 + 15 = 51
        let encoded_from_e = encode_sparse(&src.precisions, 0b0000000010_000000000000000, 36);
        // rhoW counts 14 leading 0's of 000000000000001, rhoW = 14 + 1 = 15
        let encoded_from_f = encode_sparse(&src.precisions, 0b0000000010_000000000000001, 36);

        match dst.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0b0000000000] = 1;
                dense_data[0b0000000001] = 28;
                dense_data[0b0000000010] = 55;
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
        match src.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                // encodedFromA last because it is rhoW-encoded, so its most significant bit is set, so it is ordered higher than others
                sparse_data.push(encoded_from_b);
                sparse_data.push(encoded_from_c);
                sparse_data.push(encoded_from_d);
                sparse_data.push(encoded_from_e);
                sparse_data.push(encoded_from_f);
                sparse_data.push(encoded_from_a);
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        dst.merge(&src);

        assert_eq!(10, dst.precisions.dense);
        assert_eq!(20, dst.precisions.sparse);
        match dst.sketch {
            crate::Sketch::Dense(dense_data) => {
                assert_eq!(17, dense_data[0b0000000000]); // max(1, 17, 15) = 17
                assert_eq!(35, dense_data[0b0000000001]); // max(28, 35, 15) = 35
                assert_eq!(55, dense_data[0b0000000010]); // max(55, 51, 15) = 55
                assert_eq!(
                    17 + 35 + 55,
                    dense_data.iter().map(|&d| d as i32).sum::<i32>()
                );
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }
    }

    #[test]
    fn get_estimate_empty_sketch() {
        let sketch = crate::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();

        let result = sketch.get_estimate();

        assert_eq!(result, 0);
    }

    #[test]
    fn get_estimate_linear_count_a() {
        // linear counting threshold for precision 10 is 900 (see linearCountingThresholds in getestimate.go)
        // linear count is 1024*ln(1024/1023) = 1.0004 which is less than 900, so we use it as the estimate (rounded)
        let mut sketch = crate::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        match sketch.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                dense_data[0] = 55; // this value doesn't matter if we're using linear counting
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        let result = sketch.get_estimate();

        assert_eq!(result, 1);
    }

    #[test]
    fn get_estimate_linear_count_b() {
        // linear counting threshold for precision 10 is 900 (see linearCountingThresholds in getestimate.go)
        // linear count is 1024*ln(1024/(1024-598)) = 898.08 which is less than 900, so we use it as the estimate (rounded)
        let mut sketch = crate::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        match sketch.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                for i in 0..598 {
                    dense_data[i] = 55; // this value doesn't matter if we're using linear counting
                }
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        let result = sketch.get_estimate();

        assert_eq!(result, 898);
    }

    #[test]
    fn get_estimate_linear_count_sparse() {
        // linear counting threshold for precision 10 is 900 (see linearCountingThresholds in getestimate.go)
        // linear count is 1024*ln(1024/(1024-599)) = 900.49 which is greater than 900, but representation is sparse, so we use linear count as the estimate
        let mut sketch = crate::HyperLogLogPlusPlus::new_with_precision(10, 10).unwrap();
        match sketch.sketch {
            crate::Sketch::Sparse(ref mut sparse_data) => {
                for i in 0..599 {
                    sparse_data.push(encode_sparse(&sketch.precisions, i, 55)); // this value doesn't matter if we're using linear counting
                }
            }
            crate::Sketch::Dense(_) => {
                panic!("expected sparse sketch")
            }
        }

        let result = sketch.get_estimate();

        assert_eq!(result, 900);
    }

    #[test]
    fn get_estimate_hll_no_bias() {
        // zero count is 0 so we use HLL
        // raw estimate is 0.7213 / (1 + 1.079 * 2^-10) * 1024 * (1024 / (1024 * 2^-3)) = 5902.6699
        // highest bias estimate in meanData is 5084.1828, so because our estimate is bigger, bias is estimated to be 0
        // unbiasedEstimate is 5902.6699 - 0 = 5902.6699 = 5903
        let mut sketch = crate::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        match sketch.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                for i in 0..1024 {
                    dense_data[i] = 3;
                }
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        let result = sketch.get_estimate();

        assert_eq!(result, 5903);
    }

    #[test]
    fn get_estimate_hll() {
        // linear counting threshold for precision 10 is 900 (see linearCountingThresholds in getestimate.go)
        // linear count is 1024*ln(1024/(1024-599)) = 900.49 which is greater than 900, so we use HLL
        // raw estimate is 0.7213 / (1 + 1.079 * 2^-10) * 1024 * (1024 / ((599 * 2^-55) + (1024-599) * 2^0)) = 1777.7453
        // closestBiases are indexes [61, 67): {194.9012, 188.4486, 183.1556, 178.6338, 173.7312, 169.6264}
        // biasEstimate is:
        // (194.9012 / (1777.7453 - 1730.9012)^2 + 188.4486 / (1777.7453 - 1750.4486)^2 + 183.1556 / (1777.7453 - 1770.1556)^2 + 178.6338 / (1777.7453 - 1791.6338)^2 + 173.7312 / (1777.7453 - 1812.7312)^2 + 169.6264 / (1777.7453 - 1833.6264)^2) /
        // ((1777.7453 - 1730.9012)^-2 + (1777.7453 - 1750.4486)^-2 + (1777.7453 - 1770.1556)^-2 + (1777.7453 - 1791.6338)^-2 + (1777.7453 - 1812.7312)^-2 + (1777.7453 - 1833.6264)^-2)
        // = 182.2522
        // unbiasedEstimate is 1777.7453 - 182.2522 = 1595.4931 = 1595
        let mut sketch = crate::HyperLogLogPlusPlus::new_with_precision(10, 25)
            .unwrap()
            .as_dense();
        match sketch.sketch {
            crate::Sketch::Dense(ref mut dense_data) => {
                for i in 0..599 {
                    dense_data[i] = 55;
                }
            }
            crate::Sketch::Sparse(_) => {
                panic!("expected dense sketch")
            }
        }

        let result = sketch.get_estimate();

        assert_eq!(result, 1595);
    }
}
