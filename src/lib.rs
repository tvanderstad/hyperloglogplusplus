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

pub const MIN_PRECISION: u8 = 15;
pub const MAX_DENSE_PRECISION: u8 = 18;
pub const MAX_SPARSE_PRECISION: u8 = 25;

#[derive(Clone)]
pub struct HyperLogLogPlusPlus {
    pub precisions: Precisions,
    sketch: Sketch,
}

#[derive(Clone, Copy)]
pub struct Precisions {
    dense: u8,
    sparse: u8,
}

#[derive(Clone)]
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
            self.precisions.dense
        } else {
            self.precisions.sparse
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
                    if let Err(index) = sparse_sketch.binary_search(&encoded_to_insert) {
                        sparse_sketch.insert(index, encoded_to_insert)
                    }
                } else {
                    // This is the encoding chosen if rhoW can't be determined from sparseIndex, and the encoding is a flag, optional padding, the normal index, and rhoW.
                    // rhoW isn't determined by the index, so instead of an exact match, we need to find the entry matching our index and overwrite if ours is larger, otherwise insert.
                    // The order of fields in the encoding was chosen so that sorting entries by encoding sorts first by index then by rhoW, so we can still search efficiently.
                    if let Err(index) = sparse_sketch.binary_search(&encoded_to_insert) {
                        // no exactly matching entry found
                        // check if the entry at the point to insert has the same index - if so it has a higher rhoW because of sort order so we do nothing
                        if index != sparse_sketch.len() {
                            let (next_index, _) = bit_arithmetic::decode_sparse(
                                &self.precisions,
                                sparse_sketch[index],
                            );
                            if index as u32 == next_index {
                                return;
                            }
                        }
                        // check if the entry just before the point to insert has the same index - if so it has a smaller rhoW because of sort order so we overwrite
                        if index != 0 {
                            let (previous_index, _) = bit_arithmetic::decode_sparse(
                                &self.precisions,
                                sparse_sketch[index - 1],
                            );
                            if index as u32 == previous_index {
                                sparse_sketch[index - 1] = encoded_to_insert;
                                return;
                            }
                        }
                        // no index-matching entry found
                        sparse_sketch.insert(index, encoded_to_insert);
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

mod bit_arithmetic;
mod get_estimate;
mod merge;
