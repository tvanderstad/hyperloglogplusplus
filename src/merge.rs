use crate::bit_arithmetic;
use crate::HyperLogLogPlusPlus;

// merge_from_same_or_higher_precision merges src into dst assuming src precisions are greater than or equal to respective dst precisions
pub(crate) fn merge_from_same_or_higher_precision(
    dst: &mut HyperLogLogPlusPlus,
    src: &HyperLogLogPlusPlus,
) {
    match (dst.get_precision() == src.get_precision(), &src.sketch) {
        (true, crate::Sketch::Dense(dense_sketch)) => {
            for (index, value) in dense_sketch.iter().enumerate() {
                dst.set_if_larger(index as u32, *value);
            }
        }
        (true, crate::Sketch::Sparse(sparse_sketch)) => {
            for encoded_value in sparse_sketch {
                let (index, value) = bit_arithmetic::decode_sparse(&src.precisions, *encoded_value);
                dst.set_if_larger(index, value);
            }
        }
        (false, crate::Sketch::Dense(dense_sketch)) => {
            let dst_precision = dst.get_precision();
            let src_precision = src.get_precision();
            for (old_index, old_value) in dense_sketch.iter().enumerate() {
                let old_index = old_index as u32;
                let new_index =
                    bit_arithmetic::downgrade_index(old_index, src_precision, dst_precision);
                let new_value = bit_arithmetic::downgrade_rho_w(
                    old_index,
                    *old_value,
                    src_precision,
                    dst_precision,
                );
                dst.set_if_larger(new_index, new_value);
            }
        }
        (false, crate::Sketch::Sparse(sparse_sketch)) => {
            let dst_precision = dst.get_precision();
            let src_precision = src.get_precision();
            for encoded_value in sparse_sketch {
                let (old_index, old_value) =
                    bit_arithmetic::decode_sparse(&src.precisions, *encoded_value);
                let new_index =
                    bit_arithmetic::downgrade_index(old_index, src_precision, dst_precision);
                let new_value = bit_arithmetic::downgrade_rho_w(
                    old_index,
                    old_value,
                    src_precision,
                    dst_precision,
                );
                dst.set_if_larger(new_index, new_value);
            }
        }
    }
}
