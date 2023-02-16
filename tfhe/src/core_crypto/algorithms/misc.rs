//! Miscellaneous algorithms.

use crate::core_crypto::prelude::*;

#[inline]
pub fn copy_from_convert<ScalarDst, ScalarSrc, Dst, Src>(dst: &mut Dst, src: &Src)
where
    ScalarSrc: Copy + CastInto<ScalarDst>,
    Dst: AsMut<[ScalarDst]>,
    Src: AsRef<[ScalarSrc]>,
{
    let dst = dst.as_mut();
    let src = src.as_ref();

    assert_eq!(dst.len(), src.len());

    dst.iter_mut()
        .zip(src.iter())
        .for_each(|(dst, &src)| *dst = src.cast_into());
}

#[inline]
pub fn divide_round<Scalar>(numerator: Scalar, denominator: Scalar) -> Scalar
where
    Scalar: UnsignedInteger,
{
    let numerator_128: u128 = numerator.cast_into();
    let half_denominator: u128 = (denominator / Scalar::TWO).cast_into();
    let denominator_128: u128 = denominator.cast_into();
    let rounded_128 = (numerator_128 + half_denominator) / denominator_128;
    rounded_128.cast_into()
}

#[inline]
pub fn divide_round_to_u128<Scalar>(numerator: Scalar, denominator: Scalar) -> u128
where
    Scalar: UnsignedInteger,
{
    let numerator_128: u128 = numerator.cast_into();
    let half_denominator: u128 = (denominator / Scalar::TWO).cast_into();
    let denominator_128: u128 = denominator.cast_into();
    let rounded_128 = (numerator_128 + half_denominator) / denominator_128;
    rounded_128
}

#[test]
fn test_divide_round() {
    use rand::Rng;

    let mut rng = rand::thread_rng();

    const NB_TESTS: usize = 1_000_000_000;
    const SCALING: f64 = u64::MAX as f64;
    for _ in 0..NB_TESTS {
        let num: f64 = rng.gen();
        let mut denom = 0.0f64;
        while denom == 0.0f64 {
            denom = rng.gen();
        }

        let num = (num * SCALING).round();
        let denom = (denom * SCALING).round();

        let rounded = (num / denom).round();
        let expected_rounded_u64: u64 = rounded as u64;

        let num_u64: u64 = num as u64;
        let denom_u64: u64 = denom as u64;

        // sanity check
        assert_eq!(num, num_u64 as f64);
        assert_eq!(denom, denom_u64 as f64);

        let rounded_u64 = divide_round(num_u64, denom_u64);

        assert_eq!(expected_rounded_u64, rounded_u64);
    }
}
