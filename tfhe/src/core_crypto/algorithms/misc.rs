//! Miscellaneous algorithms.

use crate::core_crypto::prelude::*;

/// Convenience function using a bit trick to determine whether a scalar is a power of 2.
pub fn is_power_of_two<Scalar>(scalar: Scalar) -> bool
where
    Scalar: UnsignedInteger,
{
    (scalar != Scalar::ZERO) && ((scalar & (scalar - Scalar::ONE)) == Scalar::ZERO)
}

pub const fn is_native_modulus<Scalar, const Q: u128>() -> bool
where
    Scalar: UnsignedInteger,
{
    (Scalar::BITS == 128 && Q == 0) || (Q == 1 << Scalar::BITS)
}

#[inline]
pub fn copy_from_convert<ScalarDst, ScalarSrc, Dst, Src>(dst: &mut Dst, src: &Src)
where
    ScalarSrc: Copy + CastInto<ScalarDst>,
    Dst: AsMut<[ScalarDst]>,
    Src: AsRef<[ScalarSrc]>,
{
    let dst = dst.as_mut();
    let src = src.as_ref();

    debug_assert_eq!(dst.len(), src.len());

    dst.iter_mut()
        .zip(src.iter())
        .for_each(|(dst, &src)| *dst = src.cast_into());
}

#[inline]
pub fn copy_from_u128_mod_convert<ScalarDst, Dst, Src, const Q: u128>(dst: &mut Dst, src: &Src)
where
    Dst: AsMut<[ScalarDst]>,
    Src: AsRef<[u128]>,
    ScalarDst: CastFrom<u128>,
{
    let dst = dst.as_mut();
    let src = src.as_ref();

    debug_assert_eq!(dst.len(), src.len());

    dst.iter_mut()
        .zip(src.iter())
        .for_each(|(dst, &src)| *dst = src.wrapping_rem_euclid(Q).cast_into());
}
