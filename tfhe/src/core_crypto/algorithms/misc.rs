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
