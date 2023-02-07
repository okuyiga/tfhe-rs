use super::super::{as_arrays, as_arrays_mut};
use crate::core_crypto::commons::utils::izip;
pub use crate::core_crypto::fft_128_impl::math::fft::{Fft128, Fft128View};
use crate::core_crypto::fft_impl::{as_mut_uninit, assume_init_mut};
use concrete_fft::fft128::f128;
use core::mem::{transmute, MaybeUninit};
use dyn_stack::DynStack;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
pub fn u128_to_f64((lo, hi): (u64, u64)) -> f64 {
    const A: f64 = (1u128 << 52) as f64;
    const B: f64 = (1u128 << 104) as f64;
    const C: f64 = (1u128 << 76) as f64;
    const D: f64 = u128::MAX as f64;
    if hi < 1 << 40 {
        let l = f64::from_bits(A.to_bits() | (lo << 12) >> 12) - A;
        let h = f64::from_bits(B.to_bits() | ((lo >> 52) | (hi << 12))) - B;
        l + h
    } else {
        let l =
            f64::from_bits(C.to_bits() | (((lo >> 12) | (hi << 52)) >> 12) | (lo & 0xFFFFFF)) - C;
        let h = f64::from_bits(D.to_bits() | (hi >> 12)) - D;
        l + h
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512dq")]
#[inline]
pub unsafe fn _mm512_movm_epi64(k: u8) -> __m512i {
    let zeros = _mm512_setzero_si512();
    let ones = _mm512_set1_epi64(-1);
    _mm512_mask_blend_epi64(k, zeros, ones)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512dq")]
#[inline]
pub unsafe fn _mm512_movepi64_mask(a: __m512i) -> u8 {
    let mask = _mm512_set1_epi64(1 << 63);
    let a = _mm512_and_si512(a, mask);
    _mm512_cmpeq_epi64_mask(a, mask)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn _mm256_cmplt_epu64(a: __m256i, b: __m256i) -> __m256i {
    let k = _mm256_set1_epi64x(0x8000000000000000u64 as _);
    _mm256_cmpgt_epi64(_mm256_xor_si256(b, k), _mm256_xor_si256(a, k))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn u128_to_f64_avx2((lo, hi): (__m256i, __m256i)) -> __m256d {
    const A: f64 = (1u128 << 52) as f64;
    const B: f64 = (1u128 << 104) as f64;
    const C: f64 = (1u128 << 76) as f64;
    const D: f64 = u128::MAX as f64;

    let a = _mm256_set1_pd(A);
    let b = _mm256_set1_pd(B);
    let c = _mm256_set1_pd(C);
    let d = _mm256_set1_pd(D);

    _mm256_blendv_pd(
        {
            // cond is false
            let x0 = _mm256_castpd_si256(c);
            let x1 = _mm256_srli_epi64::<12>(_mm256_or_si256(
                _mm256_srli_epi64::<12>(lo),
                _mm256_slli_epi64::<52>(hi),
            ));
            let x2 = _mm256_and_si256(lo, _mm256_set1_epi64x(0xFFFFFF));
            let l = _mm256_sub_pd(
                _mm256_castsi256_pd(_mm256_or_si256(x1, _mm256_or_si256(x2, x0))),
                c,
            );
            let h = _mm256_sub_pd(
                _mm256_castsi256_pd(_mm256_or_si256(
                    _mm256_castpd_si256(d),
                    _mm256_srli_epi64::<12>(hi),
                )),
                d,
            );
            _mm256_add_pd(l, h)
        },
        {
            // cond is true
            let l = _mm256_sub_pd(
                _mm256_castsi256_pd(_mm256_or_si256(
                    _mm256_castpd_si256(a),
                    _mm256_and_si256(lo, _mm256_set1_epi64x(0xFFFFFFFFFFFFF)),
                )),
                a,
            );

            let h = _mm256_sub_pd(
                _mm256_castsi256_pd(_mm256_or_si256(
                    _mm256_castpd_si256(b),
                    _mm256_or_si256(_mm256_srli_epi64::<52>(lo), _mm256_slli_epi64::<12>(hi)),
                )),
                b,
            );

            _mm256_add_pd(l, h)
        },
        _mm256_castsi256_pd(_mm256_cmplt_epu64(hi, _mm256_set1_epi64x(1 << 40))),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
pub unsafe fn u128_to_f64_avx512((lo, hi): (__m512i, __m512i)) -> __m512d {
    const A: f64 = (1u128 << 52) as f64;
    const B: f64 = (1u128 << 104) as f64;
    const C: f64 = (1u128 << 76) as f64;
    const D: f64 = u128::MAX as f64;

    let a = _mm512_set1_pd(A);
    let b = _mm512_set1_pd(B);
    let c = _mm512_set1_pd(C);
    let d = _mm512_set1_pd(D);

    _mm512_mask_blend_pd(
        _mm512_cmplt_epu64_mask(hi, _mm512_set1_epi64(1 << 40)),
        {
            // cond is false
            let x0 = _mm512_castpd_si512(c);
            let x1 = _mm512_srli_epi64::<12>(_mm512_or_si512(
                _mm512_srli_epi64::<12>(lo),
                _mm512_slli_epi64::<52>(hi),
            ));
            let x2 = _mm512_and_si512(lo, _mm512_set1_epi64(0xFFFFFF));
            let l = _mm512_sub_pd(
                _mm512_castsi512_pd(_mm512_or_si512(x1, _mm512_or_si512(x2, x0))),
                c,
            );
            let h = _mm512_sub_pd(
                _mm512_castsi512_pd(_mm512_or_si512(
                    _mm512_castpd_si512(d),
                    _mm512_srli_epi64::<12>(hi),
                )),
                d,
            );
            _mm512_add_pd(l, h)
        },
        {
            // cond is true
            let l = _mm512_sub_pd(
                _mm512_castsi512_pd(_mm512_or_si512(
                    _mm512_castpd_si512(a),
                    _mm512_and_si512(lo, _mm512_set1_epi64(0xFFFFFFFFFFFFF)),
                )),
                a,
            );

            let h = _mm512_sub_pd(
                _mm512_castsi512_pd(_mm512_or_si512(
                    _mm512_castpd_si512(b),
                    _mm512_or_si512(_mm512_srli_epi64::<52>(lo), _mm512_slli_epi64::<12>(hi)),
                )),
                b,
            );

            _mm512_add_pd(l, h)
        },
    )
}

#[inline(always)]
pub fn wrapping_sub((a_lo, a_hi): (u64, u64), (b_lo, b_hi): (u64, u64)) -> (u64, u64) {
    let (diff_lo, overflow) = a_lo.overflowing_sub(b_lo);
    (diff_lo, a_hi.wrapping_sub(b_hi).wrapping_sub(overflow as _))
}

#[inline(always)]
pub fn wrapping_add((a_lo, a_hi): (u64, u64), (b_lo, b_hi): (u64, u64)) -> (u64, u64) {
    let (sum_lo, overflow) = a_lo.overflowing_add(b_lo);
    (sum_lo, a_hi.wrapping_add(b_hi).wrapping_add(overflow as _))
}

#[inline(always)]
pub fn wrapping_neg((lo, hi): (u64, u64)) -> (u64, u64) {
    wrapping_add((1, 0), (!lo, !hi))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn wrapping_sub_avx2(
    (a_lo, a_hi): (__m256i, __m256i),
    (b_lo, b_hi): (__m256i, __m256i),
) -> (__m256i, __m256i) {
    let diff_lo = _mm256_sub_epi64(a_lo, b_lo);
    let diff_hi0 = _mm256_sub_epi64(a_hi, b_hi);
    let overflow = _mm256_cmplt_epu64(a_lo, b_lo);
    let diff_hi = _mm256_add_epi64(diff_hi0, overflow);
    (diff_lo, diff_hi)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn wrapping_add_avx2(
    (a_lo, a_hi): (__m256i, __m256i),
    (b_lo, b_hi): (__m256i, __m256i),
) -> (__m256i, __m256i) {
    let sum_lo = _mm256_add_epi64(a_lo, b_lo);
    let overflow = _mm256_cmplt_epu64(sum_lo, a_lo);
    let sum_hi0 = _mm256_add_epi64(a_hi, b_hi);
    let sum_hi = _mm256_sub_epi64(sum_hi0, overflow);
    (sum_lo, sum_hi)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn wrapping_neg_avx2((lo, hi): (__m256i, __m256i)) -> (__m256i, __m256i) {
    let diff_lo = _mm256_sub_epi64(_mm256_setzero_si256(), lo);
    let overflow = _mm256_cmplt_epu64(_mm256_setzero_si256(), lo);
    let diff_hi = _mm256_sub_epi64(overflow, hi);
    (diff_lo, diff_hi)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
pub unsafe fn wrapping_sub_avx512(
    (a_lo, a_hi): (__m512i, __m512i),
    (b_lo, b_hi): (__m512i, __m512i),
) -> (__m512i, __m512i) {
    let diff_lo = _mm512_sub_epi64(a_lo, b_lo);
    let diff_hi0 = _mm512_sub_epi64(a_hi, b_hi);
    let overflow = _mm512_movm_epi64(_mm512_cmplt_epu64_mask(a_lo, b_lo));
    let diff_hi = _mm512_add_epi64(diff_hi0, overflow);
    (diff_lo, diff_hi)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
pub unsafe fn wrapping_add_avx512(
    (a_lo, a_hi): (__m512i, __m512i),
    (b_lo, b_hi): (__m512i, __m512i),
) -> (__m512i, __m512i) {
    let sum_lo = _mm512_add_epi64(a_lo, b_lo);
    let overflow = _mm512_movm_epi64(_mm512_cmplt_epu64_mask(sum_lo, a_lo));
    let sum_hi0 = _mm512_add_epi64(a_hi, b_hi);
    let sum_hi = _mm512_sub_epi64(sum_hi0, overflow);
    (sum_lo, sum_hi)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
pub unsafe fn wrapping_neg_avx512((lo, hi): (__m512i, __m512i)) -> (__m512i, __m512i) {
    let diff_lo = _mm512_sub_epi64(_mm512_setzero_si512(), lo);
    let overflow = _mm512_movm_epi64(_mm512_cmplt_epu64_mask(_mm512_setzero_si512(), lo));
    let diff_hi = _mm512_sub_epi64(overflow, hi);
    (diff_lo, diff_hi)
}

#[inline(always)]
fn i128_to_f64((lo, hi): (u64, u64)) -> f64 {
    let sign = hi & (1u64 << 63);
    let abs = if sign == (1u64 << 63) {
        wrapping_neg((lo, hi))
    } else {
        (lo, hi)
    };
    f64::from_bits(u128_to_f64(abs).to_bits() | sign)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn i128_to_f64_avx2((lo, hi): (__m256i, __m256i)) -> __m256d {
    let sign_bit = _mm256_set1_epi64x(1 << 63);
    let sign = _mm256_and_si256(hi, sign_bit);
    let neg = wrapping_neg_avx2((lo, hi));

    let abs = (
        _mm256_castpd_si256(_mm256_blendv_pd(
            _mm256_castsi256_pd(lo),
            _mm256_castsi256_pd(neg.0),
            _mm256_castsi256_pd(sign),
        )),
        _mm256_castpd_si256(_mm256_blendv_pd(
            _mm256_castsi256_pd(hi),
            _mm256_castsi256_pd(neg.1),
            _mm256_castsi256_pd(sign),
        )),
    );

    _mm256_castsi256_pd(_mm256_or_si256(
        _mm256_castpd_si256(u128_to_f64_avx2(abs)),
        sign,
    ))
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
unsafe fn i128_to_f64_avx512((lo, hi): (__m512i, __m512i)) -> __m512d {
    let sign = _mm512_movepi64_mask(hi);
    let neg = wrapping_neg_avx512((lo, hi));

    let abs = (
        _mm512_mask_blend_epi64(sign, lo, neg.0),
        _mm512_mask_blend_epi64(sign, hi, neg.1),
    );

    _mm512_castsi512_pd(_mm512_or_si512(
        _mm512_castpd_si512(u128_to_f64_avx512(abs)),
        _mm512_and_si512(hi, _mm512_set1_epi64(1 << 63)),
    ))
}

#[inline(always)]
pub fn f64_to_u128(f: f64) -> (u64, u64) {
    let f = f.to_bits();
    if f < 1023 << 52 {
        // >= 0, < 1
        (0u64, 0u64)
    } else {
        // >= 1, < max
        let hi = 1 << 63 | f << 11;
        let s = 1150 - (f >> 52); // Shift based on the exponent and bias.
        if s >= 128 {
            (0u64, 0u64)
        } else if s >= 64 {
            (hi >> (s - 64), 0u64)
        } else {
            (hi << (64 - s), hi >> s)
        }
    }
}

#[inline(always)]
pub fn f64_to_i128(f: f64) -> (u64, u64) {
    let f = f.to_bits();

    let a = f & !0 >> 1; // Remove sign bit.
    if a < 1023 << 52 {
        // >= 0, < 1
        (0, 0)
    } else {
        // >= 1, < max
        let hi = 1 << 63 | a << 11;
        let s = 1150 - (a >> 52); // Shift based on the exponent and bias.
        let u = if s >= 128 {
            (0, 0)
        } else if s >= 64 {
            (hi >> (s - 64), 0)
        } else {
            (hi << (64 - s), hi >> s)
        };
        if (f as i64) < 0 {
            wrapping_neg(u)
        } else {
            u
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn f64_to_u128_avx2(f: __m256d) -> (__m256i, __m256i) {
    let f = _mm256_castpd_si256(f);
    let less_than_one = _mm256_cmplt_epu64(f, _mm256_set1_epi64x(1023 << 52));
    let if_not_zero = {
        let hi = _mm256_or_si256(_mm256_set1_epi64x(1 << 63), _mm256_slli_epi64::<11>(f));
        let shift = _mm256_sub_epi64(_mm256_set1_epi64x(1150), _mm256_srli_epi64::<52>(f));
        (
            _mm256_or_si256(
                _mm256_srlv_epi64(hi, _mm256_sub_epi64(shift, _mm256_set1_epi64x(64))),
                _mm256_sllv_epi64(hi, _mm256_sub_epi64(_mm256_set1_epi64x(64), shift)),
            ),
            _mm256_srlv_epi64(hi, shift),
        )
    };
    (
        _mm256_andnot_si256(less_than_one, if_not_zero.0),
        _mm256_andnot_si256(less_than_one, if_not_zero.1),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn f64_to_i128_avx2(f: __m256d) -> (__m256i, __m256i) {
    let sign_bit = _mm256_set1_epi64x(1 << 63);
    let f = _mm256_castpd_si256(f);
    let a = _mm256_andnot_si256(sign_bit, f);

    let less_than_one = _mm256_cmplt_epu64(a, _mm256_set1_epi64x(1023 << 52));
    let if_not_zero = {
        let hi = _mm256_or_si256(_mm256_set1_epi64x(1 << 63), _mm256_slli_epi64::<11>(a));
        let shift = _mm256_sub_epi64(_mm256_set1_epi64x(1150), _mm256_srli_epi64::<52>(a));
        let abs = (
            _mm256_or_si256(
                _mm256_srlv_epi64(hi, _mm256_sub_epi64(shift, _mm256_set1_epi64x(64))),
                _mm256_sllv_epi64(hi, _mm256_sub_epi64(_mm256_set1_epi64x(64), shift)),
            ),
            _mm256_srlv_epi64(hi, shift),
        );
        let neg = wrapping_neg_avx2(abs);
        (
            _mm256_castpd_si256(_mm256_blendv_pd(
                _mm256_castsi256_pd(abs.0),
                _mm256_castsi256_pd(neg.0),
                _mm256_castsi256_pd(f),
            )),
            _mm256_castpd_si256(_mm256_blendv_pd(
                _mm256_castsi256_pd(abs.1),
                _mm256_castsi256_pd(neg.1),
                _mm256_castsi256_pd(f),
            )),
        )
    };
    (
        _mm256_andnot_si256(less_than_one, if_not_zero.0),
        _mm256_andnot_si256(less_than_one, if_not_zero.1),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
unsafe fn f64_to_i128_avx512(f: __m512d) -> (__m512i, __m512i) {
    let sign_bit = _mm512_set1_epi64(1 << 63);
    let f = _mm512_castpd_si512(f);
    let a = _mm512_andnot_si512(sign_bit, f);

    let less_than_one =
        _mm512_movm_epi64(_mm512_cmplt_epu64_mask(a, _mm512_set1_epi64(1023 << 52)));
    let if_not_zero = {
        let hi = _mm512_or_si512(_mm512_set1_epi64(1 << 63), _mm512_slli_epi64::<11>(a));
        let shift = _mm512_sub_epi64(_mm512_set1_epi64(1150), _mm512_srli_epi64::<52>(a));
        let abs = (
            _mm512_or_si512(
                _mm512_srlv_epi64(hi, _mm512_sub_epi64(shift, _mm512_set1_epi64(64))),
                _mm512_sllv_epi64(hi, _mm512_sub_epi64(_mm512_set1_epi64(64), shift)),
            ),
            _mm512_srlv_epi64(hi, shift),
        );
        let neg = wrapping_neg_avx512(abs);
        (
            _mm512_castpd_si512(_mm512_mask_blend_pd(
                _mm512_movepi64_mask(f),
                _mm512_castsi512_pd(abs.0),
                _mm512_castsi512_pd(neg.0),
            )),
            _mm512_castpd_si512(_mm512_mask_blend_pd(
                _mm512_movepi64_mask(f),
                _mm512_castsi512_pd(abs.1),
                _mm512_castsi512_pd(neg.1),
            )),
        )
    };
    (
        _mm512_andnot_si512(less_than_one, if_not_zero.0),
        _mm512_andnot_si512(less_than_one, if_not_zero.1),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
unsafe fn f64_to_u128_avx512(f: __m512d) -> (__m512i, __m512i) {
    let f = _mm512_castpd_si512(f);
    let less_than_one =
        _mm512_movm_epi64(_mm512_cmplt_epu64_mask(f, _mm512_set1_epi64(1023 << 52)));
    let if_not_zero = {
        let hi = _mm512_or_si512(_mm512_set1_epi64(1 << 63), _mm512_slli_epi64::<11>(f));
        let shift = _mm512_sub_epi64(_mm512_set1_epi64(1150), _mm512_srli_epi64::<52>(f));
        (
            _mm512_or_si512(
                _mm512_srlv_epi64(hi, _mm512_sub_epi64(shift, _mm512_set1_epi64(64))),
                _mm512_sllv_epi64(hi, _mm512_sub_epi64(_mm512_set1_epi64(64), shift)),
            ),
            _mm512_srlv_epi64(hi, shift),
        )
    };
    (
        _mm512_andnot_si512(less_than_one, if_not_zero.0),
        _mm512_andnot_si512(less_than_one, if_not_zero.1),
    )
}

#[inline(always)]
fn to_signed_to_f128((lo, hi): (u64, u64)) -> f128 {
    // convert to signed then to float
    let first_approx = i128_to_f64((lo, hi));

    // discard sign then convert back to unsigned integer, the result can be at most `2^(BITS - 1)`,
    // which should fit in a `Scalar`
    //
    // we perform this step since converting back directly to a signed integer may overflow
    let sign_bit = first_approx.to_bits() & (1u64 << 63);
    let first_approx_roundtrip = f64_to_u128(first_approx.abs());

    // apply sign again to get a wraparound effect
    let first_approx_roundtrip_signed = if sign_bit == (1u64 << 63) {
        // negative
        wrapping_neg(first_approx_roundtrip)
    } else {
        // positive
        first_approx_roundtrip
    };

    let correction = i128_to_f64(wrapping_sub((lo, hi), first_approx_roundtrip_signed) as _);
    f128(first_approx, correction)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn to_signed_to_f128_avx2((lo, hi): (__m256i, __m256i)) -> (__m256d, __m256d) {
    // convert to signed then to float
    let first_approx = i128_to_f64_avx2((lo, hi));

    // discard sign then convert back to unsigned integer, the result can be at most `2^(BITS - 1)`,
    // which should fit in a `Scalar`
    //
    // we perform this step since converting back directly to a signed integer may overflow
    let sign_bit = _mm256_set1_epi64x(1 << 63);
    let sign = _mm256_and_si256(sign_bit, _mm256_castpd_si256(first_approx));

    let first_approx_roundtrip = f64_to_u128_avx2(_mm256_castsi256_pd(_mm256_andnot_si256(
        sign_bit,
        _mm256_castpd_si256(first_approx),
    )));

    // apply sign again to get a wraparound effect
    let neg = wrapping_neg_avx2(first_approx_roundtrip);

    let first_approx_roundtrip_signed = (
        _mm256_castpd_si256(_mm256_blendv_pd(
            _mm256_castsi256_pd(first_approx_roundtrip.0),
            _mm256_castsi256_pd(neg.0),
            _mm256_castsi256_pd(sign),
        )),
        _mm256_castpd_si256(_mm256_blendv_pd(
            _mm256_castsi256_pd(first_approx_roundtrip.1),
            _mm256_castsi256_pd(neg.1),
            _mm256_castsi256_pd(sign),
        )),
    );

    let correction = i128_to_f64_avx2(wrapping_sub_avx2((lo, hi), first_approx_roundtrip_signed));
    (first_approx, correction)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
unsafe fn to_signed_to_f128_avx512((lo, hi): (__m512i, __m512i)) -> (__m512d, __m512d) {
    // convert to signed then to float
    let first_approx = i128_to_f64_avx512((lo, hi));

    // discard sign then convert back to unsigned integer, the result can be at most `2^(BITS - 1)`,
    // which should fit in a `Scalar`
    //
    // we perform this step since converting back directly to a signed integer may overflow
    let sign = _mm512_movepi64_mask(_mm512_castpd_si512(first_approx));
    let sign_bit = _mm512_set1_epi64(1 << 63);

    let first_approx_roundtrip = f64_to_u128_avx512(_mm512_castsi512_pd(_mm512_andnot_si512(
        sign_bit,
        _mm512_castpd_si512(first_approx),
    )));

    // apply sign again to get a wraparound effect
    let neg = wrapping_neg_avx512(first_approx_roundtrip);

    let first_approx_roundtrip_signed = (
        _mm512_mask_blend_epi64(sign, first_approx_roundtrip.0, neg.0),
        _mm512_mask_blend_epi64(sign, first_approx_roundtrip.1, neg.1),
    );

    let correction =
        i128_to_f64_avx512(wrapping_sub_avx512((lo, hi), first_approx_roundtrip_signed));
    (first_approx, correction)
}

#[inline(always)]
fn f128_floor(x: f128) -> f128 {
    let f128(x0, x1) = x;
    let x0_floor = x0.floor();
    if x0_floor == x0 {
        f128(x0_floor, x1.floor())
    } else {
        f128(x0_floor, 0.0)
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn f128_floor_avx2((x0, x1): (__m256d, __m256d)) -> (__m256d, __m256d) {
    let x0_floor = _mm256_floor_pd(x0);
    let x1_floor = _mm256_floor_pd(x1);

    (
        x0_floor,
        _mm256_blendv_pd(
            _mm256_setzero_pd(),
            x1_floor,
            _mm256_cmp_pd::<_CMP_EQ_OQ>(x0_floor, x0),
        ),
    )
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
unsafe fn f128_floor_avx512((x0, x1): (__m512d, __m512d)) -> (__m512d, __m512d) {
    let x0_floor = _mm512_roundscale_pd::<_MM_FROUND_TO_NEG_INF>(x0);
    let x1_floor = _mm512_roundscale_pd::<_MM_FROUND_TO_NEG_INF>(x1);

    (
        x0_floor,
        _mm512_mask_blend_pd(
            _mm512_cmp_pd_mask::<_CMP_EQ_OQ>(x0_floor, x0),
            _mm512_setzero_pd(),
            x1_floor,
        ),
    )
}

#[inline(always)]
fn from_torus_f128(x: f128) -> (u64, u64) {
    let mut x = x - f128_floor(x);

    let normalization = 2.0f64.powi(128);
    x.0 *= normalization;
    x.1 *= normalization;

    let x = f128_floor(x);

    let x0 = f64_to_u128(x.0);
    let x1 = f64_to_i128(x.1);

    wrapping_add(x0, x1)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn from_torus_f128_avx2(x: (__m256d, __m256d)) -> (__m256i, __m256i) {
    let floor = f128_floor_avx2(x);
    let mut x = concrete_fft::fft128::Avx::new_unchecked()
        ._mm256_sub_estimate_f128_f128(x.0, x.1, floor.0, floor.1);

    let normalization = _mm256_set1_pd(2.0f64.powi(128));
    x.0 = _mm256_mul_pd(normalization, x.0);
    x.1 = _mm256_mul_pd(normalization, x.1);

    let x = f128_floor_avx2(x);

    let x0 = f64_to_u128_avx2(x.0);
    let x1 = f64_to_i128_avx2(x.1);

    wrapping_add_avx2(x0, x1)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[inline(always)]
unsafe fn from_torus_f128_avx512(x: (__m512d, __m512d)) -> (__m512i, __m512i) {
    let floor = f128_floor_avx512(x);
    let mut x = concrete_fft::fft128::Avx512::new_unchecked()
        ._mm512_sub_estimate_f128_f128(x.0, x.1, floor.0, floor.1);

    let normalization = _mm512_set1_pd(2.0f64.powi(128));
    x.0 = _mm512_mul_pd(normalization, x.0);
    x.1 = _mm512_mul_pd(normalization, x.1);

    let x = f128_floor_avx512(x);

    let x0 = f64_to_u128_avx512(x.0);
    let x1 = f64_to_i128_avx512(x.1);

    wrapping_add_avx512(x0, x1)
}

pub fn convert_forward_torus(
    out_re0: &mut [MaybeUninit<f64>],
    out_re1: &mut [MaybeUninit<f64>],
    out_im0: &mut [MaybeUninit<f64>],
    out_im1: &mut [MaybeUninit<f64>],
    in_re_lo: &[u64],
    in_re_hi: &[u64],
    in_im_lo: &[u64],
    in_im_hi: &[u64],
) {
    let normalization = 2.0_f64.powi(-128);

    for (out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi) in
        izip!(out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi)
    {
        let out_re = to_signed_to_f128((*in_re_lo, *in_re_hi));
        let out_im = to_signed_to_f128((*in_im_lo, *in_im_hi));

        let out_re = (out_re.0 * normalization, out_re.1 * normalization);
        let out_im = (out_im.0 * normalization, out_im.1 * normalization);

        out_re0.write(out_re.0);
        out_re1.write(out_re.1);
        out_im0.write(out_im.0);
        out_im1.write(out_im.1);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,fma")]
pub unsafe fn convert_forward_integer_avx2(
    out_re0: &mut [MaybeUninit<f64>],
    out_re1: &mut [MaybeUninit<f64>],
    out_im0: &mut [MaybeUninit<f64>],
    out_im1: &mut [MaybeUninit<f64>],
    in_re_lo: &[u64],
    in_re_hi: &[u64],
    in_im_lo: &[u64],
    in_im_hi: &[u64],
) {
    let out_re0 = as_arrays_mut::<4, _>(out_re0).0;
    let out_re1 = as_arrays_mut::<4, _>(out_re1).0;
    let out_im0 = as_arrays_mut::<4, _>(out_im0).0;
    let out_im1 = as_arrays_mut::<4, _>(out_im1).0;

    let in_re_lo = as_arrays::<4, _>(in_re_lo).0;
    let in_re_hi = as_arrays::<4, _>(in_re_hi).0;
    let in_im_lo = as_arrays::<4, _>(in_im_lo).0;
    let in_im_hi = as_arrays::<4, _>(in_im_hi).0;

    for (out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi) in
        izip!(out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi)
    {
        let out_re = to_signed_to_f128_avx2((transmute(*in_re_lo), transmute(*in_re_hi)));
        let out_im = to_signed_to_f128_avx2((transmute(*in_im_lo), transmute(*in_im_hi)));

        *out_re0 = transmute(out_re.0);
        *out_re1 = transmute(out_re.1);
        *out_im0 = transmute(out_im.0);
        *out_im1 = transmute(out_im.1);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512f,avx512dq")]
pub unsafe fn convert_forward_integer_avx512(
    out_re0: &mut [MaybeUninit<f64>],
    out_re1: &mut [MaybeUninit<f64>],
    out_im0: &mut [MaybeUninit<f64>],
    out_im1: &mut [MaybeUninit<f64>],
    in_re_lo: &[u64],
    in_re_hi: &[u64],
    in_im_lo: &[u64],
    in_im_hi: &[u64],
) {
    let out_re0 = as_arrays_mut::<8, _>(out_re0).0;
    let out_re1 = as_arrays_mut::<8, _>(out_re1).0;
    let out_im0 = as_arrays_mut::<8, _>(out_im0).0;
    let out_im1 = as_arrays_mut::<8, _>(out_im1).0;

    let in_re_lo = as_arrays::<8, _>(in_re_lo).0;
    let in_re_hi = as_arrays::<8, _>(in_re_hi).0;
    let in_im_lo = as_arrays::<8, _>(in_im_lo).0;
    let in_im_hi = as_arrays::<8, _>(in_im_hi).0;

    for (out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi) in
        izip!(out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi)
    {
        let out_re = to_signed_to_f128_avx512((transmute(*in_re_lo), transmute(*in_re_hi)));
        let out_im = to_signed_to_f128_avx512((transmute(*in_im_lo), transmute(*in_im_hi)));

        *out_re0 = transmute(out_re.0);
        *out_re1 = transmute(out_re.1);
        *out_im0 = transmute(out_im.0);
        *out_im1 = transmute(out_im.1);
    }
}

pub fn convert_forward_integer_scalar(
    out_re0: &mut [MaybeUninit<f64>],
    out_re1: &mut [MaybeUninit<f64>],
    out_im0: &mut [MaybeUninit<f64>],
    out_im1: &mut [MaybeUninit<f64>],
    in_re_lo: &[u64],
    in_re_hi: &[u64],
    in_im_lo: &[u64],
    in_im_hi: &[u64],
) {
    for (out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi) in
        izip!(out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi)
    {
        let out_re = to_signed_to_f128((*in_re_lo, *in_re_hi));
        let out_im = to_signed_to_f128((*in_im_lo, *in_im_hi));

        out_re0.write(out_re.0);
        out_re1.write(out_re.1);
        out_im0.write(out_im.0);
        out_im1.write(out_im.1);
    }
}

pub fn convert_forward_integer(
    out_re0: &mut [MaybeUninit<f64>],
    out_re1: &mut [MaybeUninit<f64>],
    out_im0: &mut [MaybeUninit<f64>],
    out_im1: &mut [MaybeUninit<f64>],
    in_re_lo: &[u64],
    in_re_hi: &[u64],
    in_im_lo: &[u64],
    in_im_hi: &[u64],
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "nightly-avx512")]
    if is_x86_feature_detected!("avx512f") & is_x86_feature_detected!("avx512dq") {
        return unsafe {
            convert_forward_integer_avx512(
                out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi,
            )
        };
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if is_x86_feature_detected!("avx2") & is_x86_feature_detected!("fma") {
        return unsafe {
            convert_forward_integer_avx2(
                out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi,
            )
        };
    }

    convert_forward_integer_scalar(
        out_re0, out_re1, out_im0, out_im1, in_re_lo, in_re_hi, in_im_lo, in_im_hi,
    )
}

pub fn convert_add_backward_torus_scalar(
    out_re_lo: &mut [MaybeUninit<u64>],
    out_re_hi: &mut [MaybeUninit<u64>],
    out_im_lo: &mut [MaybeUninit<u64>],
    out_im_hi: &mut [MaybeUninit<u64>],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    unsafe {
        let norm = 1.0 / in_re0.len() as f64;
        for (out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1) in
            izip!(out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1)
        {
            let in_re = f128(*in_re0 * norm, *in_re1 * norm);
            let in_im = f128(*in_im0 * norm, *in_im1 * norm);
            let out_re = wrapping_add(
                (out_re_lo.assume_init(), out_re_hi.assume_init()),
                from_torus_f128(in_re),
            );
            let out_im = wrapping_add(
                (out_im_lo.assume_init(), out_im_hi.assume_init()),
                from_torus_f128(in_im),
            );
            out_re_lo.write(out_re.0);
            out_re_hi.write(out_re.1);
            out_im_lo.write(out_im.0);
            out_im_hi.write(out_im.1);
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2,fma")]
pub unsafe fn convert_add_backward_torus_avx2(
    out_re_lo: &mut [MaybeUninit<u64>],
    out_re_hi: &mut [MaybeUninit<u64>],
    out_im_lo: &mut [MaybeUninit<u64>],
    out_im_hi: &mut [MaybeUninit<u64>],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    unsafe {
        let norm = _mm256_set1_pd(1.0 / in_re0.len() as f64);

        let out_re_lo = as_arrays_mut::<4, _>(out_re_lo).0;
        let out_re_hi = as_arrays_mut::<4, _>(out_re_hi).0;
        let out_im_lo = as_arrays_mut::<4, _>(out_im_lo).0;
        let out_im_hi = as_arrays_mut::<4, _>(out_im_hi).0;

        let in_re0 = as_arrays::<4, _>(in_re0).0;
        let in_re1 = as_arrays::<4, _>(in_re1).0;
        let in_im0 = as_arrays::<4, _>(in_im0).0;
        let in_im1 = as_arrays::<4, _>(in_im1).0;

        for (out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1) in
            izip!(out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1)
        {
            let in_re = (
                _mm256_mul_pd(transmute(*in_re0), norm),
                _mm256_mul_pd(transmute(*in_re1), norm),
            );
            let in_im = (
                _mm256_mul_pd(transmute(*in_im0), norm),
                _mm256_mul_pd(transmute(*in_im1), norm),
            );
            let out_re = wrapping_add_avx2(
                (transmute(*out_re_lo), transmute(*out_re_hi)),
                from_torus_f128_avx2(in_re),
            );
            let out_im = wrapping_add_avx2(
                (transmute(*out_im_lo), transmute(*out_im_hi)),
                from_torus_f128_avx2(in_im),
            );
            *out_re_lo = transmute(out_re.0);
            *out_re_hi = transmute(out_re.1);
            *out_im_lo = transmute(out_im.0);
            *out_im_hi = transmute(out_im.1);
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512f,avx512dq")]
pub unsafe fn convert_add_backward_torus_avx512(
    out_re_lo: &mut [MaybeUninit<u64>],
    out_re_hi: &mut [MaybeUninit<u64>],
    out_im_lo: &mut [MaybeUninit<u64>],
    out_im_hi: &mut [MaybeUninit<u64>],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    unsafe {
        let norm = _mm512_set1_pd(1.0 / in_re0.len() as f64);

        let out_re_lo = as_arrays_mut::<8, _>(out_re_lo).0;
        let out_re_hi = as_arrays_mut::<8, _>(out_re_hi).0;
        let out_im_lo = as_arrays_mut::<8, _>(out_im_lo).0;
        let out_im_hi = as_arrays_mut::<8, _>(out_im_hi).0;

        let in_re0 = as_arrays::<8, _>(in_re0).0;
        let in_re1 = as_arrays::<8, _>(in_re1).0;
        let in_im0 = as_arrays::<8, _>(in_im0).0;
        let in_im1 = as_arrays::<8, _>(in_im1).0;

        for (out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1) in
            izip!(out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1)
        {
            let in_re = (
                _mm512_mul_pd(transmute(*in_re0), norm),
                _mm512_mul_pd(transmute(*in_re1), norm),
            );
            let in_im = (
                _mm512_mul_pd(transmute(*in_im0), norm),
                _mm512_mul_pd(transmute(*in_im1), norm),
            );
            let out_re = wrapping_add_avx512(
                (transmute(*out_re_lo), transmute(*out_re_hi)),
                from_torus_f128_avx512(in_re),
            );
            let out_im = wrapping_add_avx512(
                (transmute(*out_im_lo), transmute(*out_im_hi)),
                from_torus_f128_avx512(in_im),
            );
            *out_re_lo = transmute(out_re.0);
            *out_re_hi = transmute(out_re.1);
            *out_im_lo = transmute(out_im.0);
            *out_im_hi = transmute(out_im.1);
        }
    }
}

pub fn convert_add_backward_torus(
    out_re_lo: &mut [MaybeUninit<u64>],
    out_re_hi: &mut [MaybeUninit<u64>],
    out_im_lo: &mut [MaybeUninit<u64>],
    out_im_hi: &mut [MaybeUninit<u64>],
    in_re0: &[f64],
    in_re1: &[f64],
    in_im0: &[f64],
    in_im1: &[f64],
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "nightly-avx512")]
    if is_x86_feature_detected!("avx512f") & is_x86_feature_detected!("avx512dq") {
        return unsafe {
            convert_add_backward_torus_avx512(
                out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1,
            )
        };
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if is_x86_feature_detected!("avx2") & is_x86_feature_detected!("fma") {
        return unsafe {
            convert_add_backward_torus_avx2(
                out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1,
            )
        };
    }
    convert_add_backward_torus_scalar(
        out_re_lo, out_re_hi, out_im_lo, out_im_hi, in_re0, in_re1, in_im0, in_im1,
    )
}

impl<'a> Fft128View<'a> {
    pub fn forward_as_integer_split(
        self,
        fourier_re0: &mut [MaybeUninit<f64>],
        fourier_re1: &mut [MaybeUninit<f64>],
        fourier_im0: &mut [MaybeUninit<f64>],
        fourier_im1: &mut [MaybeUninit<f64>],
        standard_lo: &[u64],
        standard_hi: &[u64],
    ) {
        unsafe {
            self.forward_with_conv_split(
                fourier_re0,
                fourier_re1,
                fourier_im0,
                fourier_im1,
                standard_lo,
                standard_hi,
                convert_forward_integer,
            )
        }
    }

    /// Perform an inverse negacyclic real FFT of `fourier` and adds the result to `standard`,
    /// viewed as torus elements.
    ///
    /// # Note
    ///
    /// this function leaves all the elements of `out_re` and `out_im` in an initialized state.
    ///
    /// # Panics
    ///
    /// See [`Self::forward_as_torus`]
    pub fn add_backward_as_torus_split(
        self,
        standard_lo: &mut [u64],
        standard_hi: &mut [u64],
        fourier_re0: &[f64],
        fourier_re1: &[f64],
        fourier_im0: &[f64],
        fourier_im1: &[f64],
        stack: DynStack<'_>,
    ) {
        // SAFETY: `convert_add_backward_torus` initializes the output slices that are passed to it
        unsafe {
            self.backward_with_conv_split(
                as_mut_uninit(standard_lo),
                as_mut_uninit(standard_hi),
                fourier_re0,
                fourier_re1,
                fourier_im0,
                fourier_im1,
                convert_add_backward_torus,
                stack,
            )
        }
    }

    unsafe fn forward_with_conv_split(
        self,
        fourier_re0: &mut [MaybeUninit<f64>],
        fourier_re1: &mut [MaybeUninit<f64>],
        fourier_im0: &mut [MaybeUninit<f64>],
        fourier_im1: &mut [MaybeUninit<f64>],
        standard_lo: &[u64],
        standard_hi: &[u64],
        conv_fn: impl Fn(
            &mut [MaybeUninit<f64>],
            &mut [MaybeUninit<f64>],
            &mut [MaybeUninit<f64>],
            &mut [MaybeUninit<f64>],
            &[u64],
            &[u64],
            &[u64],
            &[u64],
        ),
    ) {
        let n = standard_lo.len();
        debug_assert_eq!(n, 2 * fourier_re0.len());
        debug_assert_eq!(n, 2 * fourier_re1.len());
        debug_assert_eq!(n, 2 * fourier_im0.len());
        debug_assert_eq!(n, 2 * fourier_im1.len());

        let (standard_re_lo, standard_im_lo) = standard_lo.split_at(n / 2);
        let (standard_re_hi, standard_im_hi) = standard_hi.split_at(n / 2);
        conv_fn(
            fourier_re0,
            fourier_re1,
            fourier_im0,
            fourier_im1,
            standard_re_lo,
            standard_re_hi,
            standard_im_lo,
            standard_im_hi,
        );
        let fourier_re0 = assume_init_mut(fourier_re0);
        let fourier_re1 = assume_init_mut(fourier_re1);
        let fourier_im0 = assume_init_mut(fourier_im0);
        let fourier_im1 = assume_init_mut(fourier_im1);
        self.plan
            .fwd(fourier_re0, fourier_re1, fourier_im0, fourier_im1);
    }

    /// # Safety
    ///
    /// `conv_fn` must initialize the entirety of the mutable slices that it receives.
    unsafe fn backward_with_conv_split(
        self,
        standard_lo: &mut [MaybeUninit<u64>],
        standard_hi: &mut [MaybeUninit<u64>],
        fourier_re0: &[f64],
        fourier_re1: &[f64],
        fourier_im0: &[f64],
        fourier_im1: &[f64],
        conv_fn: impl Fn(
            &mut [MaybeUninit<u64>],
            &mut [MaybeUninit<u64>],
            &mut [MaybeUninit<u64>],
            &mut [MaybeUninit<u64>],
            &[f64],
            &[f64],
            &[f64],
            &[f64],
        ),
        stack: DynStack<'_>,
    ) {
        let n = standard_lo.len();
        debug_assert_eq!(n, 2 * fourier_re0.len());
        debug_assert_eq!(n, 2 * fourier_re1.len());
        debug_assert_eq!(n, 2 * fourier_im0.len());
        debug_assert_eq!(n, 2 * fourier_im1.len());

        let (mut tmp_re0, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_re0.iter().copied());
        let (mut tmp_re1, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_re1.iter().copied());
        let (mut tmp_im0, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_im0.iter().copied());
        let (mut tmp_im1, _) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier_im1.iter().copied());

        self.plan
            .inv(&mut tmp_re0, &mut tmp_re1, &mut tmp_im0, &mut tmp_im1);

        let (standard_re_lo, standard_im_lo) = standard_lo.split_at_mut(n / 2);
        let (standard_re_hi, standard_im_hi) = standard_hi.split_at_mut(n / 2);
        conv_fn(
            standard_re_lo,
            standard_re_hi,
            standard_im_lo,
            standard_im_hi,
            &tmp_re0,
            &tmp_re1,
            &tmp_im0,
            &tmp_im1,
        );
    }
}
