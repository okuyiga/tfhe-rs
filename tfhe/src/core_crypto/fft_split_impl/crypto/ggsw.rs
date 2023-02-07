use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::traits::container::Split;
use crate::core_crypto::commons::traits::contiguous_entity_container::{
    ContiguousEntityContainer, ContiguousEntityContainerMut,
};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_128_impl::crypto::ggsw::{
    update_with_fmadd, FourierGgswCiphertextView,
};
use crate::core_crypto::fft_128_impl::math::fft::Fft128View;
use crate::core_crypto::fft_impl::assume_init_mut;
use crate::core_crypto::fft_split_impl::as_arrays_mut;
use crate::core_crypto::fft_split_impl::math::fft::{wrapping_add, wrapping_sub};
use crate::core_crypto::prelude::SignedDecomposer;
use aligned_vec::CACHELINE_ALIGN;
use core::mem::{transmute, MaybeUninit};
use dyn_stack::{DynStack, ReborrowMut};

#[cfg_attr(__profiling, inline(never))]
pub fn add_external_product_assign_split(
    mut out_lo: GlweCiphertextMutView<'_, u64>,
    mut out_hi: GlweCiphertextMutView<'_, u64>,
    ggsw: FourierGgswCiphertextView<'_>,
    glwe_lo: GlweCiphertext<&[u64]>,
    glwe_hi: GlweCiphertext<&[u64]>,
    fft: Fft128View<'_>,
    stack: DynStack<'_>,
) {
    // we check that the polynomial sizes match
    debug_assert_eq!(ggsw.polynomial_size(), glwe_lo.polynomial_size());
    debug_assert_eq!(ggsw.polynomial_size(), glwe_hi.polynomial_size());
    debug_assert_eq!(ggsw.polynomial_size(), out_lo.polynomial_size());
    debug_assert_eq!(ggsw.polynomial_size(), out_hi.polynomial_size());
    // we check that the glwe sizes match
    debug_assert_eq!(ggsw.glwe_size(), glwe_lo.glwe_size());
    debug_assert_eq!(ggsw.glwe_size(), glwe_hi.glwe_size());
    debug_assert_eq!(ggsw.glwe_size(), out_lo.glwe_size());
    debug_assert_eq!(ggsw.glwe_size(), out_hi.glwe_size());

    let align = CACHELINE_ALIGN;
    let poly_size = ggsw.polynomial_size().0;
    let glwe_size = ggsw.glwe_size().0;

    // we round the input mask and body
    let decomposer = SignedDecomposer::<u128>::new(
        ggsw.decomposition_base_log(),
        ggsw.decomposition_level_count(),
    );

    let (mut output_fft_buffer_re0, stack) =
        stack.make_aligned_uninit::<f64>(poly_size / 2 * ggsw.glwe_size().0, align);
    let (mut output_fft_buffer_re1, stack) =
        stack.make_aligned_uninit::<f64>(poly_size / 2 * ggsw.glwe_size().0, align);
    let (mut output_fft_buffer_im0, stack) =
        stack.make_aligned_uninit::<f64>(poly_size / 2 * ggsw.glwe_size().0, align);
    let (mut output_fft_buffer_im1, mut substack0) =
        stack.make_aligned_uninit::<f64>(poly_size / 2 * ggsw.glwe_size().0, align);

    // output_fft_buffer is initially uninitialized, considered to be implicitly zero, to avoid
    // the cost of filling it up with zeros. `is_output_uninit` is set to `false` once
    // it has been fully initialized for the first time.
    let output_fft_buffer_re0 = &mut *output_fft_buffer_re0;
    let output_fft_buffer_re1 = &mut *output_fft_buffer_re1;
    let output_fft_buffer_im0 = &mut *output_fft_buffer_im0;
    let output_fft_buffer_im1 = &mut *output_fft_buffer_im1;
    let mut is_output_uninit = true;

    {
        // ------------------------------------------------------ EXTERNAL PRODUCT IN FOURIER DOMAIN
        // In this section, we perform the external product in the fourier domain, and accumulate
        // the result in the output_fft_buffer variable.
        let (mut decomposition_states_lo, stack) = substack0
            .rb_mut()
            .make_aligned_uninit::<u64>(poly_size * glwe_size, align);
        let (mut decomposition_states_hi, mut substack1) =
            stack.make_aligned_uninit::<u64>(poly_size * glwe_size, align);

        let shift = 128 - decomposer.base_log * decomposer.level_count;

        for (out_lo, out_hi, in_lo, in_hi) in izip!(
            &mut *decomposition_states_lo,
            &mut *decomposition_states_hi,
            glwe_lo.as_ref(),
            glwe_hi.as_ref(),
        ) {
            let input = (*in_lo as u128) | ((*in_hi as u128) << 64);
            let value = decomposer.closest_representable(input) >> shift;
            out_lo.write(value as u64);
            out_hi.write((value >> 64) as u64);
        }
        let decomposition_states_lo = unsafe { assume_init_mut(&mut decomposition_states_lo) };
        let decomposition_states_hi = unsafe { assume_init_mut(&mut decomposition_states_hi) };
        let mut current_level = decomposer.level_count;
        let mod_b_mask = (1u128 << decomposer.base_log) - 1;
        let mod_b_mask_lo = mod_b_mask as u64;
        let mod_b_mask_hi = (mod_b_mask >> 64) as u64;

        // We loop through the levels (we reverse to match the order of the decomposition iterator.)
        for ggsw_decomp_matrix in ggsw.into_levels().rev() {
            // We retrieve the decomposition of this level.
            assert_ne!(current_level, 0);
            let glwe_level = DecompositionLevel(current_level);
            current_level -= 1;
            let (mut glwe_decomp_term_lo, stack) = substack1
                .rb_mut()
                .make_aligned_uninit::<u64>(poly_size * glwe_size, align);
            let (mut glwe_decomp_term_hi, mut substack2) =
                stack.make_aligned_uninit::<u64>(poly_size * glwe_size, align);

            let base_log = decomposer.base_log;

            collect_next_term_split(
                &mut glwe_decomp_term_lo,
                &mut glwe_decomp_term_hi,
                decomposition_states_lo,
                decomposition_states_hi,
                mod_b_mask_lo,
                mod_b_mask_hi,
                base_log,
            );

            let glwe_decomp_term_lo = unsafe { assume_init_mut(&mut glwe_decomp_term_lo) };
            let glwe_decomp_term_hi = unsafe { assume_init_mut(&mut glwe_decomp_term_hi) };

            let glwe_decomp_term_lo =
                GlweCiphertextView::from_container(&*glwe_decomp_term_lo, ggsw.polynomial_size());
            let glwe_decomp_term_hi =
                GlweCiphertextView::from_container(&*glwe_decomp_term_hi, ggsw.polynomial_size());
            debug_assert_eq!(ggsw_decomp_matrix.decomposition_level(), glwe_level);

            // For each level we have to add the result of the vector-matrix product between the
            // decomposition of the glwe, and the ggsw level matrix to the output. To do so, we
            // iteratively add to the output, the product between every line of the matrix, and
            // the corresponding (scalar) polynomial in the glwe decomposition:
            //
            //                ggsw_mat                        ggsw_mat
            //   glwe_dec   | - - - - | <        glwe_dec   | - - - - |
            //  | - - - | x | - - - - |         | - - - | x | - - - - | <
            //    ^         | - - - - |             ^       | - - - - |
            //
            //        t = 1                           t = 2                     ...

            for (ggsw_row, glwe_poly_lo, glwe_poly_hi) in izip!(
                ggsw_decomp_matrix.into_rows(),
                glwe_decomp_term_lo.as_polynomial_list().iter(),
                glwe_decomp_term_hi.as_polynomial_list().iter(),
            ) {
                let len = poly_size / 2;
                let stack = substack2.rb_mut();
                let (mut fourier_re0, stack) = stack.make_aligned_uninit::<f64>(len, align);
                let (mut fourier_re1, stack) = stack.make_aligned_uninit::<f64>(len, align);
                let (mut fourier_im0, stack) = stack.make_aligned_uninit::<f64>(len, align);
                let (mut fourier_im1, _) = stack.make_aligned_uninit::<f64>(len, align);
                // We perform the forward fft transform for the glwe polynomial
                fft.forward_as_integer_split(
                    &mut fourier_re0,
                    &mut fourier_re1,
                    &mut fourier_im0,
                    &mut fourier_im1,
                    glwe_poly_lo.as_ref(),
                    glwe_poly_hi.as_ref(),
                );
                // Now we loop through the polynomials of the output, and add the
                // corresponding product of polynomials.

                // SAFETY: see comment above definition of `output_fft_buffer`
                unsafe {
                    update_with_fmadd(
                        output_fft_buffer_re0,
                        output_fft_buffer_re1,
                        output_fft_buffer_im0,
                        output_fft_buffer_im1,
                        ggsw_row,
                        &*assume_init_mut(&mut fourier_re0),
                        &*assume_init_mut(&mut fourier_re1),
                        &*assume_init_mut(&mut fourier_im0),
                        &*assume_init_mut(&mut fourier_im1),
                        is_output_uninit,
                        poly_size,
                    )
                };

                // we initialized `output_fft_buffer, so we can set this to false
                is_output_uninit = false;
            }
        }
    }

    // --------------------------------------------  TRANSFORMATION OF RESULT TO STANDARD DOMAIN
    // In this section, we bring the result from the fourier domain, back to the standard
    // domain, and add it to the output.
    //
    // We iterate over the polynomials in the output.
    if !is_output_uninit {
        // SAFETY: output_fft_buffer is initialized, since `is_output_uninit` is false
        let output_fft_buffer_re0 = &*unsafe { assume_init_mut(output_fft_buffer_re0) };
        let output_fft_buffer_re1 = &*unsafe { assume_init_mut(output_fft_buffer_re1) };
        let output_fft_buffer_im0 = &*unsafe { assume_init_mut(output_fft_buffer_im0) };
        let output_fft_buffer_im1 = &*unsafe { assume_init_mut(output_fft_buffer_im1) };

        for (mut out_lo, mut out_hi, fourier_re0, fourier_re1, fourier_im0, fourier_im1) in izip!(
            out_lo.as_mut_polynomial_list().iter_mut(),
            out_hi.as_mut_polynomial_list().iter_mut(),
            output_fft_buffer_re0.into_chunks(poly_size / 2),
            output_fft_buffer_re1.into_chunks(poly_size / 2),
            output_fft_buffer_im0.into_chunks(poly_size / 2),
            output_fft_buffer_im1.into_chunks(poly_size / 2),
        ) {
            fft.add_backward_as_torus_split(
                out_lo.as_mut(),
                out_hi.as_mut(),
                fourier_re0,
                fourier_re1,
                fourier_im0,
                fourier_im1,
                substack0.rb_mut(),
            );
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg(feature = "nightly-avx512")]
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn collect_next_term_split_avx512(
    glwe_decomp_term_lo: &mut [MaybeUninit<u64>],
    glwe_decomp_term_hi: &mut [MaybeUninit<u64>],
    decomposition_states_lo: &mut [u64],
    decomposition_states_hi: &mut [u64],
    mod_b_mask_lo: u64,
    mod_b_mask_hi: u64,
    base_log: usize,
) {
    use crate::core_crypto::fft_split_impl::math::fft::{
        _mm512_movm_epi64, wrapping_add_avx512, wrapping_sub_avx512,
    };
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    assert!(base_log < 128);
    assert!(base_log > 0);

    let glwe_decomp_term_lo = as_arrays_mut::<8, _>(glwe_decomp_term_lo).0;
    let glwe_decomp_term_hi = as_arrays_mut::<8, _>(glwe_decomp_term_hi).0;
    let decomposition_states_lo = as_arrays_mut::<8, _>(decomposition_states_lo).0;
    let decomposition_states_hi = as_arrays_mut::<8, _>(decomposition_states_hi).0;
    let shift = base_log - 1;

    let mod_b_mask_lo = _mm512_set1_epi64(mod_b_mask_lo as i64);
    let mod_b_mask_hi = _mm512_set1_epi64(mod_b_mask_hi as i64);

    let shift_minus_64 = _mm512_set1_epi64(shift as u64 as i64 - 64);
    let _64_minus_shift = _mm512_set1_epi64(64 - shift as u64 as i64);
    let shift = _mm512_set1_epi64(shift as u64 as i64);
    let base_log_minus_64 = _mm512_set1_epi64(base_log as u64 as i64 - 64);
    let _64_minus_base_log = _mm512_set1_epi64(64 - base_log as u64 as i64);
    let base_log = _mm512_set1_epi64(base_log as u64 as i64);

    for (out_lo, out_hi, state_lo, state_hi) in izip!(
        glwe_decomp_term_lo,
        glwe_decomp_term_hi,
        decomposition_states_lo,
        decomposition_states_hi,
    ) {
        let mut vstate_lo: __m512i = transmute(*state_lo);
        let mut vstate_hi: __m512i = transmute(*state_hi);

        let res_lo = _mm512_and_si512(vstate_lo, mod_b_mask_lo);
        let res_hi = _mm512_and_si512(vstate_hi, mod_b_mask_hi);

        vstate_lo = _mm512_or_si512(
            _mm512_srlv_epi64(vstate_hi, base_log_minus_64),
            _mm512_or_si512(
                _mm512_sllv_epi64(vstate_hi, _64_minus_base_log),
                _mm512_srlv_epi64(vstate_lo, base_log),
            ),
        );
        vstate_hi = _mm512_srlv_epi64(vstate_hi, base_log);

        let res_sub1_lo = _mm512_sub_epi64(res_lo, _mm512_set1_epi64(1));
        let overflow = _mm512_movm_epi64(_mm512_cmpeq_epi64_mask(res_lo, _mm512_setzero_si512()));
        let res_sub1_hi = _mm512_add_epi64(res_hi, overflow);

        let mut carry_lo = _mm512_and_si512(_mm512_or_si512(res_sub1_lo, vstate_lo), res_lo);
        let mut carry_hi = _mm512_and_si512(_mm512_or_si512(res_sub1_hi, vstate_hi), res_hi);

        carry_lo = _mm512_or_si512(
            _mm512_srlv_epi64(carry_hi, shift_minus_64),
            _mm512_or_si512(
                _mm512_srlv_epi64(carry_lo, shift),
                _mm512_srlv_epi64(carry_hi, _64_minus_shift),
            ),
        );
        carry_hi = _mm512_srlv_epi64(carry_hi, shift);

        (vstate_lo, vstate_hi) = wrapping_add_avx512((vstate_lo, vstate_hi), (carry_lo, carry_hi));
        *state_lo = transmute(vstate_lo);
        *state_hi = transmute(vstate_hi);

        carry_hi = _mm512_or_si512(
            _mm512_or_si512(
                _mm512_sllv_epi64(carry_hi, base_log),
                _mm512_srlv_epi64(carry_lo, _64_minus_base_log),
            ),
            _mm512_sllv_epi64(carry_lo, base_log_minus_64),
        );
        carry_lo = _mm512_sllv_epi64(carry_lo, base_log);

        let (res_lo, res_hi) = wrapping_sub_avx512((res_lo, res_hi), (carry_lo, carry_hi));

        *out_lo = transmute(res_lo);
        *out_hi = transmute(res_hi);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn collect_next_term_split_avx2(
    glwe_decomp_term_lo: &mut [MaybeUninit<u64>],
    glwe_decomp_term_hi: &mut [MaybeUninit<u64>],
    decomposition_states_lo: &mut [u64],
    decomposition_states_hi: &mut [u64],
    mod_b_mask_lo: u64,
    mod_b_mask_hi: u64,
    base_log: usize,
) {
    use crate::core_crypto::fft_split_impl::math::fft::{wrapping_add_avx2, wrapping_sub_avx2};
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    assert!(base_log < 128);
    assert!(base_log > 0);

    let glwe_decomp_term_lo = as_arrays_mut::<4, _>(glwe_decomp_term_lo).0;
    let glwe_decomp_term_hi = as_arrays_mut::<4, _>(glwe_decomp_term_hi).0;
    let decomposition_states_lo = as_arrays_mut::<4, _>(decomposition_states_lo).0;
    let decomposition_states_hi = as_arrays_mut::<4, _>(decomposition_states_hi).0;
    let shift = base_log - 1;

    let mod_b_mask_lo = _mm256_set1_epi64x(mod_b_mask_lo as i64);
    let mod_b_mask_hi = _mm256_set1_epi64x(mod_b_mask_hi as i64);

    let shift_minus_64 = _mm256_set1_epi64x(shift as u64 as i64 - 64);
    let _64_minus_shift = _mm256_set1_epi64x(64 - shift as u64 as i64);
    let shift = _mm256_set1_epi64x(shift as u64 as i64);
    let base_log_minus_64 = _mm256_set1_epi64x(base_log as u64 as i64 - 64);
    let _64_minus_base_log = _mm256_set1_epi64x(64 - base_log as u64 as i64);
    let base_log = _mm256_set1_epi64x(base_log as u64 as i64);

    for (out_lo, out_hi, state_lo, state_hi) in izip!(
        glwe_decomp_term_lo,
        glwe_decomp_term_hi,
        decomposition_states_lo,
        decomposition_states_hi,
    ) {
        let mut vstate_lo: __m256i = transmute(*state_lo);
        let mut vstate_hi: __m256i = transmute(*state_hi);

        let res_lo = _mm256_and_si256(vstate_lo, mod_b_mask_lo);
        let res_hi = _mm256_and_si256(vstate_hi, mod_b_mask_hi);

        vstate_lo = _mm256_or_si256(
            _mm256_srlv_epi64(vstate_hi, base_log_minus_64),
            _mm256_or_si256(
                _mm256_sllv_epi64(vstate_hi, _64_minus_base_log),
                _mm256_srlv_epi64(vstate_lo, base_log),
            ),
        );
        vstate_hi = _mm256_srlv_epi64(vstate_hi, base_log);

        let res_sub1_lo = _mm256_sub_epi64(res_lo, _mm256_set1_epi64x(1));
        let overflow = _mm256_cmpeq_epi64(res_lo, _mm256_setzero_si256());
        let res_sub1_hi = _mm256_add_epi64(res_hi, overflow);

        let mut carry_lo = _mm256_and_si256(_mm256_or_si256(res_sub1_lo, vstate_lo), res_lo);
        let mut carry_hi = _mm256_and_si256(_mm256_or_si256(res_sub1_hi, vstate_hi), res_hi);

        carry_lo = _mm256_or_si256(
            _mm256_srlv_epi64(carry_hi, shift_minus_64),
            _mm256_or_si256(
                _mm256_srlv_epi64(carry_lo, shift),
                _mm256_srlv_epi64(carry_hi, _64_minus_shift),
            ),
        );
        carry_hi = _mm256_srlv_epi64(carry_hi, shift);

        (vstate_lo, vstate_hi) = wrapping_add_avx2((vstate_lo, vstate_hi), (carry_lo, carry_hi));
        *state_lo = transmute(vstate_lo);
        *state_hi = transmute(vstate_hi);

        carry_hi = _mm256_or_si256(
            _mm256_or_si256(
                _mm256_sllv_epi64(carry_hi, base_log),
                _mm256_srlv_epi64(carry_lo, _64_minus_base_log),
            ),
            _mm256_sllv_epi64(carry_lo, base_log_minus_64),
        );
        carry_lo = _mm256_sllv_epi64(carry_lo, base_log);

        let (res_lo, res_hi) = wrapping_sub_avx2((res_lo, res_hi), (carry_lo, carry_hi));

        *out_lo = transmute(res_lo);
        *out_hi = transmute(res_hi);
    }
}

fn collect_next_term_split_scalar(
    glwe_decomp_term_lo: &mut [MaybeUninit<u64>],
    glwe_decomp_term_hi: &mut [MaybeUninit<u64>],
    decomposition_states_lo: &mut [u64],
    decomposition_states_hi: &mut [u64],
    mod_b_mask_lo: u64,
    mod_b_mask_hi: u64,
    base_log: usize,
) {
    assert!(base_log < 128);
    for (out_lo, out_hi, state_lo, state_hi) in izip!(
        glwe_decomp_term_lo,
        glwe_decomp_term_hi,
        decomposition_states_lo,
        decomposition_states_hi,
    ) {
        // decompose one level
        let res_lo = *state_lo & mod_b_mask_lo;
        let res_hi = *state_hi & mod_b_mask_hi;
        if base_log < 64 {
            *state_lo = (*state_hi << (64 - base_log)) | (*state_lo >> base_log);
            *state_hi = *state_hi >> base_log;
        } else {
            *state_lo = *state_hi >> (base_log - 64);
            *state_hi = 0;
        }
        let (res_sub1_lo, overflow) = res_lo.overflowing_sub(1);
        let res_sub1_hi = res_hi.wrapping_sub(overflow as u64);

        let mut carry_lo = (res_sub1_lo | *state_lo) & res_lo;
        let mut carry_hi = (res_sub1_hi | *state_hi) & res_hi;

        let shift = base_log - 1;
        if shift < 64 {
            carry_lo = (carry_hi << (64 - shift)) | (carry_lo >> shift);
            carry_hi = carry_hi >> shift;
        } else {
            carry_lo = carry_hi >> (shift - 64);
            carry_hi = 0;
        }
        (*state_lo, *state_hi) = wrapping_add((*state_lo, *state_hi), (carry_lo, carry_hi));

        if base_log < 64 {
            carry_hi = (carry_hi << base_log) | (carry_lo >> (64 - base_log));
            carry_lo = carry_lo << base_log;
        } else {
            carry_hi = carry_lo << (base_log - 64);
            carry_lo = 0;
        }
        let (res_lo, res_hi) = wrapping_sub((res_lo, res_hi), (carry_lo, carry_hi));
        out_lo.write(res_lo);
        out_hi.write(res_hi);
    }
}

fn collect_next_term_split(
    glwe_decomp_term_lo: &mut [MaybeUninit<u64>],
    glwe_decomp_term_hi: &mut [MaybeUninit<u64>],
    decomposition_states_lo: &mut [u64],
    decomposition_states_hi: &mut [u64],
    mod_b_mask_lo: u64,
    mod_b_mask_hi: u64,
    base_log: usize,
) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[cfg(feature = "nightly-avx512")]
    if is_x86_feature_detected!("avx512f") & is_x86_feature_detected!("avx512dq") {
        return unsafe {
            collect_next_term_split_avx512(
                glwe_decomp_term_lo,
                glwe_decomp_term_hi,
                decomposition_states_lo,
                decomposition_states_hi,
                mod_b_mask_lo,
                mod_b_mask_hi,
                base_log,
            )
        };
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if is_x86_feature_detected!("avx2") {
        return unsafe {
            collect_next_term_split_avx2(
                glwe_decomp_term_lo,
                glwe_decomp_term_hi,
                decomposition_states_lo,
                decomposition_states_hi,
                mod_b_mask_lo,
                mod_b_mask_hi,
                base_log,
            )
        };
    }

    collect_next_term_split_scalar(
        glwe_decomp_term_lo,
        glwe_decomp_term_hi,
        decomposition_states_lo,
        decomposition_states_hi,
        mod_b_mask_lo,
        mod_b_mask_hi,
        base_log,
    );
}

/// This cmux mutates both ct1 and ct0. The result is in ct0 after the method was called.
pub fn cmux_split(
    ct0_lo: GlweCiphertextMutView<'_, u64>,
    ct0_hi: GlweCiphertextMutView<'_, u64>,
    mut ct1_lo: GlweCiphertextMutView<'_, u64>,
    mut ct1_hi: GlweCiphertextMutView<'_, u64>,
    ggsw: FourierGgswCiphertextView<'_>,
    fft: Fft128View<'_>,
    stack: DynStack<'_>,
) {
    for (c1_lo, c1_hi, c0_lo, c0_hi) in izip!(
        ct1_lo.as_mut(),
        ct1_hi.as_mut(),
        ct0_lo.as_ref(),
        ct0_hi.as_ref(),
    ) {
        let overflow;
        (*c1_lo, overflow) = c1_lo.overflowing_sub(*c0_lo);
        *c1_hi = c1_hi.wrapping_sub(*c0_hi).wrapping_sub(overflow as u64);
    }

    add_external_product_assign_split(
        ct0_lo,
        ct0_hi,
        ggsw,
        ct1_lo.as_view(),
        ct1_hi.as_view(),
        fft,
        stack,
    );
}
