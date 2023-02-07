use super::super::math::fft::Fft128View;
use super::ggsw::cmux_split;
use crate::core_crypto::algorithms::extract_lwe_sample_from_glwe_ciphertext;
use crate::core_crypto::commons::parameters::{LutCountLog, ModulusSwitchOffset, MonomialDegree};
use crate::core_crypto::commons::traits::ContiguousEntityContainerMut;
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_128_impl::crypto::bootstrap::FourierLweBootstrapKeyView;
use crate::core_crypto::fft_impl::crypto::bootstrap::pbs_modulus_switch;
use crate::core_crypto::fft_split_impl::math::fft::wrapping_neg;
use crate::core_crypto::prelude::Container;
use aligned_vec::CACHELINE_ALIGN;
use dyn_stack::{DynStack, ReborrowMut};

pub fn polynomial_wrapping_monic_monomial_mul_assign_split(
    output_lo: Polynomial<&mut [u64]>,
    output_hi: Polynomial<&mut [u64]>,
    monomial_degree: MonomialDegree,
) {
    let output_lo = output_lo.into_container();
    let output_hi = output_hi.into_container();
    let full_cycles_count = monomial_degree.0 / output_lo.container_len();
    if full_cycles_count % 2 != 0 {
        izip!(&mut *output_lo, &mut *output_hi)
            .for_each(|(lo, hi)| (*lo, *hi) = wrapping_neg((*lo, *hi)));
    }
    let remaining_degree = monomial_degree.0 % output_lo.container_len();
    output_lo.rotate_right(remaining_degree);
    output_hi.rotate_right(remaining_degree);
    izip!(output_lo, output_hi)
        .take(remaining_degree)
        .for_each(|(lo, hi)| (*lo, *hi) = wrapping_neg((*lo, *hi)));
}

pub fn polynomial_wrapping_monic_monomial_div_assign_split(
    output_lo: Polynomial<&mut [u64]>,
    output_hi: Polynomial<&mut [u64]>,
    monomial_degree: MonomialDegree,
) {
    let output_lo = output_lo.into_container();
    let output_hi = output_hi.into_container();
    let full_cycles_count = monomial_degree.0 / output_lo.container_len();
    if full_cycles_count % 2 != 0 {
        izip!(&mut *output_lo, &mut *output_hi)
            .for_each(|(lo, hi)| (*lo, *hi) = wrapping_neg((*lo, *hi)));
    }
    let remaining_degree = monomial_degree.0 % output_lo.container_len();
    output_lo.rotate_left(remaining_degree);
    output_hi.rotate_left(remaining_degree);
    izip!(output_lo, output_hi)
        .rev()
        .take(remaining_degree)
        .for_each(|(lo, hi)| (*lo, *hi) = wrapping_neg((*lo, *hi)));
}

impl<'a> FourierLweBootstrapKeyView<'a> {
    // CastInto required for PBS modulus switch which returns a usize
    pub fn blind_rotate_assign_split(
        self,
        mut lut_lo: GlweCiphertextMutView<'_, u64>,
        mut lut_hi: GlweCiphertextMutView<'_, u64>,
        lwe: &[u128],
        fft: Fft128View<'_>,
        mut stack: DynStack<'_>,
    ) {
        let (lwe_body, lwe_mask) = lwe.split_last().unwrap();

        let lut_poly_size = lut_lo.polynomial_size();
        let monomial_degree = pbs_modulus_switch(
            *lwe_body,
            lut_poly_size,
            ModulusSwitchOffset(0),
            LutCountLog(0),
        );

        for (poly_lo, poly_hi) in izip!(
            lut_lo.as_mut_polynomial_list().iter_mut(),
            lut_hi.as_mut_polynomial_list().iter_mut(),
        ) {
            polynomial_wrapping_monic_monomial_div_assign_split(
                poly_lo,
                poly_hi,
                MonomialDegree(monomial_degree),
            )
        }

        // We initialize the ct_0 used for the successive cmuxes
        let mut ct0_lo = lut_lo;
        let mut ct0_hi = lut_hi;

        for (lwe_mask_element, bootstrap_key_ggsw) in izip!(lwe_mask.iter(), self.into_ggsw_iter())
        {
            if *lwe_mask_element != 0 {
                let stack = stack.rb_mut();
                // We copy ct_0 to ct_1
                let (mut ct1_lo, stack) =
                    stack.collect_aligned(CACHELINE_ALIGN, ct0_lo.as_ref().iter().copied());
                let (mut ct1_hi, stack) =
                    stack.collect_aligned(CACHELINE_ALIGN, ct0_hi.as_ref().iter().copied());
                let mut ct1_lo =
                    GlweCiphertextMutView::from_container(&mut *ct1_lo, ct0_lo.polynomial_size());
                let mut ct1_hi =
                    GlweCiphertextMutView::from_container(&mut *ct1_hi, ct0_lo.polynomial_size());

                // We rotate ct_1 by performing ct_1 <- ct_1 * X^{a_hat}
                for (poly_lo, poly_hi) in izip!(
                    ct1_lo.as_mut_polynomial_list().iter_mut(),
                    ct1_hi.as_mut_polynomial_list().iter_mut(),
                ) {
                    polynomial_wrapping_monic_monomial_mul_assign_split(
                        poly_lo,
                        poly_hi,
                        MonomialDegree(pbs_modulus_switch(
                            *lwe_mask_element,
                            lut_poly_size,
                            ModulusSwitchOffset(0),
                            LutCountLog(0),
                        )),
                    )
                }

                // ct1 is re-created each loop it can be moved, ct0 is already a view, but
                // as_mut_view is required to keep borrow rules consistent
                cmux_split(
                    ct0_lo.as_mut_view(),
                    ct0_hi.as_mut_view(),
                    ct1_lo,
                    ct1_hi,
                    bootstrap_key_ggsw,
                    fft,
                    stack,
                );
            }
        }
    }

    pub fn bootstrap_u128(
        self,
        lwe_out: &mut [u128],
        lwe_in: &[u128],
        accumulator: GlweCiphertextView<'_, u128>,
        fft: Fft128View<'_>,
        stack: DynStack<'_>,
    ) {
        let align = CACHELINE_ALIGN;

        let (mut local_accumulator_lo, stack) =
            stack.collect_aligned(align, accumulator.as_ref().iter().map(|i| *i as u64));
        let (mut local_accumulator_hi, mut stack) = stack.collect_aligned(
            align,
            accumulator.as_ref().iter().map(|i| (*i >> 64) as u64),
        );

        let mut local_accumulator_lo = GlweCiphertextMutView::from_container(
            &mut *local_accumulator_lo,
            accumulator.polynomial_size(),
        );
        let mut local_accumulator_hi = GlweCiphertextMutView::from_container(
            &mut *local_accumulator_hi,
            accumulator.polynomial_size(),
        );
        self.blind_rotate_assign_split(
            local_accumulator_lo.as_mut_view(),
            local_accumulator_hi.as_mut_view(),
            lwe_in,
            fft,
            stack.rb_mut(),
        );
        let (local_accumulator, _) = stack.collect_aligned(
            align,
            izip!(local_accumulator_lo.as_ref(), local_accumulator_hi.as_ref())
                .map(|(&lo, &hi)| lo as u128 | ((hi as u128) << 64)),
        );
        let local_accumulator =
            GlweCiphertextView::from_container(&*local_accumulator, accumulator.polynomial_size());

        extract_lwe_sample_from_glwe_ciphertext(
            &local_accumulator,
            &mut LweCiphertextMutView::from_container(&mut *lwe_out),
            MonomialDegree(0),
        );
    }
}
