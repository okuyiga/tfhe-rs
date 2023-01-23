//! Module with primitives pertaining to [`SeededLweCiphertext`] decompression.

use crate::core_crypto::algorithms::misc::*;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Convenience function to share the core logic of the decompression algorithm for
/// [`SeededLweCiphertext`] between all functions needing it.
pub fn decompress_seeded_lwe_ciphertext_with_existing_generator<
    Scalar,
    OutputCont,
    Gen,
    const Q: u128,
>(
    output_lwe: &mut LweCiphertext<OutputCont, Q>,
    input_seeded_lwe: &SeededLweCiphertext<Scalar, Q>,
    generator: &mut RandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let (mut output_mask, output_body) = output_lwe.get_mut_mask_and_body();

    // generate a uniformly random mask
    generator.fill_slice_with_random_uniform(output_mask.as_mut());
    *output_body.0 = *input_seeded_lwe.get_body().0
}

/// Decompress a [`SeededLweCiphertext`], without consuming it, into a standard
/// [`LweCiphertext`].
pub fn decompress_seeded_lwe_ciphertext<Scalar, OutputCont, Gen, const Q: u128>(
    output_lwe: &mut LweCiphertext<OutputCont, Q>,
    input_seeded_lwe: &SeededLweCiphertext<Scalar, Q>,
) where
    Scalar: UnsignedTorus,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        is_native_modulus::<Scalar, Q>(),
        "This operation only supports native moduli"
    );
    let mut generator = RandomGenerator::<Gen>::new(input_seeded_lwe.compression_seed().seed);
    decompress_seeded_lwe_ciphertext_with_existing_generator::<_, _, Gen, Q>(
        output_lwe,
        input_seeded_lwe,
        &mut generator,
    )
}
