use std::mem::MaybeUninit;

use criterion::{criterion_group, criterion_main, Criterion};
use dyn_stack::DynStack;

fn sqr(x: f64) -> f64 {
    x * x
}

fn criterion_bench(c: &mut Criterion) {
    use tfhe::core_crypto::fft_impl::crypto::bootstrap::{
        bootstrap_scratch, FourierLweBootstrapKey,
    };
    use tfhe::core_crypto::fft_impl::math::fft::Fft;
    use tfhe::core_crypto::prelude::*;

    c.bench_function("pbs", |b| {
        type Scalar = u64;

        let small_lwe_dimension = LweDimension(742);
        let glwe_dimension = GlweDimension(1);
        let polynomial_size = PolynomialSize(2048);
        let lwe_modular_std_dev = StandardDev(sqr(0.000007069849454709433));
        let pbs_base_log = DecompositionBaseLog(23);
        let pbs_level = DecompositionLevelCount(1);

        // Request the best seeder possible, starting with hardware entropy sources and falling back
        // to /dev/random on Unix systems if enabled via cargo features
        let mut boxed_seeder = new_seeder();
        // Get a mutable reference to the seeder as a trait object from the Box returned by
        // new_seeder
        let seeder = boxed_seeder.as_mut();

        // Create a generator which uses a CSPRNG to generate secret keys
        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

        // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
        // noise
        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate an LweSecretKey with binary coefficients
        let small_lwe_sk =
            LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

        // Generate a GlweSecretKey with binary coefficients
        let glwe_sk = GlweSecretKey::<Vec<Scalar>>::generate_new_binary(
            glwe_dimension,
            polynomial_size,
            &mut secret_generator,
        );

        // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
        let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

        // Create the empty bootstrapping key in the Fourier domain
        let fourier_bsk = FourierLweBootstrapKey::new(
            small_lwe_dimension,
            glwe_dimension.to_glwe_size(),
            polynomial_size,
            pbs_base_log,
            pbs_level,
        );

        let fft = Fft::new(polynomial_size);
        let fft = fft.as_view();

        // We don't need the standard bootstrapping key anymore

        // Our 4 bits message space
        let message_modulus: Scalar = 1 << 4;

        // Our input message
        let input_message: Scalar = 3;

        // Delta used to encode 4 bits of message + a bit of padding on Scalar
        let delta: Scalar = (1 << (Scalar::BITS - 1)) / message_modulus;

        // Apply our encoding
        let plaintext = Plaintext(input_message * delta);

        // Allocate a new LweCiphertext and encrypt our plaintext
        let lwe_ciphertext_in: LweCiphertextOwned<Scalar> = allocate_and_encrypt_new_lwe_ciphertext(
            &small_lwe_sk,
            plaintext,
            lwe_modular_std_dev,
            &mut encryption_generator,
        );

        // Now we will use a PBS to compute a multiplication by 2, it is NOT the recommended way of
        // doing this operation in terms of performance as it's much more costly than a
        // multiplication with a cleartext, however it resets the noise in a ciphertext to a
        // nominal level and allows to evaluate arbitrary functions so depending on your use
        // case it can be a better fit.

        // Here we will define a helper function to generate an accumulator for a PBS
        fn generate_accumulator<F>(
            polynomial_size: PolynomialSize,
            glwe_size: GlweSize,
            message_modulus: usize,
            delta: Scalar,
            f: F,
        ) -> GlweCiphertextOwned<Scalar>
        where
            F: Fn(Scalar) -> Scalar,
        {
            // N/(p/2) = size of each block, to correct noise from the input we introduce the notion
            // of box, which manages redundancy to yield a denoised value for several
            // noisy values around a true input value.
            let box_size = polynomial_size.0 / message_modulus;

            // Create the accumulator
            let mut accumulator_scalar: Vec<Scalar> = vec![0; polynomial_size.0];

            // Fill each box with the encoded denoised value
            for i in 0..message_modulus {
                let index = i * box_size;
                accumulator_scalar[index..index + box_size]
                    .iter_mut()
                    .for_each(|a| *a = f(i as Scalar) * delta);
            }

            let half_box_size = box_size / 2;

            // Negate the first half_box_size coefficients to manage negacyclicity and rotate
            for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
                *a_i = (*a_i).wrapping_neg();
            }

            // Rotate the accumulator
            accumulator_scalar.rotate_left(half_box_size);

            let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

            let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
                glwe_size,
                &accumulator_plaintext,
            );

            accumulator
        }

        let f = |x: Scalar| (x * x + x) % 16;
        let accumulator: GlweCiphertextOwned<Scalar> = generate_accumulator(
            polynomial_size,
            glwe_dimension.to_glwe_size(),
            message_modulus as usize,
            delta,
            f,
        );

        // Allocate the LweCiphertext to store the result of the PBS
        let mut pbs_multiplication_ct: LweCiphertext<Vec<Scalar>> =
            LweCiphertext::new(0, big_lwe_sk.lwe_dimension().to_lwe_size());

        let mut buf = vec![
            MaybeUninit::uninit();
            bootstrap_scratch::<Scalar>(
                fourier_bsk.glwe_size(),
                fourier_bsk.polynomial_size(),
                fft
            )
            .unwrap()
            .unaligned_bytes_required()
        ];

        b.iter(|| {
            fourier_bsk.as_view().bootstrap(
                pbs_multiplication_ct.as_mut(),
                lwe_ciphertext_in.as_ref(),
                accumulator.as_view(),
                fft,
                DynStack::new(&mut buf),
            )
        });
    });
}

criterion_group!(benches, criterion_bench);
criterion_main!(benches);
