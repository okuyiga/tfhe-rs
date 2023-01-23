use super::*;

fn lwe_encrypt_add_assign_decrypt_custom_mod<Scalar: UnsignedTorus>(params: TestParams<Scalar>) {
    let lwe_dimension = params.lwe_dimension;
    let lwe_modular_std_dev = params.lwe_modular_std_dev;
    let ciphertext_modulus = params.ciphertext_modulus;
    let message_modulus_log = params.message_modulus_log;
    let encoding_with_padding = get_encoding_with_padding(ciphertext_modulus);

    let mut rsc = TestResources::new();

    const NB_TESTS: usize = 10;
    let msg_modulus = Scalar::ONE.shl(message_modulus_log.0);
    let mut msg = msg_modulus;
    let delta: Scalar = (encoding_with_padding / cast_into_u128(msg_modulus)).cast_into();

    while msg != Scalar::ZERO {
        msg = msg.wrapping_sub(Scalar::ONE);
        for _ in 0..NB_TESTS {
            let lwe_sk = allocate_and_generate_new_binary_lwe_secret_key(
                lwe_dimension,
                &mut rsc.secret_random_generator,
            );

            let mut ct = LweCiphertext::new(
                Scalar::ZERO,
                lwe_dimension.to_lwe_size(),
                ciphertext_modulus,
            );

            let plaintext = Plaintext(msg * delta);

            encrypt_lwe_ciphertext(
                &lwe_sk,
                &mut ct,
                plaintext,
                lwe_modular_std_dev,
                &mut rsc.encryption_random_generator,
            );

            assert!(check_content_respects_mod(&ct, ciphertext_modulus));

            let rhs = ct.clone();

            lwe_ciphertext_add_assign(&mut ct, &rhs);

            assert!(check_content_respects_mod(&ct, ciphertext_modulus));

            let decrypted = decrypt_lwe_ciphertext(&lwe_sk, &ct);

            let decoded = round_decode(decrypted.0, delta) % msg_modulus;

            assert_eq!((msg + msg) % msg_modulus, decoded);
        }
    }
}

#[test]
fn lwe_encrypt_add_assign_decrypt_native_mod() {
    lwe_encrypt_add_assign_decrypt_custom_mod(TEST_PARAMS_4_BITS_NATIVE_U64);
}

#[test]
fn lwe_encrypt_add_assign_decrypt_non_native_mod() {
    lwe_encrypt_add_assign_decrypt_custom_mod(TEST_PARAMS_3_BITS_63_U64);
}
