use crate::core_crypto::algorithms::*;
use crate::core_crypto::entities::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{CiphertextNew, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_scalar_add<const OP_ORDER: u8>(
        &mut self,
        ct: &CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut ct_result = ct.clone();
        self.unchecked_scalar_add_assign(&mut ct_result, scalar)?;
        Ok(ct_result)
    }

    pub(crate) fn unchecked_scalar_add_assign<const OP_ORDER: u8>(
        &mut self,
        ct: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        let delta = (1_u64 << 63) / (ct.message_modulus.0 * ct.carry_modulus.0) as u64;
        let shift_plaintext = u64::from(scalar) * delta;
        let encoded_scalar = Plaintext(shift_plaintext);
        lwe_ciphertext_plaintext_add_assign(&mut ct.ct, encoded_scalar);

        ct.degree = Degree(ct.degree.0 + scalar as usize);
        Ok(())
    }

    pub(crate) fn unchecked_scalar_add_assign_crt<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;
        let shift_plaintext = u64::from(scalar) * delta;
        let encoded_scalar = Plaintext(shift_plaintext);
        lwe_ciphertext_plaintext_add_assign(&mut ct.ct, encoded_scalar);

        ct.degree = Degree(ct.degree.0 + scalar as usize);
        Ok(())
    }

    pub(crate) fn smart_scalar_add<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut ct_result = ct.clone();
        self.smart_scalar_add_assign(server_key, &mut ct_result, scalar)?;

        Ok(ct_result)
    }

    pub(crate) fn smart_scalar_add_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        let modulus = server_key.message_modulus.0 as u64;
        // Direct scalar computation is possible
        if server_key.is_scalar_add_possible(ct, scalar) {
            self.unchecked_scalar_add_assign(ct, scalar)?;
        } else {
            // If the scalar is too large, PBS is used to compute the scalar mul
            let acc = self.generate_accumulator(server_key, |x| (scalar as u64 + x) % modulus)?;
            self.apply_lookup_table_assign(server_key, ct, &acc)?;
            ct.degree = Degree(server_key.message_modulus.0 - 1);
        }
        Ok(())
    }
}
