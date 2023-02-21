use crate::core_crypto::algorithms::*;
use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{CiphertextNew, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_add<const OP_ORDER: u8>(
        &mut self,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_add_assign(&mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_add_assign<const OP_ORDER: u8>(
        &mut self,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        lwe_ciphertext_add_assign(&mut ct_left.ct, &ct_right.ct);
        ct_left.degree = Degree(ct_left.degree.0 + ct_right.degree.0);
        Ok(())
    }

    pub(crate) fn smart_add<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_add_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_add_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        //If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if !server_key.is_add_possible(ct_left, ct_right) {
            if ct_left.message_modulus.0 - 1 + ct_right.degree.0 <= server_key.max_degree.0 {
                self.message_extract_assign(server_key, ct_left)?;
            } else if ct_right.message_modulus.0 - 1 + ct_left.degree.0 <= server_key.max_degree.0 {
                self.message_extract_assign(server_key, ct_right)?;
            } else {
                self.message_extract_assign(server_key, ct_left)?;
                self.message_extract_assign(server_key, ct_right)?;
            }
        }
        self.unchecked_add_assign(ct_left, ct_right)?;
        Ok(())
    }
}
