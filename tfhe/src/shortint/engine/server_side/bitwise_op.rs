use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{CiphertextNew, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_bitand<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_bitand_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_bitand_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            (x / modulus) & (x % modulus)
        })?;
        ct_left.degree = ct_left.degree.after_bitand(ct_right.degree);
        Ok(())
    }

    pub(crate) fn smart_bitand<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_bitand_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_bitand_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_bitand_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_bitxor<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_bitxor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_bitxor_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            (x / modulus) ^ (x % modulus)
        })?;
        ct_left.degree = ct_left.degree.after_bitxor(ct_right.degree);
        Ok(())
    }

    pub(crate) fn smart_bitxor<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_bitxor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_bitxor_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_bitxor_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_bitor<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_bitor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_bitor_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            (x / modulus) | (x % modulus)
        })?;
        ct_left.degree = ct_left.degree.after_bitor(ct_right.degree);
        Ok(())
    }

    pub(crate) fn smart_bitor<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_bitor_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_bitor_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_bitor_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }
}
