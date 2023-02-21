use crate::shortint::ciphertext::Degree;
use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{CiphertextNew, ServerKey};

// Specific division function returning 0 in case of a division by 0
pub(crate) fn division(x: u64, modulus: u64) -> u64 {
    if x % modulus == 0 {
        0
    } else {
        (x / modulus) / (x % modulus)
    }
}

impl ShortintEngine {
    pub(crate) fn unchecked_div<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_div_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn unchecked_div_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;

        //In this case the degree of the result is equal to the degree of ct_left
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            division(x, modulus)
        })?;
        Ok(())
    }

    pub(crate) fn smart_div<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_div_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_div_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            if ct_left.message_modulus.0 + ct_right.degree.0 <= server_key.max_degree.0 {
                self.message_extract_assign(server_key, ct_left)?;
            } else if ct_right.message_modulus.0 + (ct_left.degree.0 + 1) <= server_key.max_degree.0
            {
                self.message_extract_assign(server_key, ct_right)?;
            } else {
                self.message_extract_assign(server_key, ct_left)?;
                self.message_extract_assign(server_key, ct_right)?;
            }
        }
        self.unchecked_div_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    /// # Panics
    ///
    /// This function will panic if `scalar == 0`
    pub(crate) fn unchecked_scalar_div<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct: &CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct.clone();
        self.unchecked_scalar_div_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    /// # Panics
    ///
    /// This function will panic if `scalar == 0`
    pub(crate) fn unchecked_scalar_div_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        assert_ne!(scalar, 0);
        //generate the accumulator for the multiplication
        let acc = self.generate_accumulator(server_key, |x| x / (scalar as u64))?;
        self.apply_lookup_table_assign(server_key, ct, &acc)?;
        ct.degree = Degree(ct.degree.0 / scalar as usize);
        Ok(())
    }

    pub(crate) fn unchecked_scalar_mod<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct: &CiphertextNew<OP_ORDER>,
        modulus: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct.clone();
        self.unchecked_scalar_mod_assign(server_key, &mut result, modulus)?;
        Ok(result)
    }

    /// # Panics
    ///
    /// This function will panic if `modulus == 0`
    pub(crate) fn unchecked_scalar_mod_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct: &mut CiphertextNew<OP_ORDER>,
        modulus: u8,
    ) -> EngineResult<()> {
        assert_ne!(modulus, 0);
        let acc = self.generate_accumulator(server_key, |x| x % modulus as u64)?;
        self.apply_lookup_table_assign(server_key, ct, &acc)?;
        ct.degree = Degree(modulus as usize - 1);
        Ok(())
    }
}
