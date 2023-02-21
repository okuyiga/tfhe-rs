use crate::shortint::engine::{EngineResult, ShortintEngine};
use crate::shortint::{CiphertextNew, ServerKey};

impl ShortintEngine {
    pub(crate) fn unchecked_greater<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_greater_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_greater_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        let modulus_msg = ct_left.message_modulus.0 as u64;
        let large_mod = modulus * modulus_msg;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            (((x % large_mod / modulus) % modulus_msg) > (x % modulus_msg)) as u64
        })?;

        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_greater<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_greater_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_greater_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }

        self.unchecked_greater_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_greater_or_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_greater_or_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_greater_or_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        let modulus_msg = ct_left.message_modulus.0 as u64;
        let large_mod = modulus * modulus_msg;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            (((x % large_mod / modulus) % modulus_msg) >= (x % modulus_msg)) as u64
        })?;

        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_greater_or_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_greater_or_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_greater_or_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_greater_or_equal_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_less<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_less_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_less_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        let modulus_msg = ct_left.message_modulus.0 as u64;
        let large_mod = modulus * modulus_msg;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            (((x % large_mod / modulus) % modulus_msg) < (x % modulus_msg)) as u64
        })?;

        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_less<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_less_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_less_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_less_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_less_or_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_less_or_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_less_or_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        let modulus_msg = ct_left.message_modulus.0 as u64;
        let large_mod = modulus * modulus_msg;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            (((x % large_mod / modulus) % modulus_msg) <= (x % modulus_msg)) as u64
        })?;

        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_less_or_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_less_or_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_less_or_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_less_or_equal_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn unchecked_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        let modulus_msg = ct_left.message_modulus.0 as u64;
        let large_mod = modulus * modulus_msg;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            ((((x % large_mod) / modulus) % modulus_msg) == (x % modulus_msg)) as u64
        })?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_equal_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn smart_scalar_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_scalar_equal_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        let modulus = ct_left.message_modulus.0 as u64;
        let acc =
            self.generate_accumulator(server_key, |x| (x % modulus == scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn unchecked_not_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.unchecked_not_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    fn unchecked_not_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        let modulus = (ct_right.degree.0 + 1) as u64;
        let modulus_msg = ct_left.message_modulus.0 as u64;
        let large_mod = modulus * modulus_msg;
        self.unchecked_functional_bivariate_pbs_assign(server_key, ct_left, ct_right, |x| {
            ((((x % large_mod) / modulus) % modulus_msg) != (x % modulus_msg)) as u64
        })?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_not_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_not_equal_assign(server_key, &mut result, ct_right)?;
        Ok(result)
    }

    pub(crate) fn smart_not_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> EngineResult<()> {
        if !server_key.is_functional_bivariate_pbs_possible(ct_left, ct_right) {
            self.message_extract_assign(server_key, ct_left)?;
            self.message_extract_assign(server_key, ct_right)?;
        }
        self.unchecked_not_equal_assign(server_key, ct_left, ct_right)?;
        Ok(())
    }

    pub(crate) fn smart_scalar_not_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_scalar_not_equal_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_not_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        let modulus = ct_left.message_modulus.0 as u64;
        let acc =
            self.generate_accumulator(server_key, |x| (x % modulus != scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_scalar_greater_or_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_scalar_greater_or_equal_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_greater_or_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_accumulator(server_key, |x| (x >= scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_scalar_less_or_equal<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_scalar_less_or_equal_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_less_or_equal_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_accumulator(server_key, |x| (x <= scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_scalar_greater<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_scalar_greater_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_greater_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_accumulator(server_key, |x| (x > scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }

    pub(crate) fn smart_scalar_less<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<CiphertextNew<OP_ORDER>> {
        let mut result = ct_left.clone();
        self.smart_scalar_less_assign(server_key, &mut result, scalar)?;
        Ok(result)
    }

    fn smart_scalar_less_assign<const OP_ORDER: u8>(
        &mut self,
        server_key: &ServerKey,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        scalar: u8,
    ) -> EngineResult<()> {
        let acc = self.generate_accumulator(server_key, |x| (x < scalar as u64) as u64)?;
        self.apply_lookup_table_assign(server_key, ct_left, &acc)?;
        ct_left.degree.0 = 1;
        Ok(())
    }
}
