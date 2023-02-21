use super::ServerKey;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::CheckError;
use crate::shortint::server_key::CheckError::CarryFull;
use crate::shortint::CiphertextNew;

impl ServerKey {
    /// Homomorphically subtracts ct_right to ct_left.
    ///
    /// The result is returned in a _new_ ciphertext.
    ///
    /// This function computes the subtraction without checking
    /// if it exceeds the capacity of the ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.unchecked_sub(&ct_1, &ct_2);
    ///
    /// // Decrypt:
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(cks.decrypt(&ct_res), 2 - 1);
    /// ```
    pub fn unchecked_sub<const OP_ORDER: u8>(
        &self,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> CiphertextNew<OP_ORDER> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.unchecked_sub(self, ct_left, ct_right).unwrap()
        })
    }

    /// Homomorphically subtracts ct_right to ct_left.
    ///
    /// The result is assigned in the `ct_left` ciphertext.
    ///
    /// This function computes the subtraction without checking
    /// if it exceeds the capacity of the ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(2);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// sks.unchecked_sub_assign(&mut ct_1, &ct_2);
    ///
    /// // Decrypt:
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(cks.decrypt(&ct_1) % modulus, 1);
    /// ```
    pub fn unchecked_sub_assign<const OP_ORDER: u8>(
        &self,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_sub_assign(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Verify if ct_right can be subtracted to ct_left.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 2;
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(msg);
    /// let ct_2 = cks.encrypt(msg);
    ///
    /// // Check if we can perform an subtraction
    /// let can_be_subtracted = sks.is_sub_possible(&ct_1, &ct_2);
    ///
    /// assert_eq!(true, can_be_subtracted);
    /// ```
    pub fn is_sub_possible<const OP_ORDER: u8>(
        &self,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> bool {
        // z = ceil( degree / 2^p ) x 2^p
        let msg_mod = self.message_modulus.0;
        let mut z = (ct_right.degree.0 + msg_mod - 1) / msg_mod;
        z = z.wrapping_mul(msg_mod);

        let final_operation_count = ct_left.degree.0 + z;

        final_operation_count <= self.max_degree.0
    }

    /// Compute homomorphically a subtraction between two ciphertexts encrypting integer values.
    ///
    /// If the operation can be performed, the result is returned a _new_ ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let ct_1 = cks.encrypt(3);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.checked_sub(&ct_1, &ct_2);
    ///
    /// assert!(ct_res.is_ok());
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// let clear_res = cks.decrypt(&ct_res.unwrap());
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn checked_sub<const OP_ORDER: u8>(
        &self,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> Result<CiphertextNew<OP_ORDER>, CheckError> {
        // If the ciphertexts cannot be subtracted without exceeding the degree max
        if self.is_sub_possible(ct_left, ct_right) {
            let ct_result = self.unchecked_sub(ct_left, ct_right);
            Ok(ct_result)
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a subtraction between two ciphertexts.
    ///
    /// If the operation can be performed, the result is stored in the `ct_left` ciphertext.
    /// Otherwise [CheckError::CarryFull] is returned, and `ct_left` is not modified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(3);
    /// let ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// let res = sks.checked_sub_assign(&mut ct_1, &ct_2);
    ///
    /// assert!(res.is_ok());
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// let clear_res = cks.decrypt(&ct_1);
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn checked_sub_assign<const OP_ORDER: u8>(
        &self,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> Result<(), CheckError> {
        // If the ciphertexts cannot be subtracted without exceeding the degree max
        if self.is_sub_possible(ct_left, ct_right) {
            self.unchecked_sub_assign(ct_left, ct_right);
            Ok(())
        } else {
            Err(CarryFull)
        }
    }

    /// Compute homomorphically a subtraction between two ciphertexts.
    ///
    /// This checks that the subtraction is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(3);
    /// let mut ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// let ct_res = sks.smart_sub(&mut ct_1, &mut ct_2);
    ///
    /// let clear_res = cks.decrypt(&ct_res);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(clear_res % modulus, 2);
    /// ```
    pub fn smart_sub<const OP_ORDER: u8>(
        &self,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> CiphertextNew<OP_ORDER> {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_sub(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically a subtraction between two ciphertexts.
    ///
    /// This checks that the subtraction is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// // Encrypt two messages:
    /// let mut ct_1 = cks.encrypt(3);
    /// let mut ct_2 = cks.encrypt(1);
    ///
    /// // Compute homomorphically a subtraction:
    /// sks.smart_sub_assign(&mut ct_1, &mut ct_2);
    /// let modulus = cks.parameters.message_modulus.0 as u64;
    /// assert_eq!(cks.decrypt(&ct_1) % modulus, 2);
    /// ```
    pub fn smart_sub_assign<const OP_ORDER: u8>(
        &self,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_sub_assign(self, ct_left, ct_right).unwrap()
        })
    }

    /// Compute homomorphically a subtraction between two ciphertexts without checks, and returns
    /// a correcting term.
    ///
    /// This checks that the subtraction is possible. In the case where the carry buffers are
    /// full, then it is automatically cleared to allow the operation.
    ///
    /// # Warning
    ///
    /// This is an advanced functionality, needed for internal requirements.
    pub fn unchecked_sub_with_correcting_term<const OP_ORDER: u8>(
        &self,
        ct_left: &CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> (CiphertextNew<OP_ORDER>, u64) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_sub_with_z(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Compute homomorphically a subtraction between two ciphertexts without checks, and returns
    /// a correcting term.
    ///
    /// # Warning
    ///
    /// This is an advanced functionality, needed for internal requirements.
    pub fn unchecked_sub_with_correcting_term_assign<const OP_ORDER: u8>(
        &self,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &CiphertextNew<OP_ORDER>,
    ) -> u64 {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine
                .unchecked_sub_assign_with_z(self, ct_left, ct_right)
                .unwrap()
        })
    }

    /// Compute homomorphically a subtraction between two ciphertexts without checks, and returns
    /// a correcting term.
    ///
    /// # Warning
    ///
    /// This is an advanced functionality, needed for internal requirements.
    pub fn smart_sub_with_correcting_term<const OP_ORDER: u8>(
        &self,
        ct_left: &mut CiphertextNew<OP_ORDER>,
        ct_right: &mut CiphertextNew<OP_ORDER>,
    ) -> (CiphertextNew<OP_ORDER>, u64) {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.smart_sub_with_z(self, ct_left, ct_right).unwrap()
        })
    }
}
