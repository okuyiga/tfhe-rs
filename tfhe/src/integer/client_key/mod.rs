//! This module implements the generation of the client keys structs
//!
//! Client keys are the keys used to encrypt an decrypt data.
//! These are private and **MUST NOT** be shared.

mod crt;
mod radix;
pub(crate) mod utils;

use crate::integer::ciphertext::{
    CompressedCrtCiphertext, CompressedRadixCiphertext, CrtCiphertext, RadixCiphertext,
};
use crate::integer::client_key::utils::i_crt;
use crate::integer::encryption::{encrypt_crt, encrypt_words_radix_impl, AsLittleEndianWords};
use crate::shortint::parameters::MessageModulus;
use crate::shortint::{
    Ciphertext as ShortintCiphertext, ClientKey as ShortintClientKey,
    Parameters as ShortintParameters,
};
use serde::{Deserialize, Serialize};
pub use utils::radix_decomposition;

pub use crt::CrtClientKey;
pub use radix::RadixClientKey;

/// A structure containing the client key, which must be kept secret.
///
/// This key can be used to encrypt both in Radix and CRT
/// decompositions.
///
/// Using this key, for both decompositions, each block will
/// use the same crypto parameters.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ClientKey {
    pub(crate) key: ShortintClientKey,
}

impl From<ShortintClientKey> for ClientKey {
    fn from(key: ShortintClientKey) -> Self {
        Self { key }
    }
}

impl From<ClientKey> for ShortintClientKey {
    fn from(key: ClientKey) -> ShortintClientKey {
        key.key
    }
}

impl AsRef<ClientKey> for ClientKey {
    fn as_ref(&self) -> &ClientKey {
        self
    }
}

impl ClientKey {
    /// Creates a Client Key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key, that can encrypt in
    /// // radix and crt decomposition, where each block of the decomposition
    /// // have over 2 bits of message modulus.
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// ```
    pub fn new(parameter_set: ShortintParameters) -> Self {
        Self {
            key: ShortintClientKey::new(parameter_set),
        }
    }

    pub fn parameters(&self) -> ShortintParameters {
        self.key.parameters
    }

    /// Encrypts an integer in radix decomposition
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 167_u64;
    ///
    /// // 2 * 4 = 8 bits of message
    /// let ct = cks.encrypt_radix(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_radix<T: AsLittleEndianWords>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> RadixCiphertext {
        self.encrypt_words_radix(message, num_blocks, crate::shortint::ClientKey::encrypt)
    }

    pub fn encrypt_radix_compressed<T: AsLittleEndianWords>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> CompressedRadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt_compressed,
        )
    }

    pub fn encrypt_radix_without_padding_compressed<T: AsLittleEndianWords>(
        &self,
        message: T,
        num_blocks: usize,
    ) -> CompressedRadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt_without_padding_compressed,
        )
    }

    /// Encrypts an integer in radix decomposition without padding bit
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 167_u64;
    ///
    /// // 2 * 4 = 8 bits of message
    /// let ct = cks.encrypt_radix_without_padding(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_radix_without_padding(
        &self,
        message: u64,
        num_blocks: usize,
    ) -> RadixCiphertext {
        self.encrypt_words_radix(
            message,
            num_blocks,
            crate::shortint::ClientKey::encrypt_without_padding,
        )
    }

    /// Encrypts 64-bits words into a ciphertext in radix decomposition
    ///
    /// The words are assumed to be in little endian order.
    ///
    /// If there are not enough words for the requested num_block,
    /// encryptions of zeros will be appended.
    pub fn encrypt_words_radix<Block, RadixCiphertextType, T, F>(
        &self,
        message_words: T,
        num_blocks: usize,
        encrypt_block: F,
    ) -> RadixCiphertextType
    where
        T: AsLittleEndianWords,
        F: Fn(&crate::shortint::ClientKey, u64) -> Block,
        RadixCiphertextType: From<Vec<Block>>,
    {
        encrypt_words_radix_impl(&self.key, message_words, num_blocks, encrypt_block)
    }

    /// Encrypts one block.
    ///
    /// This returns a shortint ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 2_u64;
    ///
    /// // Encryption
    /// let ct = cks.encrypt_one_block(msg);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_one_block(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_one_block(&self, message: u64) -> ShortintCiphertext {
        self.key.encrypt(message)
    }

    /// Decrypts one block.
    ///
    /// This takes a shortint ciphertext as input.
    pub fn decrypt_one_block(&self, ct: &ShortintCiphertext) -> u64 {
        self.key.decrypt(ct)
    }

    /// Decrypts a ciphertext encrypting an radix integer
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 191_u64;
    ///
    /// // Encryption
    /// let ct = cks.encrypt_radix(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_radix<T: AsLittleEndianWords + Default>(&self, ctxt: &RadixCiphertext) -> T {
        let mut res = T::default();
        self.decrypt_radix_into(ctxt, &mut res);
        res
    }

    pub fn decrypt_radix_into<T: AsLittleEndianWords>(&self, ctxt: &RadixCiphertext, out: &mut T) {
        self.decrypt_radix_into_words(
            ctxt,
            out,
            crate::shortint::ClientKey::decrypt_message_and_carry,
        );
    }

    /// Decrypts a ciphertext encrypting an radix integer encrypted without padding
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    /// let num_block = 4;
    ///
    /// let msg = 191_u64;
    ///
    /// // Encryption
    /// let ct = cks.encrypt_radix_without_padding(msg, num_block);
    ///
    /// // Decryption
    /// let dec = cks.decrypt_radix_without_padding(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_radix_without_padding(&self, ctxt: &RadixCiphertext) -> u64 {
        let mut res = 0u64;
        self.decrypt_radix_into_words(
            ctxt,
            &mut res,
            crate::shortint::ClientKey::decrypt_message_and_carry_without_padding,
        );
        res
    }

    /// Decrypts a ciphertext in radix decomposition into 64bits
    ///
    /// The words are assumed to be in little endian order.
    pub fn decrypt_radix_into_words<T, F>(
        &self,
        ctxt: &RadixCiphertext,
        clear_words: &mut T,
        decrypt_block: F,
    ) where
        T: AsLittleEndianWords,
        F: Fn(&crate::shortint::ClientKey, &crate::shortint::Ciphertext) -> u64,
    {
        // limit to know when we have at least 64 bits
        // of decrypted data
        const U64_MODULUS: u128 = 1 << 64;

        let clear_words_iter = clear_words.as_little_endian_iter_mut();

        let mut cipher_blocks_iter = ctxt.blocks.iter();
        let mut bit_buffer = 0u128;
        let mut valid_until_power = 1u128;
        for current_clear_word in clear_words_iter {
            for cipher_block in cipher_blocks_iter.by_ref() {
                let block_value = decrypt_block(&self.key, cipher_block) as u128;

                let shifted_block_value = block_value * valid_until_power;
                bit_buffer += shifted_block_value;

                valid_until_power *= self.key.parameters.message_modulus.0 as u128;

                if valid_until_power >= U64_MODULUS {
                    // We have enough data to fill the current word
                    // e.g.
                    // bit_buffer: [b0, ..., b64, b66, b67,..., b128]
                    //                       ^          ^
                    //                       |          |-> valid_until_power
                    //                       |              = end of decrypted bits
                    //                       |-> U64_MODULUS
                    break;
                }
            }

            // We want to take at most 64 bits of data from the bit buffer
            // since our words are 64 bits
            let power_to_write = std::cmp::min(valid_until_power, U64_MODULUS);
            let mask = power_to_write - 1;
            *current_clear_word = (bit_buffer & mask) as u64;
            bit_buffer /= power_to_write;
            valid_until_power /= power_to_write;
        }
    }

    /// Encrypts an integer using crt representation
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 13_u64;
    ///
    /// // Encryption:
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let ct = cks.encrypt_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(
            message,
            base_vec,
            crate::shortint::ClientKey::encrypt_with_message_modulus,
        )
    }

    pub fn encrypt_crt_compressed(
        &self,
        message: u64,
        base_vec: Vec<u64>,
    ) -> CompressedCrtCiphertext {
        self.encrypt_crt_impl(
            message,
            base_vec,
            crate::shortint::ClientKey::encrypt_with_message_modulus_compressed,
        )
    }

    /// Decrypts an integer in crt decomposition
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
    ///
    /// // Generate the client key and the server key:
    /// let mut cks = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
    ///
    /// let msg = 27_u64;
    /// let basis: Vec<u64> = vec![2, 3, 5];
    ///
    /// // Encryption:
    /// let mut ct = cks.encrypt_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_crt(&self, ctxt: &CrtCiphertext) -> u64 {
        let mut val: Vec<u64> = Vec::with_capacity(ctxt.blocks.len());

        // Decrypting each block individually
        for (c_i, b_i) in ctxt.blocks.iter().zip(ctxt.moduli.iter()) {
            // decrypt the component i of the integer and multiply it by the radix product
            val.push(self.key.decrypt_message_and_carry(c_i) % b_i);
        }

        // Computing the inverse CRT to recompose the message
        let result = i_crt(&ctxt.moduli, &val);

        let whole_modulus: u64 = ctxt.moduli.iter().copied().product();

        result % whole_modulus
    }

    /// Encrypts a small integer message using the client key and some moduli without padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_3_CARRY_3);
    ///
    /// let msg = 13_u64;
    ///
    /// // Encryption of one message:
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// let ct = cks.encrypt_native_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_native_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn encrypt_native_crt(&self, message: u64, base_vec: Vec<u64>) -> CrtCiphertext {
        self.encrypt_crt_impl(message, base_vec, |cks, msg, moduli| {
            cks.encrypt_native_crt(msg, moduli.0 as u8)
        })
    }

    pub fn encrypt_native_crt_compressed(
        &self,
        message: u64,
        base_vec: Vec<u64>,
    ) -> CompressedCrtCiphertext {
        self.encrypt_crt_impl(message, base_vec, |cks, msg, moduli| {
            cks.encrypt_native_crt_compressed(msg, moduli.0 as u8)
        })
    }

    /// Decrypts a ciphertext encrypting an integer message with some moduli basis without
    /// padding bit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::integer::ClientKey;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_3_CARRY_3;
    ///
    /// let cks = ClientKey::new(PARAM_MESSAGE_3_CARRY_3);
    ///
    /// let msg = 27_u64;
    /// let basis: Vec<u64> = vec![2, 3, 5];
    /// // Encryption of one message:
    /// let mut ct = cks.encrypt_native_crt(msg, basis);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt_native_crt(&ct);
    /// assert_eq!(msg, dec);
    /// ```
    pub fn decrypt_native_crt(&self, ct: &CrtCiphertext) -> u64 {
        let mut val: Vec<u64> = vec![];

        //Decrypting each block individually
        for (c_i, b_i) in ct.blocks.iter().zip(ct.moduli.iter()) {
            //decrypt the component i of the integer and multiply it by the radix product
            val.push(self.key.decrypt_message_native_crt(c_i, *b_i as u8));
        }

        //Computing the inverse CRT to recompose the message
        let result = i_crt(&ct.moduli, &val);

        let whole_modulus: u64 = ct.moduli.iter().copied().product();

        result % whole_modulus
    }

    fn encrypt_crt_impl<Block, CrtCiphertextType, F>(
        &self,
        message: u64,
        base_vec: Vec<u64>,
        encrypt_block: F,
    ) -> CrtCiphertextType
    where
        F: Fn(&crate::shortint::ClientKey, u64, MessageModulus) -> Block,
        CrtCiphertextType: From<(Vec<Block>, Vec<u64>)>,
    {
        encrypt_crt(&self.key, message, base_vec, encrypt_block)
    }
}
