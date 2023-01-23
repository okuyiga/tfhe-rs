//! Module containing the definition of the LwePublicKey.

use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

// An LwePublicKey is literally an LweCiphertextList, so we wrap an LweCiphertextList and use
// Deref to have access to all the primitives of the LweCiphertextList easily

/// A [`public LWE bootstrap key`](`LwePublicKey`).
///
/// This is a wrapper type of [`LweCiphertextList`], [`std::ops::Deref`] and [`std::ops::DerefMut`]
/// are implemented to dereference to the underlying [`LweCiphertextList`] for ease of use. See
/// [`LweCiphertextList`] for additional methods.
///
/// # Formal Definition
///
/// ## LWE Public Key
///
/// An LWE public key contains $m$ LWE encryptions of 0 under a secret key
/// $\vec{s}\in\mathbb{Z}\_q^n$ where $n$ is the LWE dimension of the ciphertexts contained in the
/// public key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LwePublicKey<C: Container, const Q: u128> {
    lwe_list: LweCiphertextList<C, Q>,
}

impl<C: Container, const Q: u128> std::ops::Deref for LwePublicKey<C, Q> {
    type Target = LweCiphertextList<C, Q>;

    fn deref(&self) -> &LweCiphertextList<C, Q> {
        &self.lwe_list
    }
}

impl<C: ContainerMut, const Q: u128> std::ops::DerefMut for LwePublicKey<C, Q> {
    fn deref_mut(&mut self) -> &mut LweCiphertextList<C, Q> {
        &mut self.lwe_list
    }
}

impl<Scalar, C: Container<Element = Scalar>, const Q: u128> LwePublicKey<C, Q> {
    /// Create an [`LwePublicKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`LwePublicKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_public_key`] using this key as output.
    ///
    /// This docstring exhibits [`LwePublicKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for LwePublicKey creation
    /// let lwe_size = LweSize(600);
    /// let zero_encryption_count = LwePublicKeyZeroEncryptionCount(3);
    ///
    /// // Create a new LwePublicKey
    /// let lwe_public_key = LwePublicKey::new(0u64, lwe_size, zero_encryption_count);
    ///
    /// // This is a method from LweCiphertextList
    /// assert_eq!(lwe_public_key.lwe_size(), lwe_size);
    /// // This is a method from LwePublicKey
    /// assert_eq!(
    ///     lwe_public_key.zero_encryption_count(),
    ///     zero_encryption_count
    /// );
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = lwe_public_key.into_container();
    ///
    /// // Recreate a public key using from_container
    /// let lwe_public_key = LwePublicKey::from_container(underlying_container, lwe_size);
    ///
    /// assert_eq!(lwe_public_key.lwe_size(), lwe_size);
    /// assert_eq!(
    ///     lwe_public_key.zero_encryption_count(),
    ///     zero_encryption_count
    /// );
    /// ```
    pub fn from_container(container: C, lwe_size: LweSize) -> LwePublicKey<C, Q> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create an LwePublicKey"
        );
        LwePublicKey {
            lwe_list: LweCiphertextList::from_container(container, lwe_size),
        }
    }

    /// Return the [`LwePublicKeyZeroEncryptionCount`] of the [`LwePublicKey`].
    ///
    /// See [`LwePublicKey::from_container`] for usage.
    pub fn zero_encryption_count(&self) -> LwePublicKeyZeroEncryptionCount {
        LwePublicKeyZeroEncryptionCount(self.lwe_ciphertext_count().0)
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`LwePublicKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.lwe_list.into_container()
    }

    /// Return a view of the [`LwePublicKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> LwePublicKey<&'_ [Scalar], Q> {
        LwePublicKey::from_container(self.as_ref(), self.lwe_size())
    }

    pub const fn modulus(&self) -> u128 {
        Q
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>, const Q: u128> LwePublicKey<C, Q> {
    /// Mutable variant of [`LwePublicKey::as_view`].
    pub fn as_mut_view(&mut self) -> LwePublicKey<&'_ mut [Scalar], Q> {
        let lwe_size = self.lwe_size();
        LwePublicKey::from_container(self.as_mut(), lwe_size)
    }
}

/// An [`LwePublicKey`] owning the memory for its own storage.
pub type LwePublicKeyOwned<Scalar, const Q: u128> = LwePublicKey<Vec<Scalar>, Q>;

pub type LwePublicKey32 = LwePublicKey<Vec<u32>, NATIVE_32_BITS_MODULUS>;
pub type LwePublicKey64 = LwePublicKey<Vec<u64>, NATIVE_64_BITS_MODULUS>;

impl<Scalar: Numeric + std::fmt::Display, const Q: u128> LwePublicKeyOwned<Scalar, Q> {
    /// Allocate memory and create a new owned [`LwePublicKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`LwePublicKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_public_key`] using this key as output.
    ///
    /// See [`LwePublicKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        zero_encryption_count: LwePublicKeyZeroEncryptionCount,
    ) -> LwePublicKeyOwned<Scalar, Q> {
        assert!(
            (Scalar::BITS == 128) || (Q != 0 && Q <= 1 << Scalar::BITS),
            "Selected modulus {Q}, is invalid either 0 or greater than max value of Scalar {}",
            Scalar::MAX
        );
        LwePublicKeyOwned::from_container(
            vec![fill_with; lwe_size.0 * zero_encryption_count.0],
            lwe_size,
        )
    }
}
