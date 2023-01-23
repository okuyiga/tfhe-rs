//! Module containing the definition of the SeededLwePublicKey.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

// A SeededLwePublicKey is literally a SeededLweCiphertextList, so we wrap an
// SeededLweCiphertextList and use Deref to have access to all the primitives of the
// SeededLweCiphertextList easily

/// A [`public LWE bootstrap key`](`SeededLwePublicKey`).
///
/// This is a wrapper type of [`SeededLweCiphertextList`], [`std::ops::Deref`] and
/// [`std::ops::DerefMut`] are implemented to dereference to the underlying
/// [`SeededLweCiphertextList`] for ease of use. See [`SeededLweCiphertextList`] for additional
/// methods.
///
/// # Formal Definition
///
/// ## LWE Public Key
///
/// An LWE public key contains $m$ LWE encryptions of 0 under a secret key
/// $\vec{s}\in\mathbb{Z}\_q^n$ where $n$ is the LWE dimension of the ciphertexts contained in the
/// public key.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeededLwePublicKey<C: Container, const Q: u128> {
    lwe_list: SeededLweCiphertextList<C, Q>,
}

impl<C: Container, const Q: u128> std::ops::Deref for SeededLwePublicKey<C, Q> {
    type Target = SeededLweCiphertextList<C, Q>;

    fn deref(&self) -> &SeededLweCiphertextList<C, Q> {
        &self.lwe_list
    }
}

impl<C: ContainerMut, const Q: u128> std::ops::DerefMut for SeededLwePublicKey<C, Q> {
    fn deref_mut(&mut self) -> &mut SeededLweCiphertextList<C, Q> {
        &mut self.lwe_list
    }
}

impl<Scalar, C: Container<Element = Scalar>, const Q: u128> SeededLwePublicKey<C, Q> {
    /// Create an [`SeededLwePublicKey`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to generate an
    /// [`SeededLwePublicKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_public_key`] using this key as output.
    ///
    /// This docstring exhibits [`SeededLwePublicKey`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLwePublicKey creation
    /// let lwe_size = LweSize(600);
    /// let zero_encryption_count = LwePublicKeyZeroEncryptionCount(3);
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLwePublicKey
    /// let seeded_lwe_public_key =
    ///     SeededLwePublicKey::new(0u64, lwe_size, zero_encryption_count, seeder.seed().into());
    ///
    /// // This is a method from LweCiphertextList
    /// assert_eq!(seeded_lwe_public_key.lwe_size(), lwe_size);
    /// // This is a method from SeededLwePublicKey
    /// assert_eq!(
    ///     seeded_lwe_public_key.zero_encryption_count(),
    ///     zero_encryption_count
    /// );
    ///
    /// let compression_seed = seeded_lwe_public_key.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = seeded_lwe_public_key.into_container();
    ///
    /// // Recreate a public key using from_container
    /// let seeded_lwe_public_key =
    ///     SeededLwePublicKey::from_container(underlying_container, lwe_size, compression_seed);
    ///
    /// assert_eq!(seeded_lwe_public_key.lwe_size(), lwe_size);
    /// assert_eq!(
    ///     seeded_lwe_public_key.zero_encryption_count(),
    ///     zero_encryption_count
    /// );
    ///
    /// // Decompress the key
    /// let lwe_public_key = seeded_lwe_public_key.decompress_into_lwe_public_key();
    ///
    /// assert_eq!(lwe_public_key.lwe_size(), lwe_size);
    /// assert_eq!(
    ///     lwe_public_key.zero_encryption_count(),
    ///     zero_encryption_count
    /// );
    /// ```
    pub fn from_container(
        container: C,
        lwe_size: LweSize,
        compression_seed: CompressionSeed,
    ) -> SeededLwePublicKey<C, Q> {
        assert!(
            container.container_len() > 0,
            "Got an empty container to create a SeededLwePublicKey"
        );
        SeededLwePublicKey {
            lwe_list: SeededLweCiphertextList::from_container(
                container,
                lwe_size,
                compression_seed,
            ),
        }
    }

    /// Return the [`LwePublicKeyZeroEncryptionCount`] of the [`SeededLwePublicKey`].
    ///
    /// See [`SeededLwePublicKey::from_container`] for usage.
    pub fn zero_encryption_count(&self) -> LwePublicKeyZeroEncryptionCount {
        LwePublicKeyZeroEncryptionCount(self.lwe_ciphertext_count().0)
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededLwePublicKey::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.lwe_list.into_container()
    }

    /// Consume the [`SeededLwePublicKey`] and decompress it into a standard
    /// [`LwePublicKey`].
    ///
    /// See [`SeededLwePublicKey::from_container`] for usage.
    pub fn decompress_into_lwe_public_key(self) -> LwePublicKeyOwned<Scalar, Q>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_list =
            LwePublicKey::new(Scalar::ZERO, self.lwe_size(), self.zero_encryption_count());
        decompress_seeded_lwe_public_key::<_, _, _, ActivatedRandomGenerator, Q>(
            &mut decompressed_list,
            &self,
        );
        decompressed_list
    }

    /// Return a view of the [`SeededLwePublicKey`]. This is useful if an algorithm takes a view by
    /// value.
    pub fn as_view(&self) -> SeededLwePublicKey<&'_ [Scalar], Q> {
        SeededLwePublicKey::from_container(self.as_ref(), self.lwe_size(), self.compression_seed())
    }

    pub const fn modulus(&self) -> u128 {
        Q
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>, const Q: u128> SeededLwePublicKey<C, Q> {
    /// Mutable variant of [`SeededLwePublicKey::as_view`].
    pub fn as_mut_view(&mut self) -> SeededLwePublicKey<&'_ mut [Scalar], Q> {
        let lwe_size = self.lwe_size();
        let compression_seed = self.compression_seed();
        SeededLwePublicKey::from_container(self.as_mut(), lwe_size, compression_seed)
    }
}

/// An [`SeededLwePublicKey`] owning the memory for its own storage.
pub type SeededLwePublicKeyOwned<Scalar, const Q: u128> = SeededLwePublicKey<Vec<Scalar>, Q>;

pub type SeededLwePublicKey32 = SeededLwePublicKey<Vec<u32>, NATIVE_32_BITS_MODULUS>;
pub type SeededLwePublicKey64 = SeededLwePublicKey<Vec<u64>, NATIVE_64_BITS_MODULUS>;

impl<Scalar: Numeric + std::fmt::Display, const Q: u128> SeededLwePublicKeyOwned<Scalar, Q> {
    /// Allocate memory and create a new owned [`SeededLwePublicKey`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to generate an [`SeededLwePublicKey`] you need to call
    /// [`crate::core_crypto::algorithms::generate_lwe_public_key`] using this key as output.
    ///
    /// See [`SeededLwePublicKey::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        zero_encryption_count: LwePublicKeyZeroEncryptionCount,
        compression_seed: CompressionSeed,
    ) -> SeededLwePublicKeyOwned<Scalar, Q> {
        assert!(
            (Scalar::BITS == 128) || (Q != 0 && Q <= 1 << Scalar::BITS),
            "Selected modulus {Q}, is invalid either 0 or greater than max value of Scalar {}",
            Scalar::MAX
        );
        SeededLwePublicKeyOwned::from_container(
            vec![fill_with; zero_encryption_count.0],
            lwe_size,
            compression_seed,
        )
    }
}
