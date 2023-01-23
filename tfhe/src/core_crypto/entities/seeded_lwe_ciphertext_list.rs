//! Module containing the definition of the SeededLweCiphertextList.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, CompressionSeed};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// A seeded list containing
/// [`LWE ciphertexts`](`crate::core_crypto::entities::LweCiphertext`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SeededLweCiphertextList<C: Container, const Q: u128> {
    data: C,
    lwe_size: LweSize,
    compression_seed: CompressionSeed,
}

impl<T, C: Container<Element = T>, const Q: u128> AsRef<[T]> for SeededLweCiphertextList<C, Q> {
    fn as_ref(&self) -> &[T] {
        self.data.as_ref()
    }
}

impl<T, C: ContainerMut<Element = T>, const Q: u128> AsMut<[T]> for SeededLweCiphertextList<C, Q> {
    fn as_mut(&mut self) -> &mut [T] {
        self.data.as_mut()
    }
}

impl<Scalar, C: Container<Element = Scalar>, const Q: u128> SeededLweCiphertextList<C, Q> {
    /// Create an [`SeededLweCiphertextList`] from an existing container.
    ///
    /// # Note
    ///
    /// This function only wraps a container in the appropriate type. If you want to encrypt data
    /// you need to use [`crate::core_crypto::algorithms::encrypt_seeded_lwe_ciphertext_list`] or
    /// [`crate::core_crypto::algorithms::par_encrypt_seeded_lwe_ciphertext_list`] using
    /// this list as output.
    ///
    /// This docstring exhibits [`SeededLweCiphertextList`] primitives usage.
    ///
    /// ```
    /// use tfhe::core_crypto::prelude::*;
    ///
    /// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    /// // computations
    /// // Define parameters for SeededLweCiphertextList creation
    /// let lwe_dimension = LweDimension(742);
    /// let lwe_ciphertext_count = LweCiphertextCount(2);
    ///
    /// // Get a seeder
    /// let mut seeder = new_seeder();
    /// let seeder = seeder.as_mut();
    ///
    /// // Create a new SeededLweCiphertextList
    /// let mut seeded_lwe_list = SeededLweCiphertextList::new(
    ///     0u64,
    ///     lwe_dimension.to_lwe_size(),
    ///     lwe_ciphertext_count,
    ///     seeder.seed().into(),
    /// );
    ///
    /// assert_eq!(seeded_lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(seeded_lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    ///
    /// let compression_seed = seeded_lwe_list.compression_seed();
    ///
    /// // Demonstrate how to recover the allocated container
    /// let underlying_container: Vec<u64> = seeded_lwe_list.into_container();
    ///
    /// // Recreate a list using from_container
    /// let seeded_lwe_list = SeededLweCiphertextList::from_container(
    ///     underlying_container,
    ///     lwe_dimension.to_lwe_size(),
    ///     compression_seed,
    /// );
    ///
    /// assert_eq!(seeded_lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(seeded_lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    ///
    /// // Decompress the list
    /// let lwe_list = seeded_lwe_list.decompress_into_lwe_ciphertext_list();
    ///
    /// assert_eq!(lwe_list.lwe_size(), lwe_dimension.to_lwe_size());
    /// assert_eq!(lwe_list.lwe_ciphertext_count(), lwe_ciphertext_count);
    /// ```
    pub fn from_container(
        container: C,
        lwe_size: LweSize,
        compression_seed: CompressionSeed,
    ) -> SeededLweCiphertextList<C, Q> {
        SeededLweCiphertextList {
            data: container,
            lwe_size,
            compression_seed,
        }
    }

    /// Return the [`LweSize`] of the compressed [`LweCiphertext`] stored in the list.
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn lwe_size(&self) -> LweSize {
        self.lwe_size
    }

    /// Return the [`CompressionSeed`] of the [`SeededLweCiphertextList`].
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn compression_seed(&self) -> CompressionSeed {
        self.compression_seed
    }

    /// Return the [`LweCiphertextCount`] of the [`SeededLweCiphertextList`].
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.data.container_len())
    }

    /// Consume the entity and return its underlying container.
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn into_container(self) -> C {
        self.data
    }

    /// Consume the [`SeededLweCiphertextList`] and decompress it into a standard
    /// [`LweCiphertextList`].
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn decompress_into_lwe_ciphertext_list(self) -> LweCiphertextListOwned<Scalar, Q>
    where
        Scalar: UnsignedTorus,
    {
        let mut decompressed_list =
            LweCiphertextList::new(Scalar::ZERO, self.lwe_size(), self.lwe_ciphertext_count());
        decompress_seeded_lwe_ciphertext_list::<_, _, _, ActivatedRandomGenerator, Q>(
            &mut decompressed_list,
            &self,
        );
        decompressed_list
    }

    /// Return a view of the [`SeededLweCiphertextList`]. This is useful if an algorithm takes a
    /// view by value.
    pub fn as_view(&self) -> SeededLweCiphertextList<&'_ [Scalar], Q> {
        SeededLweCiphertextList::from_container(
            self.as_ref(),
            self.lwe_size(),
            self.compression_seed(),
        )
    }

    pub const fn modulus(&self) -> u128 {
        Q
    }
}

impl<Scalar, C: ContainerMut<Element = Scalar>, const Q: u128> SeededLweCiphertextList<C, Q> {
    /// Mutable variant of [`SeededLweCiphertextList::as_view`].
    pub fn as_mut_view(&mut self) -> SeededLweCiphertextList<&'_ mut [Scalar], Q> {
        let lwe_size = self.lwe_size();
        let compression_seed = self.compression_seed();
        SeededLweCiphertextList::from_container(self.as_mut(), lwe_size, compression_seed)
    }
}

/// An [`SeededLweCiphertextList`] owning the memory for its own storage.
pub type SeededLweCiphertextListOwned<Scalar, const Q: u128> =
    SeededLweCiphertextList<Vec<Scalar>, Q>;
/// An [`SeededLweCiphertextList`] immutably borrowing memory for its own storage.
pub type SeededLweCiphertextListView<'data, Scalar, const Q: u128> =
    SeededLweCiphertextList<&'data [Scalar], Q>;
/// An [`SeededLweCiphertextList`] mutably borrowing memory for its own storage.
pub type SeededLweCiphertextListMutView<'data, Scalar, const Q: u128> =
    SeededLweCiphertextList<&'data mut [Scalar], Q>;

impl<Scalar: Numeric + std::fmt::Display, const Q: u128> SeededLweCiphertextListOwned<Scalar, Q> {
    /// Allocate memory and create a new owned [`SeededLweCiphertextList`].
    ///
    /// # Note
    ///
    /// This function allocates a vector of the appropriate size and wraps it in the appropriate
    /// type. If you want to encrypt data you need to use
    /// [`crate::core_crypto::algorithms::encrypt_seeded_lwe_ciphertext_list`] or
    /// [`crate::core_crypto::algorithms::par_encrypt_seeded_lwe_ciphertext_list`]  using this list
    /// as output.
    ///
    /// See [`SeededLweCiphertextList::from_container`] for usage.
    pub fn new(
        fill_with: Scalar,
        lwe_size: LweSize,
        ciphertext_count: LweCiphertextCount,
        compression_seed: CompressionSeed,
    ) -> SeededLweCiphertextListOwned<Scalar, Q> {
        assert!(
            (Scalar::BITS == 128) || (Q != 0 && Q <= 1 << Scalar::BITS),
            "Selected modulus {Q}, is invalid either 0 or greater than max value of Scalar {}",
            Scalar::MAX
        );
        SeededLweCiphertextListOwned::from_container(
            vec![fill_with; ciphertext_count.0],
            lwe_size,
            compression_seed,
        )
    }
}

/// Metadata used in the [`CreateFrom`] implementation to create [`SeededLweCiphertextList`]
/// entities.
#[derive(Clone, Copy)]
pub struct SeededLweCiphertextListCreationMetadata(pub LweSize, pub CompressionSeed);

impl<C: Container, const Q: u128> CreateFrom<C> for SeededLweCiphertextList<C, Q> {
    type Metadata = SeededLweCiphertextListCreationMetadata;

    #[inline]
    fn create_from(from: C, meta: Self::Metadata) -> SeededLweCiphertextList<C, Q> {
        let SeededLweCiphertextListCreationMetadata(lwe_size, compression_seed) = meta;
        SeededLweCiphertextList::from_container(from, lwe_size, compression_seed)
    }
}

impl<C: Container, const Q: u128> ContiguousEntityContainer for SeededLweCiphertextList<C, Q> {
    type Element = C::Element;

    type EntityViewMetadata = ();

    type EntityView<'this> = LweBody<&'this Self::Element, Q>
    where
        Self: 'this;

    type SelfViewMetadata = ();

    type SelfView<'this> = DummyCreateFrom
    where
        Self: 'this;

    fn get_entity_view_creation_metadata(&self) {}

    fn get_entity_view_pod_size(&self) -> usize {
        1
    }

    /// Unimplemented for [`SeededLweCiphertextList`]. At the moment it does not make sense to
    /// return "sub" seeded lists.
    fn get_self_view_creation_metadata(&self) {
        unimplemented!(
            "This function is not supported for SeededLweCiphertextList. \
        At the moment it does not make sense to return 'sub' seeded lists."
        )
    }
}

impl<C: ContainerMut, const Q: u128> ContiguousEntityContainerMut
    for SeededLweCiphertextList<C, Q>
{
    type EntityMutView<'this> = LweBody<&'this mut Self::Element, Q>
    where
        Self: 'this;

    type SelfMutView<'this> = DummyCreateFrom
    where
        Self: 'this;
}
