//! Module with the definition of the Ciphertext.
use crate::core_crypto::entities::*;
use crate::shortint::parameters::{CarryModulus, MessageModulus};
use serde::{Deserialize, Serialize};
use std::cmp;
use std::fmt::Debug;

/// This tracks the number of operations that has been done.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct Degree(pub usize);

#[repr(u8)]
pub enum CiphertextOpOrder {
    /// Ciphertext is encrypted using the big LWE secret key corresponding to the GLWE secret key.
    ///
    /// A keyswitch is first performed to bring it to the small LWE secret key realm, then the PBS
    /// is computed bringing it back to the large LWE secret key.
    KeyswitchPBS = 0,
    /// Ciphertext is encrypted using the small LWE secret key.
    ///
    /// The PBS is computed first and a keyswitch is applied to get back to the small LWE secret
    /// key realm.
    PBSKeyswitch = 1,
}

impl TryFrom<u8> for CiphertextOpOrder {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CiphertextOpOrder::KeyswitchPBS),
            1 => Ok(CiphertextOpOrder::PBSKeyswitch),
            v => Err(format!("Cannot convert {v} to CiphertextOpOrder")),
        }
    }
}

impl Degree {
    pub(crate) fn after_bitxor(&self, other: Degree) -> Degree {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        //Try every possibility to find the worst case
        for i in 0..min + 1 {
            if max ^ i > result {
                result = max ^ i;
            }
        }

        Degree(result)
    }

    pub(crate) fn after_bitor(&self, other: Degree) -> Degree {
        let max = cmp::max(self.0, other.0);
        let min = cmp::min(self.0, other.0);
        let mut result = max;

        for i in 0..min + 1 {
            if max | i > result {
                result = max | i;
            }
        }

        Degree(result)
    }

    pub(crate) fn after_bitand(&self, other: Degree) -> Degree {
        Degree(cmp::min(self.0, other.0))
    }

    pub(crate) fn after_left_shift(&self, shift: u8, modulus: usize) -> Degree {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = (i << shift) % modulus;
            if tmp > result {
                result = tmp;
            }
        }

        Degree(result)
    }

    #[allow(dead_code)]
    pub(crate) fn after_pbs<F>(&self, f: F) -> Degree
    where
        F: Fn(usize) -> usize,
    {
        let mut result = 0;

        for i in 0..self.0 + 1 {
            let tmp = f(i);
            if tmp > result {
                result = tmp;
            }
        }

        Degree(result)
    }
}

#[derive(Clone)]
#[must_use]
pub struct CiphertextNew<const OP_ORDER: u8> {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
}

pub type CiphertextBig = CiphertextNew<{ CiphertextOpOrder::KeyswitchPBS as u8 }>;
pub type CiphertextSmall = CiphertextNew<{ CiphertextOpOrder::PBSKeyswitch as u8 }>;

#[derive(Serialize, Deserialize)]
struct SerialiazableCiphertextNew {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub op_order: u8,
}

// Manual impl to be able to carry the OP_ORDER information
impl<const OP_ORDER: u8> Serialize for CiphertextNew<OP_ORDER> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerialiazableCiphertextNew {
            ct: self.ct.clone(),
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            op_order: OP_ORDER,
        }
        .serialize(serializer)
    }
}

// Manual impl to be able to check the OP_ORDER information
impl<'de, const OP_ORDER: u8> Deserialize<'de> for CiphertextNew<OP_ORDER> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let intermediate = SerialiazableCiphertextNew::deserialize(deserializer)?;
        if intermediate.op_order != OP_ORDER {
            return Err(serde::de::Error::custom(format!(
                "Expected OP_ORDER: {OP_ORDER}, got {}, \
                did you mix CiphertextBig ({}) and CiphertextSmall ({})?",
                intermediate.op_order,
                CiphertextOpOrder::KeyswitchPBS as u8,
                CiphertextOpOrder::PBSKeyswitch as u8
            )));
        }

        Ok(CiphertextNew {
            ct: intermediate.ct,
            degree: intermediate.degree,
            message_modulus: intermediate.message_modulus,
            carry_modulus: intermediate.carry_modulus,
        })
    }
}

/// A structure representing a compressed shortint ciphertext.
/// It is used to homomorphically evaluate a shortint circuits.
/// Internally, it uses a LWE ciphertext.
#[derive(Clone)]
pub struct CompressedCiphertextNew<const OP_ORDER: u8> {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
}

pub type CompressedCiphertextBig =
    CompressedCiphertextNew<{ CiphertextOpOrder::KeyswitchPBS as u8 }>;
pub type CompressedCiphertextSmall =
    CompressedCiphertextNew<{ CiphertextOpOrder::PBSKeyswitch as u8 }>;

#[derive(Serialize, Deserialize)]
struct SerialiazableCompressedCiphertextNew {
    pub ct: SeededLweCiphertext<u64>,
    pub degree: Degree,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub op_order: u8,
}

// Manual impl to be able to carry the OP_ORDER information
impl<const OP_ORDER: u8> Serialize for CompressedCiphertextNew<OP_ORDER> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        SerialiazableCompressedCiphertextNew {
            ct: self.ct.clone(),
            degree: self.degree,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            op_order: OP_ORDER,
        }
        .serialize(serializer)
    }
}

// Manual impl to be able to check the OP_ORDER information
impl<'de, const OP_ORDER: u8> Deserialize<'de> for CompressedCiphertextNew<OP_ORDER> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let intermediate = SerialiazableCompressedCiphertextNew::deserialize(deserializer)?;
        if intermediate.op_order != OP_ORDER {
            return Err(serde::de::Error::custom(format!(
                "Expected OP_ORDER: {OP_ORDER}, got {}, \
                    did you mix CompressedCiphertextBig ({}) and CompressedCiphertextSmall ({})?",
                intermediate.op_order,
                CiphertextOpOrder::KeyswitchPBS as u8,
                CiphertextOpOrder::PBSKeyswitch as u8
            )));
        }

        Ok(CompressedCiphertextNew {
            ct: intermediate.ct,
            degree: intermediate.degree,
            message_modulus: intermediate.message_modulus,
            carry_modulus: intermediate.carry_modulus,
        })
    }
}

impl<const OP_ORDER: u8> CompressedCiphertextNew<OP_ORDER> {
    pub fn decompress(self) -> CiphertextNew<OP_ORDER> {
        let CompressedCiphertextNew {
            ct,
            degree,
            message_modulus,
            carry_modulus,
        } = self;

        CiphertextNew {
            ct: ct.decompress_into_lwe_ciphertext(),
            degree,
            message_modulus,
            carry_modulus,
        }
    }
}

impl<const OP_ORDER: u8> From<CompressedCiphertextNew<OP_ORDER>> for CiphertextNew<OP_ORDER> {
    fn from(value: CompressedCiphertextNew<OP_ORDER>) -> Self {
        value.decompress()
    }
}
