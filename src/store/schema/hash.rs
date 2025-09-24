use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
};

use sea_query::{Nullable, Value as SeaValue};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::prelude::Type;

use crate::store::error::{Error, Result};

#[derive(Debug, Deserialize, Type)]
pub struct Sha256Hash {
    inner: [u8; 32],
}

impl Sha256Hash {
    pub fn try_from_str(val: &str) -> Result<Self> {
        let bytes = sha2::Sha256::digest(val.as_bytes());

        Ok(Self {
            inner: bytes.into(),
        })
    }

    pub fn try_from_value<V: Serialize>(val: &V) -> Result<Self> {
        let json_str = serde_json::to_string(val)?;
        let bytes = sha2::Sha256::digest(json_str.as_bytes());

        Ok(Self {
            inner: bytes.into(),
        })
    }
}

impl Deref for Sha256Hash {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Sha256Hash {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Display for Sha256Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = self.try_into().map_err(|e| std::fmt::Error)?;
        write!(f, "{s}")
    }
}

impl TryFrom<Sha256Hash> for String {
    type Error = Error;

    fn try_from(value: Sha256Hash) -> Result<String> {
        Ok(hex::encode(*value))
    }
}

impl TryFrom<&Sha256Hash> for String {
    type Error = Error;

    fn try_from(value: &Sha256Hash) -> Result<String> {
        Ok(hex::encode(**value))
    }
}

impl TryFrom<String> for Sha256Hash {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        let mut bytes = [0_u8; 32];

        let bytes_vec = hex::decode(value)?;

        bytes_vec
            .iter()
            .enumerate()
            .for_each(|(i, b)| bytes[i] = *b);

        Ok(Sha256Hash { inner: bytes })
    }
}

impl Nullable for Sha256Hash {
    fn null() -> SeaValue {
        SeaValue::String(None)
    }
}

impl From<Sha256Hash> for SeaValue {
    fn from(value: Sha256Hash) -> Self {
        SeaValue::String(Some(Box::new(value.to_string())))
    }
}
