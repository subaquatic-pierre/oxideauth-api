use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
};

use sea_query::{Nullable, Value as SeaValue};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::Digest;
use sqlx::prelude::Type;
use tracing::{error, warn};

use crate::store::error::{StoreError, Result};

#[derive(Debug, Deserialize, Type)]
pub struct Sha256Hash {
    inner: [u8; 32],
}
impl Sha256Hash {
    pub fn new(data: [u8; 32]) -> Self {
        Self { inner: data }
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
        let s: String = hex::encode(**self);
        write!(f, "{s}")
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
