use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::core::error::{Error, Result};
use crate::store::schema::hash::Sha256Hash;

pub trait Hashable {
    fn hash_sha256(&self) -> Result<Sha256Hash>;
}

impl<T: Serialize> Hashable for T {
    fn hash_sha256(&self) -> Result<Sha256Hash> {
        let bytes = bincode::serialize(&self)?;
        let hash = Sha256::digest(bytes);
        let data: [u8; 32] = hash.try_into()?;
        Ok(Sha256Hash::new(data))
    }
}
