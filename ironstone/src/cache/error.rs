use std::{error::Error, fmt::Display};

use derive_more::From;
use redis::RedisError;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

pub type CacheResult<T> = Result<T, CacheError>;

#[serde_as]
#[derive(Debug, Serialize, From)]
pub enum CacheError {
    #[from]
    BincodeError(#[serde_as(as = "DisplayFromStr")] redis::RedisError),
}

impl Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for CacheError {}
