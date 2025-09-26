use std::{convert::Infallible, fmt::Display};

use derive_more::From;
use hex::FromHexError;
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use serde_with::{serde_as, DisplayFromStr};
use time::error::{Format, Parse};

pub type Result<T> = core::result::Result<T, Error>;

#[serde_as]
#[derive(Debug, Serialize, From)]
pub enum Error {
    #[from]
    FormatError(#[serde_as(as = "DisplayFromStr")] std::fmt::Error),
    #[from]
    BincodeError(#[serde_as(as = "DisplayFromStr")] bincode::Error),
    #[from]
    InfallibleError(#[serde_as(as = "DisplayFromStr")] Infallible),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
