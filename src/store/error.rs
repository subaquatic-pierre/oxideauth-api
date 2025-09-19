use std::fmt::Display;

use derive_more::From;
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use serde_with::{serde_as, DisplayFromStr};
use time::error::Parse;

pub type Result<T> = core::result::Result<T, Error>;

#[serde_as]
#[derive(Debug, Serialize, From)]
pub enum Error {
    WithTxnFalse,
    NoTxn,
    EntityNotFound {
        entity: String,
        id: String,
    },
    InvalidListOptions {
        max: i64,
        actual: i64,
    },
    // Serialize(&'static str),
    // #[from]
    // Deserialize(#[serde_as(as = "DisplayFromStr")] JsonError),

    // --- StoreManager
    CantCreateDataStore(String),
    UnknownError(String),

    // --- Externals
    #[from]
    TimeError(#[serde_as(as = "DisplayFromStr")] Parse),
    #[from]
    JsonError(#[serde_as(as = "DisplayFromStr")] JsonError),
    #[from]
    ModqlError(#[serde_as(as = "DisplayFromStr")] modql::filter::IntoSeaError),
    #[from]
    Sqlx(#[serde_as(as = "DisplayFromStr")] sqlx::Error),
    #[from]
    SeaQueryError(#[serde_as(as = "DisplayFromStr")] sea_query::error::Error),
}

// impl From<sqlx::Error> for Error {
//     fn from(value: sqlx::Error) -> Self {
//         match value {
//             sqlx::Error::RowNotFound => todo!(),
//             _ => todo!(),
//         }
//     }
// }

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
