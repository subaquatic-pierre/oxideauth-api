use std::fmt::Display;

use derive_more::From;
use serde::Serialize;
use serde_with::{serde_as, DisplayFromStr};

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
    ListLimitOverMax {
        max: i64,
        actual: i64,
    },

    // --- StoreManager
    CantCreateDataStore(String),

    // --- Externals
    #[from]
    ModqlError(#[serde_as(as = "DisplayFromStr")] modql::filter::IntoSeaError),
    #[from]
    Sqlx(#[serde_as(as = "DisplayFromStr")] sqlx::Error),
    #[from]
    SeaQueryError(#[serde_as(as = "DisplayFromStr")] sea_query::error::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
