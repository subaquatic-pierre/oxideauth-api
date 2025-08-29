use sqlx::{Pool, Postgres};

pub mod crud;
pub mod dbx;
pub mod error;
pub mod init;
pub mod queries;
pub mod store;
pub mod stores;

pub use init::DbPool;
