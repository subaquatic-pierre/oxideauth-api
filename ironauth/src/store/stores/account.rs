use std::sync::Arc;

use modql::SIden;
use sea_query::Iden;
use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    schema::account::{AccountFilter, AccountForCreate, AccountForUpdate, AccountIden, AccountRow},
    traits::{
        crud::{
            Create, CreateMany, Delete, DeleteMany, Get, GetCount, GetFirst, List, Update,
            UpdateMany,
        },
        meta::{MutateStoreMeta, ReadStoreMeta, Store},
    },
};
/// The struct for our Account store, holding the database connection wrapper.
pub struct AccountStore {
    db: Arc<Dbx>,
}

impl AccountStore {
    /// Creates a new `AccountStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// These implementations provide the core metadata for the store.

impl Store for AccountStore {
    type Iden = AccountIden;
    type Row = AccountRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStoreMeta for AccountStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: AccountIden::Table,
            pk: AccountIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStoreMeta for AccountStore {
    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: AccountIden::Table,
            pk: AccountIden::Id,
            has_audit: true,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations

// region:    --- Functional Trait Implementations
// -----------------------------------------------------------------------------
// With the metadata defined above, these implementations are now very concise.
// We only need to specify the associated types for params (Create, Update, Filter).
// The actual method logic is handled by the default implementations in your traits.

impl Create for AccountStore {
    type CreateStoreParams = AccountForCreate;
}

impl Get for AccountStore {}

impl List for AccountStore {
    type FilterStoreParams = AccountFilter;
}

impl Update for AccountStore {
    type UpdateStoreParams = AccountForUpdate;
}

impl Delete for AccountStore {}

impl CreateMany for AccountStore {}

impl UpdateMany for AccountStore {
    type UpdateStoreParams = AccountForUpdate;
}

impl DeleteMany for AccountStore {}

impl GetFirst for AccountStore {}

impl GetCount for AccountStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
