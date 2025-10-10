use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::account::{
        AccountFilter, AccountForCreate, AccountForUpdate, AccountIden, AccountRow,
        AccountWithCredentials,
    },
    queries::meta::{ContainsFilterQueryMeta, MutateQueryMeta, OneToManyQueryMeta, ReadQueryMeta},
    traits::meta::{ContainsFilterStoreMeta, MutateStore, OneToManyStore, ReadStore, Store},
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
// By implementing these meta traits, AccountStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for AccountStore {
    type Iden = AccountIden;
    type Row = AccountRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStore for AccountStore {
    type FilterStoreParams = AccountFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: AccountIden::Table,
            pk: AccountIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStore for AccountStore {
    type CreateStoreParams = AccountForCreate;
    type UpdateStoreParams = AccountForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: AccountIden::Table,
            pk: AccountIden::Id,
            has_audit: true,
        }
    }
}

impl OneToManyStore for AccountStore {
    type OneToManyRow = AccountWithCredentials;

    type FilterStoreParams = AccountFilter;

    fn one_to_many_meta(&self) -> OneToManyQueryMeta<Self::Iden> {
        OneToManyQueryMeta {
            single_table: AccountIden::Table,
            many_table: AccountIden::Credential,
            single_pk: AccountIden::Id,
            many_pk: AccountIden::Id,
            many_fk: AccountIden::AccountId,
            agg_alias: AccountIden::Credentials,
            has_audit: true,
        }
    }
}

impl ContainsFilterStoreMeta for AccountStore {
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: AccountIden::Table,
            col: AccountIden::Tags,
        }
    }

    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: AccountIden::Table,
            col: AccountIden::Meta,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
