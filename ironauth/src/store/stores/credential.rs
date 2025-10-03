use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    queries::meta::{MutateQueryMeta, ReadQueryMeta},
    schema::credential::{
        CredentialFilter, CredentialForCreate, CredentialForUpdate, CredentialIden, CredentialRow,
    },
    traits::{
        crud::{
            Countable, Creatable, CreatableMany, Deletable, DeletableMany, Firstable, Listable,
            Readable, Updatable, UpdatableMany,
        },
        meta::{MutableMeta, ReadableMeta, Store},
    },
};

/// The struct for our Credential store, holding the database connection wrapper.
pub struct CredentialStore {
    db: Arc<Dbx>,
}

impl CredentialStore {
    /// Creates a new `CredentialStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// These implementations provide the core metadata for the store.

impl Store for CredentialStore {
    type Iden = CredentialIden;
    type Row = CredentialRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadableMeta for CredentialStore {
    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: CredentialIden::Table,
            pk: CredentialIden::Id,
            has_audit: true,
        }
    }
}

impl MutableMeta for CredentialStore {
    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: CredentialIden::Table,
            pk: CredentialIden::Id,
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

impl Creatable for CredentialStore {
    type CreateStoreParams = CredentialForCreate;
}

impl Readable for CredentialStore {}

impl Listable for CredentialStore {
    type FilterStoreParams = CredentialFilter;
}

impl Updatable for CredentialStore {
    type UpdateStoreParams = CredentialForUpdate;
}

impl Deletable for CredentialStore {}

impl CreatableMany for CredentialStore {}

impl UpdatableMany for CredentialStore {
    type UpdateStoreParams = CredentialForUpdate;
}

impl DeletableMany for CredentialStore {}

impl Firstable for CredentialStore {}

impl Countable for CredentialStore {}

// -----------------------------------------------------------------------------
// endregion: --- Functional Trait Implementations
