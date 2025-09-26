use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::membership::{
        MembershipCreate, MembershipFilter, MembershipIden, MembershipRow, MembershipUpdate,
    },
    traits::{
        crud::{
            Creatable, DeletableMany, Deletable	, Readable, Listable, UpdatableMany,
            Updatable,
        },
        meta::Store,
    },
};

pub struct MembershipStore {
    db: Arc<Dbx>,
}

impl MembershipStore {
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

impl Store for MembershipStore {
    type TableIden = MembershipIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = MembershipIden::Table;
    const TABLE_PK: Self::TableIden = MembershipIden::Id;

    type IdKind = Uuid;

    type Row = MembershipRow;

    fn db(&self) -> &Dbx {
        &self.db
    }

    fn has_audit_fields() -> bool {
        true
    }
}

impl Creatable for MembershipStore {
    type CreateStoreParams = MembershipCreate;
}

impl Readable for MembershipStore {}

impl Listable for MembershipStore {
    type FilterStoreParams = MembershipFilter;
}

impl Updatable for MembershipStore {
    type UpdateStoreParams = MembershipUpdate;
}

impl DeletableMany for MembershipStore {}

impl UpdatableMany for MembershipStore {
    type UpdateStoreParams = MembershipUpdate;
}

impl Deletable	 for MembershipStore {}
