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
            CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, UpdateManyStore,
            UpdateStore,
        },
        meta::BaseMetaStore,
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

impl BaseMetaStore for MembershipStore {
    type TableIden = MembershipIden;

    /// Static table identifiers used in SQL queries.
    const TABLE_NAME: Self::TableIden = MembershipIden::TableName;
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

impl CreateStore for MembershipStore {
    type CreateStoreParams = MembershipCreate;
}

impl GetStore for MembershipStore {}

impl ListStore for MembershipStore {
    type FilterStoreParams = MembershipFilter;
}

impl UpdateStore for MembershipStore {
    type UpdateStoreParams = MembershipUpdate;
}

impl DeleteManyStore for MembershipStore {}

impl UpdateManyStore for MembershipStore {
    type UpdateStoreParams = MembershipUpdate;
}

impl DeleteStore for MembershipStore {}
