use std::sync::Arc;

use sea_query::{IntoIden, TableRef};
use sqlx::prelude::FromRow;
use uuid::Uuid;

use crate::store::{
    dbx::Dbx,
    schema::{
        iden::TableIden,
        membership::{MembershipCreate, MembershipFilter, MembershipRow, MembershipUpdate},
    },
    stores::base::{
        CreateStore, DeleteManyStore, DeleteStore, GetStore, ListStore, MetaStore, UpdateManyStore,
        UpdateStore,
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

impl MetaStore for MembershipStore {
    type Id = Uuid;
    type Row = MembershipRow;

    const TABLE: TableIden = TableIden::Membership;
    const HAS_AUDIT_FIELDS: bool = true;

    fn db(&self) -> &Dbx {
        &self.db
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
