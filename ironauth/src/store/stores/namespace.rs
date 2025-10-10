use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::namespace::{
        NamespaceFilter, NamespaceForCreate, NamespaceForUpdate, NamespaceIden, NamespaceRow,
        NamespaceWithProjects,
    },
    queries::meta::{ContainsFilterQueryMeta, MutateQueryMeta, OneToManyQueryMeta, ReadQueryMeta},
    traits::meta::{ContainsFilterStore, MutateStore, OneToManyStore, ReadStore, Store},
};

/// The struct for our Namespace store, holding the database connection wrapper.
pub struct NamespaceStore {
    db: Arc<Dbx>,
}

impl NamespaceStore {
    /// Creates a new `NamespaceStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, NamespaceStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for NamespaceStore {
    type Iden = NamespaceIden;
    type Row = NamespaceRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStore for NamespaceStore {
    type FilterStoreParams = NamespaceFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: NamespaceIden::Table,
            pk: NamespaceIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStore for NamespaceStore {
    type CreateStoreParams = NamespaceForCreate;
    type UpdateStoreParams = NamespaceForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: NamespaceIden::Table,
            pk: NamespaceIden::Id,
            has_audit: true,
        }
    }
}

impl OneToManyStore for NamespaceStore {
    type OneToManyRow = NamespaceWithProjects;

    type FilterStoreParams = NamespaceFilter;

    fn one_to_many_meta(&self) -> OneToManyQueryMeta<Self::Iden> {
        OneToManyQueryMeta {
            single_table: NamespaceIden::Table,
            many_table: NamespaceIden::Project,
            single_pk: NamespaceIden::Id,
            many_pk: NamespaceIden::Id,
            many_fk: NamespaceIden::NamespaceId,
            agg_alias: NamespaceIden::Projects,
            has_audit: true,
        }
    }
}

impl ContainsFilterStore for NamespaceStore {
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: NamespaceIden::Table,
            col: NamespaceIden::Tags,
        }
    }

    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: NamespaceIden::Table,
            col: NamespaceIden::Meta,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations
