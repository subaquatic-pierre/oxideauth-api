use sea_query::{Iden, IntoIden, IntoTableRef, TableRef};
use serde_json::Value;

use crate::store::traits::meta::TableIden;

/// Metadata for read-only operations like `list`, `get`, `first`, `count`.
pub struct ReadQueryMeta<I: TableIden> {
    pub table: I,
    pub pk: I,
    pub has_audit: bool,
}

/// Metadata for mutating operations like `create`, `update`, `delete`.
pub struct MutateQueryMeta<I: TableIden> {
    pub table: I,
    pub pk: I,
    pub has_audit: bool,
}

pub struct OneToManyQueryMeta<I: TableIden> {
    pub single_table: I,
    pub many_table: I,
    pub single_pk: I,
    pub many_pk: I,
    pub many_fk: I,
    pub agg_alias: I,
    pub has_audit: bool,
}

pub struct ManyToManyQueryMeta<I: TableIden> {
    pub single_table: I,
    pub many_table: I,
    pub join_table: I,
    pub join_fk: I,
    pub single_pk: I,
    pub many_pk: I,
    pub many_fk: I,
    pub agg_alias: I,
    pub has_audit: bool,
}

pub struct CountManyQueryMeta<I: TableIden> {
    pub table: I,
    pub fk: I,
}

pub enum ContainsFilter {
    Array(Vec<String>),
    Json(Value),
}

pub struct ContainsFilterQueryMeta<I: TableIden> {
    pub table: I,
    pub col: I,
}
