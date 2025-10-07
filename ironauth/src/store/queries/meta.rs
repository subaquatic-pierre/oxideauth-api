use sea_query::{Iden, IntoIden, IntoTableRef, TableRef};

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

pub struct ListQueryMeta<I: TableIden> {
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

pub struct ManyToManyReadQueryMeta<I: TableIden> {
    pub single_table: I,
    pub many_table: I,
    pub join_table: I,
    pub single_pk: I,
    pub many_pk: I,
    pub many_fk: I,
    pub join_fk: I,
    pub agg_alias: I,
    pub has_audit: bool,
}

pub struct ManyToManyMutateQueryMeta<I: TableIden> {
    pub single_table: I,
    pub many_table: I,
    pub join_table: I,
    pub single_pk: I,
    pub many_pk: I,
    pub many_fk: I,
    pub join_fk: I,
    pub agg_alias: I,
    pub has_audit: bool,
}

pub struct FirstQueryMeta<I: TableIden> {
    pub table: I,
    pub has_audit: bool,
}

pub struct CountManyQueryMeta<I: TableIden> {
    pub table: I,
    pub fk: I,
}
