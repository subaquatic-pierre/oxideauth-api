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

pub struct GetJoinedQueryMeta<I: TableIden> {
    pub table: I,
    pub pk: I,
    pub has_audit: bool,
}

pub struct FirstQueryMeta<I: TableIden> {
    pub table: I,
    pub has_audit: bool,
}
