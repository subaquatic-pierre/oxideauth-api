use sea_query::IntoIden;
use sea_query::TableRef;
use sea_query::{Iden, IntoTableRef};

#[derive(Iden)]
pub enum CommonIden {
    Id,
    OwnerId,
    NamespaceId,
    ProjectId,
    Tags,
    Meta,
}

#[derive(Iden)]
pub enum AuditIden {
    CreatedBy,
    CreatedAt,
    UpdatedBy,
    UpdatedAt,
    // DeletedBy, // enable later if you add soft delete
    // DeletedAt,
}

#[derive(Iden)]
pub enum TableIden {
    Account,
}
