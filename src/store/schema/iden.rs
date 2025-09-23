use sea_query::IntoIden;
use sea_query::TableRef;
use sea_query::{Iden, IntoTableRef};

#[derive(Iden)]
pub enum CommonIden {
    Id,
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
}

#[derive(Iden)]
pub enum TableIden {
    Account,
    Credential,
    Membership,
    MembershipRole,
    Namespace,
    Permission,
    Project,
    Role,
    RolePermission,
}
