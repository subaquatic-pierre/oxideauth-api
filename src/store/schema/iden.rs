use sea_query::Iden;

#[derive(Iden)]
pub enum CommonIden {
    Id,
    OwnerId,
    NamespaceId,
    ProjectId,
    Version,
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
