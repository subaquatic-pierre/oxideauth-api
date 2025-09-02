use sea_query::{Iden, IntoIden, TableRef};

#[derive(Iden)]
pub enum CommonIden {
    Id,
    OwnerId,
}

#[derive(Iden)]
pub enum AuditIden {
    Cid,
    Ctime,
    Mid,
    Mtime,
}
