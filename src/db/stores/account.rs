use uuid::Uuid;

use crate::db::dbx::Dbx;

struct AccountRow {
    id: Uuid,
    name: String,
}

struct AccountCreate {
    name: String,
}

struct AccountUpdate {
    name: Option<String>,
}

pub struct AccountStore {
    db: Dbx,
}
