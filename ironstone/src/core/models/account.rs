use uuid::Uuid;

use crate::store::entities::account::AccountRow;

pub struct Account {
    pub id: Uuid,
}

impl From<AccountRow> for Account {
    fn from(value: AccountRow) -> Self {
        Self {
            id: value.id.into(),
        }
    }
}
