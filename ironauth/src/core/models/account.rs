use crate::store::entities::account::AccountRow;

pub struct Account {}

impl From<AccountRow> for Account {
    fn from(value: AccountRow) -> Self {
        Self {}
    }
}
