use crate::db::{dbx::Dbx, error::Result, stores::account::AccountStore};

pub struct DataStore {
    dbx: Dbx,

    // --- specific table stores
    account: AccountStore,
}

impl DataStore {
    pub fn new() -> Result<Self> {
        todo!()
    }
}
