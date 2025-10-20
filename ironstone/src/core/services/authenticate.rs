use crate::{
    core::error::{CoreError, CoreResult},
    store::{dbx::PgDbx, manager::StoreManager},
};
use std::sync::Arc;

pub struct AuthenticateService {
    sm: Arc<StoreManager<PgDbx>>,
}

impl AuthenticateService {
    // The constructor takes the dependencies.
    pub fn new(sm: Arc<StoreManager<PgDbx>>) -> Self {
        Self { sm }
    }

    // Methods use the stored dependency via `self`.
    pub async fn register_user(&self, email: &str, password: &str) -> CoreResult<()> {
        // The method signature is clean and focused on its own logic.
        Ok(())
    }
}
