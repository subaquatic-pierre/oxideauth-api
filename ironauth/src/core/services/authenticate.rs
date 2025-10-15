use crate::{
    core::error::{CoreError, CoreResult},
    store::manager::StoreManager,
};
use std::sync::Arc;

pub struct AuthService {
    sm: Arc<StoreManager>,
}

impl AuthService {
    // The constructor takes the dependencies.
    pub fn new(sm: Arc<StoreManager>) -> Self {
        Self { sm }
    }

    // Methods use the stored dependency via `self`.
    pub async fn register_user(&self, email: &str, password: &str) -> CoreResult<()> {
        // The method signature is clean and focused on its own logic.
        Ok(())
    }
}
