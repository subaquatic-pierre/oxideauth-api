use std::sync::Arc;

use serde_json::json;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::account::Account,
    },
    store::{
        entities::account::{AccountFilter, AccountForCreate},
        manager::StoreManager,
        traits::crud::*,
    },
};

pub struct AccountService {
    sm: Arc<StoreManager>,
    // password_hasher: Arc<dyn PasswordHasher>, // Dependency for hashing
}

impl AccountService {
    pub fn new(sm: Arc<StoreManager>) -> Self {
        Self { sm }
    }

    pub async fn register(
        &self,
        ctx: &CoreCtx,
        email: &str,
        password: &str,
    ) -> CoreResult<Account> {
        let filter: AccountFilter = json!({
            "email": email.to_string()
        })
        .try_into()?;

        if !self
            .sm
            .account
            .list(&ctx.into(), Some(filter), None)
            .await?
            .is_empty()
        {
            return Err(CoreError::AlreadyExists("email already exists".to_string()));
        }

        let n_acc = AccountForCreate {
            email: todo!(),
            name: todo!(),
            description: todo!(),
            avatar_url: todo!(),
            enabled: todo!(),
            verified: todo!(),
            tags: todo!(),
            meta: todo!(),
        };

        let new_account = self.sm.account.create(&ctx.into(), n_acc).await?;

        Ok(new_account.into())
    }
}
