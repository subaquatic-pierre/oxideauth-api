use std::sync::Arc;

use crate::{
    core::error::{CoreError, CoreResult},
    store::{
        entities::account::{AccountFilter, AccountForCreate},
        manager::StoreManager,
        traits::crud::List,
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
        let filter = AccountFilter {
            email: email.to_string(),
            ..Default::default()
        };

        if let Some(acc) = self.sm.account.list(&ctx.into(), filter, None).await? {
            return Err(CoreError::AlreadyExists("email already exists"));
        }

        // // 2. Perform its own logic: hashing the password
        // let password_hash = self.password_hasher.hash(password)?;

        // 3. Delegate to the store to create the new account and credential
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

        Ok(new_account)
    }
}
