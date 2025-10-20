use std::sync::Arc;

use serde_json::json;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::account::Account,
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        entities::account::{AccountFilter, AccountForCreate},
        manager::StoreManager,
        stores::account::AccountStore,
        traits::crud::*,
    },
};

pub struct AccountService<'a, Dbx: DbExecutor> {
    acc_store: &'a AccountStore<Dbx>,
    // password_hasher: Arc<dyn PasswordHasher>, // Dependency for hashing
}

impl<'a, Dbx: DbExecutor> AccountService<'a, Dbx> {
    pub fn new(acc_store: &'a AccountStore<Dbx>) -> Self {
        Self { acc_store }
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
            .acc_store
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

        let new_account = self.acc_store.create(&ctx.into(), n_acc).await?;

        Ok(new_account.into())
    }
}
