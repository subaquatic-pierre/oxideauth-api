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

        let n_acc = AccountForCreate::default();

        let new_account = self.acc_store.create(&ctx.into(), n_acc).await?;

        Ok(new_account.into())
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use super::*;
    use crate::{
        create_dbx_mock_unsafe,
        dev::init::init_test,
        store::{
            ctx::StoreCtx,
            entities::{
                account::AccountRow,
                credential::{CredentialForCreate, CredentialProvider},
            },
            error::StoreError,
            meta::StoreId,
            stores::account::AccountStore,
            traits::{contains::FilterByContains, crud::*, join::GetOneToMany},
        },
    };
    use anyhow::Result;
    use modql::filter::{ListOptions, OpValsString};
    use serde_json::json;
    use serial_test::serial;
    use uuid::Uuid;

    #[tokio::test]
    #[serial]
    async fn test_create_account_success() -> CoreResult<()> {
        create_dbx_mock_unsafe!(
            MockDbxAccountRegister,
            fetch_one: {
                let acc = AccountRow::default();
                let result = unsafe { mem::transmute_copy::<AccountRow, O>(&acc) };
                mem::forget(acc);
                Ok(result)
            },
            fetch_optional: { Ok(None) },
            fetch_all: { Ok(vec![]) },
            execute: { Ok(1) }
        );

        let dbx = Arc::new(MockDbxAccountRegister);
        let acc_store = AccountStore::new(dbx);
        let acc_svc = AccountService::new(&acc_store);
        let ctx = CoreCtx::new_test();
        let new_acc = acc_svc.register(&ctx, "user@user.com", "password").await?;

        let expected = Account::default();

        assert_eq!(
            new_acc.id, expected.id,
            "incorrect account id returned from AccountService.register()"
        );
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_create_account_error() -> CoreResult<()> {
        create_dbx_mock_unsafe!(
            MockDbxAccountRegister,
            fetch_one: {
                let acc = AccountRow::default();
                let result = unsafe { mem::transmute_copy::<AccountRow, O>(&acc) };
                mem::forget(acc);
                Ok(result)
            },
            fetch_optional: { Ok(None) },
            fetch_all: {
                let acc = AccountRow::default();
                let result = unsafe { mem::transmute_copy::<AccountRow, O>(&acc) };
                mem::forget(acc);
                Ok(vec![result])
            },
            execute: { Ok(1) }
        );
        let dbx = Arc::new(MockDbxAccountRegister);
        let acc_store = AccountStore::new(dbx);
        let acc_svc = AccountService::new(&acc_store);
        let ctx = CoreCtx::new_test();
        let new_acc = acc_svc.register(&ctx, "user@user.com", "password").await;

        assert!(
            matches!(new_acc, Err(CoreError::AlreadyExists(..))),
            "should be CoreError::AlreadyExists"
        );
        let expected = Account::default();
        // assert!(matches!(new_acc, Ok(expected)), "should not be OK");

        Ok(())
    }
}
