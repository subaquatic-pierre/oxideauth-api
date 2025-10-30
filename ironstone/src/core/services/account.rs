use serde_json::json;

use crate::{
    core::{
        ctx::CoreCtx,
        dto::account::{AccountCreateParams, AccountDescribeParams},
        error::{CoreError, CoreResult},
        models::account::Account,
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        entities::account::{AccountFilter, AccountForCreate, AccountMeta},
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

    pub async fn create_account(
        &self,
        ctx: &CoreCtx,
        params: AccountCreateParams,
    ) -> CoreResult<Account> {
        if self
            .acc_store
            .get_by_email(&ctx.into(), &params.email)
            .await?
            .is_some()
        {
            return Err(CoreError::AlreadyExists("email already exists".to_string()));
        }

        let n_acc = AccountForCreate {
            email: params.email,
            name: "name".to_string(),
            description: None,
            avatar_url: None,
            enabled: false,
            verified: false,
            tags: vec![],
            meta: AccountMeta {
                schema_version: "1".to_string(),
            },
        };

        let new_account = self.acc_store.create(&ctx.into(), n_acc).await?;

        Ok(new_account.into())
    }

    pub async fn describe_account(
        &self,
        ctx: &CoreCtx,
        _params: AccountDescribeParams,
    ) -> CoreResult<Account> {
        let n_acc = Account::default();

        Ok(n_acc)
    }
}

#[cfg(test)]
mod tests {
    use std::mem;
    use std::sync::Arc;

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
        let params = AccountCreateParams {
            email: "user@user.com".to_string(),
            password: "password".to_string(),
        };

        let new_acc = acc_svc.create_account(&ctx, params).await?;

        let expected = Account::default();

        assert_eq!(
            new_acc.id, expected.id,
            "incorrect account id returned from AccountService.create_account()"
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
                let mut acc = AccountRow::default();
                acc.email = "user@user.com".to_string();
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
        let params = AccountCreateParams {
            email: "user@user.com".to_string(),
            password: "password".to_string(),
        };
        let new_acc = acc_svc.create_account(&ctx, params).await;

        assert!(
            matches!(new_acc, Err(CoreError::AlreadyExists(..))),
            "should be CoreError::AlreadyExists"
        );

        Ok(())
    }
}
