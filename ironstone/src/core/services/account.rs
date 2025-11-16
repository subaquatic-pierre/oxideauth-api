use std::sync::Arc;

use serde_json::json;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::{
            account::{Account, AccountCreateParams, AccountDescribeParams, AccountListParams},
            list::ListResponse,
        },
    },
    store::{
        contains::FilterByContains,
        ctx::StoreCtx,
        dbx::{DbExecutor, PgDbx},
        entities::account::{AccountFilter, AccountForCreate, AccountMeta},
        manager::StoreManager,
        meta::ContainsFilterStore,
        stores::account::AccountStore,
        traits::crud::*,
        utils::ListOptionsValidator,
    },
};

pub struct AccountService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
    // password_hasher: Arc<dyn PasswordHasher>, // Dependency for hashing
}

impl<D: DbExecutor> AccountService<D> {
    pub fn new(sm: Arc<StoreManager<D>>) -> Self {
        Self { sm }
    }

    pub async fn create(&self, ctx: &CoreCtx, params: AccountCreateParams) -> CoreResult<Account> {
        let store = self.store();

        if store
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

        let new_account = store.create(&ctx.into(), n_acc).await?;

        Ok(new_account.into())
    }

    pub async fn describe(
        &self,
        ctx: &CoreCtx,
        _params: AccountDescribeParams,
    ) -> CoreResult<Account> {
        let n_acc = Account::default();

        Ok(n_acc)
    }

    pub async fn list(
        &self,
        ctx: &CoreCtx,
        params: AccountListParams,
    ) -> CoreResult<ListResponse<Account>> {
        let store = self.store();

        let ctx: StoreCtx = ctx.into();

        let options = match params.options {
            Some(options) => options,
            None => ListOptionsValidator::default(),
        };

        let (tags, filter) = match params.filter {
            Some(filter) => filter.validate()?,
            None => (None, None),
        };

        if let Some(tags) = tags {
            let data = store.filter_by_tags_contain(&ctx, tags.clone()).await?;
            let total = store.count_by_tags_contain(&ctx, tags).await?;

            let accounts: Vec<Account> = data.into_iter().map(|el| el.into()).collect();
            Ok(ListResponse::new(accounts, total, options))
        } else {
            let data = store
                .list(&ctx, filter.clone(), Some(options.clone()))
                .await?;
            let total = store.count(&ctx, filter).await?;
            let accounts: Vec<Account> = data.into_iter().map(|el| el.into()).collect();
            Ok(ListResponse::new(accounts, total, options))
        }
    }

    fn store(&self) -> &AccountStore<D> {
        &self.sm.account
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
        let sm = Arc::new(StoreManager::new(dbx));
        let svc = AccountService::new(sm);
        let ctx = CoreCtx::new_test();
        let params = AccountCreateParams {
            email: "user@user.com".to_string(),
            password: "password".to_string(),
        };

        let new_acc = svc.create(&ctx, params).await?;

        let expected = Account::default();

        assert_eq!(
            new_acc.id, expected.id,
            "incorrect account id returned from AccountService.create()"
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
        let sm = Arc::new(StoreManager::new(dbx));
        let svc = AccountService::new(sm);
        let ctx = CoreCtx::new_test();
        let params = AccountCreateParams {
            email: "user@user.com".to_string(),
            password: "password".to_string(),
        };
        let new_acc = svc.create(&ctx, params).await;

        assert!(
            matches!(new_acc, Err(CoreError::AlreadyExists(..))),
            "should be CoreError::AlreadyExists"
        );

        Ok(())
    }
}
