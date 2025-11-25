use std::sync::Arc;

use serde_json::json;
use uuid::Uuid;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::{
            account::{
                Account, AccountCreateParams, AccountDeleteParams, AccountDescribeParams,
                AccountListParams, AccountUpdateParams,
            },
            list::{ListResponse, ListResponseMeta},
        },
        traits::list::RequestListParams,
    },
    store::{
        contains::FilterByContains,
        ctx::StoreCtx,
        dbx::PgDbx,
        entities::{
            account::{AccountFilter, AccountForCreate, AccountForUpdate, AccountMeta},
            id::DbId,
        },
        error::StoreError,
        manager::StoreManager,
        meta::{ContainsFilterStore, StoreId},
        stores::account::AccountStore,
        traits::{crud::*, dbx::DbExecutor},
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
        params: AccountDescribeParams,
    ) -> CoreResult<Account> {
        let store = self.store();

        let id = self.get_account_id(&ctx, params.id, params.email).await?;

        let acc: Account = store.get(&ctx.into(), &id).await?.into();

        Ok(acc)
    }

    pub async fn list(
        &self,
        ctx: &CoreCtx,
        params: AccountListParams,
    ) -> CoreResult<ListResponse<Account>> {
        let store = self.store();

        let ctx: StoreCtx = ctx.into();

        let options = params.list_options();

        let tags_filter = params.validate_filter_tags()?;

        // NOTE: Account can never be workspace scoped, like other services such as ProjectService, because the model does not have a workspace_id field on it. This means Accounts are always global scoped. We have to find a different way to scope accounts by workspace, or only reserve account::list permission to memberships in the global namespace

        // filter by tags
        if let Some(tags) = tags_filter.tags() {
            let data = store
                .filter_by_tags_contain(&ctx, tags.clone(), Some(options.clone()))
                .await?;
            let total = store.count_by_tags_contain(&ctx, tags).await?;

            let accounts: Vec<Account> = data.into_iter().map(|el| el.into()).collect();
            return Ok(ListResponse::new(accounts, total, options));
        }

        // filter by filter
        if let Some(filter) = tags_filter.filter() {
            let filter = Some(filter);
            let data = store
                .list(&ctx, filter.clone(), Some(options.clone()))
                .await?;
            let total = store.count(&ctx, filter).await?;
            let accounts: Vec<Account> = data.into_iter().map(|el| el.into()).collect();
            return Ok(ListResponse::new(accounts, total, options));
        }

        // empty result
        Ok(ListResponse::default())
    }

    pub async fn delete(&self, ctx: &CoreCtx, params: AccountDeleteParams) -> CoreResult<Account> {
        let store = self.store();

        let id = self.get_account_id(ctx, params.id, params.email).await?;

        let deleted = store.delete(&ctx.into(), &id).await?.into();

        Ok(deleted)
    }

    pub async fn update(&self, ctx: &CoreCtx, params: AccountUpdateParams) -> CoreResult<Account> {
        let store = self.store();

        let email = params.email.clone();
        let id = self.get_account_id(ctx, params.id, params.email).await?;

        // 2. Prepare the update struct for the store layer
        let update_data = AccountForUpdate {
            email: email, // Use the new email if provided in params
            name: params.name,
            description: params.description,
            avatar_url: params.avatar_url,
            enabled: params.enabled,
            verified: params.verified,
            tags: params.tags,
            meta: params.meta,
        };

        let updated_account = store.update(&ctx.into(), &id, update_data).await?;

        Ok(updated_account.into())
    }

    async fn get_account_id(
        &self,
        ctx: &CoreCtx,
        id: Option<Uuid>,
        email: Option<String>,
    ) -> CoreResult<DbId> {
        let store = self.store();

        let id: DbId = match (id, email) {
            (Some(id), _) => id.into(),
            (None, Some(email)) => match store.get_by_email(&ctx.into(), &email).await? {
                Some(acc) => acc.id,
                None => {
                    return Err(CoreError::StoreError(StoreError::EntityNotFound {
                        entity: "account".to_string(),
                        id: email.to_string(),
                    }))
                }
            },
            (None, None) => {
                return Err(CoreError::InvalidParams(
                    "Account ID or email required".to_string(),
                ))
            }
        };

        Ok(id)
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
        let ctx = CoreCtx::new_test()?;
        let params = AccountCreateParams::default();

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
        let ctx = CoreCtx::new_test()?;
        let params = AccountCreateParams::default();
        let new_acc = svc.create(&ctx, params).await;

        assert!(
            matches!(new_acc, Err(CoreError::AlreadyExists(..))),
            "should be CoreError::AlreadyExists"
        );

        Ok(())
    }
}
