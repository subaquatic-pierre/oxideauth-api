use std::sync::Arc;

use serde_json::json;

use crate::{
    cache::{manager::CacheManager, stores::membership::MembershipCache, traits::CacheExecutor},
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::{
            account::{Account, AccountDescribeParams},
            list::RequestFilterParams,
            membership::{
                CachedMembership, Membership, MembershipCreateParams, MembershipDescribeParams,
            },
            role::{Role, RoleFilter, RoleListParams},
            workspace::WorkspaceDescribeParams,
        },
        services::{
            account::AccountService, auth::AuthValidator, role::RoleService,
            workspace::WorkspaceService,
        },
        traits::service::{
            CoreModelCreateService, CoreModelDescribeService, CoreModelListService,
            CoreModelService,
        },
    },
    store::{
        dbx::PgDbx,
        entities::{
            account::{AccountFilter, AccountForCreate, AccountMeta},
            id::DbId,
            membership::{MembershipForCreate, MembershipRow, MembershipWithRoles},
        },
        join::GetManyToMany,
        manager::StoreManager,
        stores::membership::MembershipStore,
        traits::{crud::*, dbx::DbExecutor},
    },
};

pub struct MembershipService<D: DbExecutor, C: CacheExecutor> {
    sm: Arc<StoreManager<D>>,
    cm: Arc<CacheManager<C>>,
    ws_svc: WorkspaceService<D>,
    acc_svc: AccountService<D>,
    role_svc: RoleService<D>,
}

impl<D: DbExecutor, C: CacheExecutor> CoreModelService for MembershipService<D, C> {
    type CoreModel = Membership;

    type ServiceStore = MembershipStore<D>;

    fn store(&self) -> &Self::ServiceStore {
        &self.sm.membership
    }

    fn validator<'a>(&self, ctx: &'a CoreCtx) -> AuthValidator<'a> {
        AuthValidator::new(ctx)
    }
}

impl<D: DbExecutor, C: CacheExecutor> MembershipService<D, C> {
    pub fn new(
        sm: Arc<StoreManager<D>>,
        cm: Arc<CacheManager<C>>,
        ws_svc: WorkspaceService<D>,
        acc_svc: AccountService<D>,
        role_svc: RoleService<D>,
    ) -> Self {
        Self {
            sm,
            cm,
            ws_svc,
            acc_svc,
            role_svc,
        }
    }

    pub fn get_cached(&self) -> Option<CachedMembership> {
        let cache = self.cache();
        None
    }

    fn cache(&self) -> &MembershipCache<C> {
        &self.cm.membership
    }
}

impl<D: DbExecutor, C: CacheExecutor> CoreModelCreateService for MembershipService<D, C> {
    type CreateParams = MembershipCreateParams;

    /// Creates a membership and optionally associates it with roles
    async fn create(
        &self,
        ctx: &mut CoreCtx,
        params: MembershipCreateParams,
    ) -> CoreResult<Membership> {
        let store = self.store();

        let m_create = MembershipForCreate {
            account_id: params.account_id,
            workspace_id: params.workspace_id,
            scope: params.scope,
            status: params.status,
            project_id: params.project_id,
            tags: params.tags,
            meta: params.meta,
        };

        // TODO: Ensure membership doesn't already exist for given account_id and workspace_id
        // check database constraints

        let membership_row = store.create(&ctx.into(), m_create).await?;

        // TODO: assign roles if present on params
        if !params.role_ids.is_empty() {}

        self.describe(
            ctx,
            MembershipDescribeParams {
                id: membership_row.id.into(),
                workspace_id: membership_row.workspace_id.into(),
            },
        )
        .await
    }
}

impl<D: DbExecutor, C: CacheExecutor> CoreModelDescribeService for MembershipService<D, C> {
    type DescribeParams = MembershipDescribeParams;

    async fn describe(
        &self,
        ctx: &mut CoreCtx,
        params: MembershipDescribeParams,
    ) -> CoreResult<Membership> {
        let store = self.store();
        let db_id: DbId = params.id.into();

        // Get Membership with Roles (Join query)
        let membership: MembershipRow = store.get(&ctx.into(), &db_id).await?;

        // Hydrate related Account and Workspace
        let account = self
            .acc_svc
            .describe(
                ctx,
                AccountDescribeParams {
                    email: None,
                    id: Some(membership.account_id.into()),
                },
            )
            .await?;

        let workspace = self
            .ws_svc
            .describe(
                ctx,
                WorkspaceDescribeParams {
                    id: Some(membership.workspace_id.into()),
                    slug: None,
                },
            )
            .await?;

        let role_filter: RoleFilter = json!({ "name": "list-role-b" }).try_into()?;
        let filter = RequestFilterParams::new(None, Some(role_filter));

        let roles = self
            .role_svc
            .list(
                ctx,
                RoleListParams {
                    filter: Some(filter),
                    options: None,
                },
            )
            .await?;

        let account = self
            .acc_svc
            .describe(
                ctx,
                AccountDescribeParams {
                    email: None,
                    id: Some(membership.account_id),
                },
            )
            .await?;

        // let roles = membership_with_roles.roles.into_iter().map(|el| Role {
        //     id: membership.id.into(),
        //     workspace: workspace.clone(),
        //     name: todo!(),
        //     description: todo!(),
        //     permissions: todo!(),
        //     tags: todo!(),
        //     meta: todo!(),
        //     audit: todo!(),
        // });

        // Membership::from_row_with_entities(
        //     row_with_roles.membership,
        //     row_with_roles.roles,
        //     account,
        //     workspace,
        // )
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::mem;
    use std::sync::Arc;

    use super::*;
    use crate::{
        cache::redis::RedisChx,
        config::Config,
        core::services::factory::ServiceFactory,
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
            stores::membership::MembershipStore,
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
    async fn test_create_membership_success() -> CoreResult<()> {
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

        let config = Config::test_config();

        // build store manager
        let dbx = Arc::new(MockDbxAccountRegister);
        let sm = Arc::new(StoreManager::new(dbx));

        // build cache manager
        let redis_cache = Arc::new(RedisChx::new(&config.redis_url).await);
        let cm = Arc::new(CacheManager::new(redis_cache));
        let svc_factory = ServiceFactory::new(sm, cm);
        let svc = svc_factory.membership();

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

        let config = Config::test_config();

        // build store manager
        let dbx = Arc::new(MockDbxAccountRegister);
        let sm = Arc::new(StoreManager::new(dbx));

        // build cache manager
        let redis_cache = Arc::new(RedisChx::new(&config.redis_url).await);
        let cm = Arc::new(CacheManager::new(redis_cache));
        let svc_factory = ServiceFactory::new(sm, cm);
        let svc = svc_factory.membership();

        Ok(())
    }
}
