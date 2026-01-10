use std::sync::Arc;

use crate::{
    core::{
        ctx::CoreCtx,
        error::CoreResult,
        models::{
            list::ListResponse,
            role::{
                Role, RoleCreateParams, RoleDeleteParams, RoleDescribeParams, RoleListParams,
                RoleUpdateParams,
            },
        },
        services::{auth::AuthValidator, permission::PermissionService},
        traits::service::{
            CoreModelCreateService, CoreModelDeleteService, CoreModelDescribeService,
            CoreModelListService, CoreModelService, CoreModelUpdateService,
        },
    },
    store::{
        entities::{id::DbId, role::RoleForCreate},
        manager::StoreManager,
        stores::role::RoleStore,
        traits::{crud::*, dbx::DbExecutor},
    },
};

pub struct RoleService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
    perm_svc: PermissionService<D>,
}

impl<D: DbExecutor> CoreModelService for RoleService<D> {
    type CoreModel = Role;
    type ServiceStore = RoleStore<D>;

    fn store(&self) -> &Self::ServiceStore {
        &self.sm.role
    }

    fn validator<'a>(&self, ctx: &'a CoreCtx) -> AuthValidator<'a> {
        AuthValidator::new(ctx)
    }
}

impl<D: DbExecutor> RoleService<D> {
    pub fn new(sm: Arc<StoreManager<D>>, perm_svc: PermissionService<D>) -> Self {
        Self { sm, perm_svc }
    }
}

impl<D: DbExecutor> CoreModelCreateService for RoleService<D> {
    type CreateParams = RoleCreateParams;

    async fn create(
        &self,
        ctx: &mut CoreCtx,
        params: Self::CreateParams,
    ) -> CoreResult<Self::CoreModel> {
        let store = self.store();

        let r_create = RoleForCreate {
            workspace_id: params.workspace_id,
            name: params.name,
            description: params.description,
            tags: params.tags,
            meta: params.meta,
        };

        let row = store.create(&ctx.into(), r_create).await?;

        // TODO: Sync many-to-many permissions
        if !params.permission_ids.is_empty() {}

        self.describe(
            ctx,
            RoleDescribeParams {
                id: Some(row.id.into()),
                workspace_id: params.workspace_id,
                name: None,
            },
        )
        .await
    }
}

impl<D: DbExecutor> CoreModelDescribeService for RoleService<D> {
    type DescribeParams = RoleDescribeParams;

    async fn describe(
        &self,
        ctx: &CoreCtx,
        params: Self::DescribeParams,
    ) -> CoreResult<Self::CoreModel> {
        let store = self.store();

        // TODO: implement
        todo!()
    }
}

impl<D: DbExecutor> CoreModelListService for RoleService<D> {
    type ListParams = RoleListParams;

    async fn list(
        &self,
        ctx: &CoreCtx,
        params: Self::ListParams,
    ) -> CoreResult<ListResponse<Self::CoreModel>> {
        let store = self.store();

        // TODO: implement
        todo!()
    }
}

impl<D: DbExecutor> CoreModelUpdateService for RoleService<D> {
    type UpdateParams = RoleUpdateParams;

    async fn update(
        &self,
        ctx: &CoreCtx,
        params: Self::UpdateParams,
    ) -> CoreResult<Self::CoreModel> {
        let store = self.store();

        // TODO: implement
        todo!()
    }
}

impl<D: DbExecutor> CoreModelDeleteService for RoleService<D> {
    type DeleteParams = RoleDeleteParams;

    async fn delete(
        &self,
        ctx: &CoreCtx,
        params: Self::DeleteParams,
    ) -> CoreResult<Self::CoreModel> {
        let store = self.store();

        // TODO: implement
        todo!()
    }
}
