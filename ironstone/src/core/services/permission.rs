use std::sync::Arc;

use crate::{
    core::{
        ctx::CoreCtx,
        error::CoreResult,
        models::{
            list::ListResponse,
            permission::{
                Permission, PermissionCreateParams, PermissionDescribeParams, PermissionListParams,
                PermissionUpdateParams,
            },
            role::Role,
        },
        services::auth::AuthValidator,
        traits::service::{
            CoreModelCreateService, CoreModelDeleteService, CoreModelDescribeService,
            CoreModelListService, CoreModelService, CoreModelUpdateService,
        },
    },
    store::{
        manager::StoreManager,
        stores::{permission::PermissionStore, role::RoleStore},
        traits::dbx::DbExecutor,
    },
};

pub struct PermissionService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
}

impl<D: DbExecutor> CoreModelService for PermissionService<D> {
    type CoreModel = Permission;
    type ServiceStore = PermissionStore<D>;

    fn store(&self) -> &Self::ServiceStore {
        &self.sm.permission
    }

    fn validator<'a>(&self, ctx: &'a CoreCtx) -> AuthValidator<'a> {
        AuthValidator::new(ctx)
    }
}

impl<D: DbExecutor> PermissionService<D> {
    pub fn new(sm: Arc<StoreManager<D>>) -> Self {
        Self { sm }
    }
}

impl<D: DbExecutor> CoreModelCreateService for PermissionService<D> {
    type CreateParams = PermissionCreateParams;

    async fn create(
        &self,
        ctx: &mut CoreCtx,
        params: Self::CreateParams,
    ) -> CoreResult<Self::CoreModel> {
        let store = self.store();
        // TODO: implement
        todo!()
    }
}
impl<D: DbExecutor> CoreModelDescribeService for PermissionService<D> {
    type DescribeParams = PermissionDescribeParams;

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

impl<D: DbExecutor> CoreModelListService for PermissionService<D> {
    type ListParams = PermissionListParams;

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

impl<D: DbExecutor> CoreModelUpdateService for PermissionService<D> {
    type UpdateParams = PermissionUpdateParams;

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
impl<D: DbExecutor> CoreModelDeleteService for PermissionService<D> {
    type DeleteParams = PermissionCreateParams;

    async fn delete(
        &self,
        ctx: &CoreCtx,
        params: Self::DeleteParams,
    ) -> CoreResult<Self::CoreModel> {
        // TODO: implement
        todo!()
    }
}
