use uuid::Uuid;

use crate::{
    core::{
        ctx::CoreCtx,
        error::CoreResult,
        models::{list::ListResponse, workspace::Workspace},
        services::auth::AuthValidator,
    },
    store::{ctx::StoreCtx, traits::dbx::DbExecutor},
};

pub trait CoreModelService {
    type CoreModel;
    type ServiceStore;
    fn store(&self) -> &Self::ServiceStore;

    fn validator<'a>(&self, ctx: &'a CoreCtx) -> AuthValidator<'a>;
    async fn get_workspace(&self, ctx: &mut CoreCtx, workspace_id: Uuid) -> CoreResult<Workspace>;

    async fn scope_and_validate_ctx(
        &self,
        ctx: &mut CoreCtx,
        workspace_id: Uuid,
        perms: &[&str],
    ) -> CoreResult<(StoreCtx, Workspace)>;
}

pub trait CoreModelCreateService: CoreModelService {
    type CreateParams;
    const CREATE_PERMISSION: &'static str;

    async fn create(
        &self,
        ctx: &mut CoreCtx,
        params: Self::CreateParams,
    ) -> CoreResult<Self::CoreModel>;
}

pub trait CoreModelDescribeService: CoreModelService {
    type DescribeParams;
    const DESCRIBE_PERMISSION: &'static str;

    async fn describe(
        &self,
        ctx: &mut CoreCtx,
        params: Self::DescribeParams,
    ) -> CoreResult<Self::CoreModel>;
}

pub trait CoreModelListService: CoreModelService {
    type ListParams;
    const LIST_PERMISSION: &'static str;

    async fn list(
        &self,
        ctx: &mut CoreCtx,
        params: Self::ListParams,
    ) -> CoreResult<ListResponse<Self::CoreModel>>;
}

pub trait CoreModelUpdateService: CoreModelService {
    type UpdateParams;
    const UPDATE_PERMISSION: &'static str;

    async fn update(
        &self,
        ctx: &mut CoreCtx,
        params: Self::UpdateParams,
    ) -> CoreResult<Self::CoreModel>;
}

pub trait CoreModelDeleteService: CoreModelService {
    type DeleteParams;
    const DELETE_PERMISSION: &'static str;

    async fn delete(
        &self,
        ctx: &mut CoreCtx,
        params: Self::DeleteParams,
    ) -> CoreResult<Self::CoreModel>;
}

/// A convenience trait that groups all CRUD operations.
pub trait CoreModelCrudService:
    CoreModelCreateService
    + CoreModelDescribeService
    + CoreModelListService
    + CoreModelUpdateService
    + CoreModelDeleteService
{
}

// Blanket implementation for any service that meets all criteria
impl<T> CoreModelCrudService for T where
    T: CoreModelCreateService
        + CoreModelDescribeService
        + CoreModelListService
        + CoreModelUpdateService
        + CoreModelDeleteService
{
}
