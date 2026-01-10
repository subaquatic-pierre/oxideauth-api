use crate::{
    core::{
        ctx::CoreCtx, error::CoreResult, models::list::ListResponse, services::auth::AuthValidator,
    },
    store::traits::dbx::DbExecutor,
};

pub trait CoreModelService {
    type CoreModel;
    type ServiceStore;
    fn store(&self) -> &Self::ServiceStore;

    fn validator<'a>(&self, ctx: &'a CoreCtx) -> AuthValidator<'a>;
}

pub trait CoreModelCreateService: CoreModelService {
    type CreateParams;

    async fn create(
        &self,
        ctx: &mut CoreCtx,
        params: Self::CreateParams,
    ) -> CoreResult<Self::CoreModel>;
}

pub trait CoreModelDescribeService: CoreModelService {
    type DescribeParams;

    async fn describe(
        &self,
        ctx: &CoreCtx,
        params: Self::DescribeParams,
    ) -> CoreResult<Self::CoreModel>;
}

pub trait CoreModelListService: CoreModelService {
    type ListParams;

    async fn list(
        &self,
        ctx: &CoreCtx,
        params: Self::ListParams,
    ) -> CoreResult<ListResponse<Self::CoreModel>>;
}

pub trait CoreModelUpdateService: CoreModelService {
    type UpdateParams;

    async fn update(
        &self,
        ctx: &CoreCtx,
        params: Self::UpdateParams,
    ) -> CoreResult<Self::CoreModel>;
}

pub trait CoreModelDeleteService: CoreModelService {
    type DeleteParams;

    async fn delete(
        &self,
        ctx: &CoreCtx,
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
