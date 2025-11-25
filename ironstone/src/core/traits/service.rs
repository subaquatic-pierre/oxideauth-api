use crate::{
    core::{ctx::CoreCtx, services::auth::AuthValidator},
    store::traits::dbx::DbExecutor,
};

pub trait CoreService {
    type ServiceStore;
    fn store(&self) -> &Self::ServiceStore;

    fn validator<'a>(&self, ctx: &'a CoreCtx) -> AuthValidator<'a>;
}
