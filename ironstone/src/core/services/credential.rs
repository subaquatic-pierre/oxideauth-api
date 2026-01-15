use crate::core::{
    ctx::CoreCtx,
    error::CoreResult,
    models::{
        credential::{
            Credential, CredentialCreateParams, CredentialDeleteParams, CredentialDescribeParams,
            CredentialListParams, CredentialUpdateParams,
        },
        list::ListResponse,
    },
    services::{account::AccountService, auth::AuthValidator, workspace::WorkspaceService},
    traits::service::{
        CoreModelCreateService, CoreModelDeleteService, CoreModelDescribeService,
        CoreModelListService, CoreModelService, CoreModelUpdateService,
    },
};
use crate::store::{
    entities::credential::{CredentialForCreate, CredentialForUpdate},
    manager::StoreManager,
    stores::credential::CredentialStore,
    traits::{crud::*, dbx::DbExecutor},
};
use std::sync::Arc;

pub struct CredentialService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
    ws_svc: WorkspaceService<D>,
}

impl<D: DbExecutor> CredentialService<D> {
    pub fn new(sm: Arc<StoreManager<D>>, ws_svc: WorkspaceService<D>) -> Self {
        Self { sm, ws_svc }
    }
}

// --- Base Model Service ---
impl<D: DbExecutor> CoreModelService<D> for CredentialService<D> {
    type CoreModel = Credential;
    type ServiceStore = CredentialStore<D>;

    fn store(&self) -> &Self::ServiceStore {
        &self.sm.credential
    }

    fn ws_svc(&self) -> &WorkspaceService<D> {
        &self.ws_svc
    }
}

// --- Create ---
impl<D: DbExecutor> CoreModelCreateService<D> for CredentialService<D> {
    type CreateParams = CredentialCreateParams;
    const CREATE_PERMISSION: &'static str = "credential:create";

    async fn create(
        &self,
        ctx: &mut CoreCtx,
        params: Self::CreateParams,
    ) -> CoreResult<Self::CoreModel> {
        // let store = self.store();

        // let for_create = CredentialForCreate {
        //     account_id: params.account_id,
        //     workspace_id: params.workspace_id,
        //     kind: params.kind,
        //     provider: params.provider,
        //     status: params.status,
        //     provider_id: params.provider_id,
        //     email: params.email,
        //     secret: params.secret,
        //     last_used_at: params.last_used_at,
        //     tags: params.tags,
        //     meta: params.meta,
        // };

        // let row = store.create(&ctx.into(), for_create).await?;

        // // Use describe to return fully hydrated model
        // self.describe(
        //     ctx,
        //     CredentialDescribeParams {
        //         id: Some(row.id.into()),
        //         account_id: params.account_id,
        //         workspace_id: params.workspace_id,
        //         provider_id: None,
        //         email: None,
        //     },
        // )
        // .await
        todo!()
    }
}

// --- Describe (with Hydration) ---
impl<D: DbExecutor> CoreModelDescribeService<D> for CredentialService<D> {
    type DescribeParams = CredentialDescribeParams;
    const DESCRIBE_PERMISSION: &'static str = "credential:describe";

    async fn describe(
        &self,
        ctx: &mut CoreCtx,
        params: Self::DescribeParams,
    ) -> CoreResult<Self::CoreModel> {
        // let store = self.store();

        // // 1. Resolve ID and fetch row
        // // Note: Real implementation would handle lookup by email/provider_id if id is None
        // let db_id: DbId = params.id.expect("ID required for boilerplate").into();
        // let row = store.get(&ctx.into(), &db_id).await?;

        // // 2. Hydrate related entities via Services
        // let account_svc = AccountService::new(self.sm.clone());
        // let workspace_svc = WorkspaceService::new(self.sm.clone());

        // let account = account_svc.describe(ctx, row.account_id.into()).await?;
        // let workspace = workspace_svc.describe(ctx, row.workspace_id.into()).await?;

        // // 3. Construct Core Model
        // Credential::from_row_with_entities(row, account, workspace)
        todo!()
    }
}

// --- List ---
impl<D: DbExecutor> CoreModelListService<D> for CredentialService<D> {
    type ListParams = CredentialListParams;
    const LIST_PERMISSION: &'static str = "credential:list";

    async fn list(
        &self,
        ctx: &mut CoreCtx,
        params: Self::ListParams,
    ) -> CoreResult<ListResponse<Self::CoreModel>> {
        // let store = self.store();
        // let options = params.list_options();
        // let filter = params.filter.map(|f| f.0);

        // let rows = store
        //     .list(&ctx.into(), filter, Some(options.clone()))
        //     .await?;
        // let total = store.count(&ctx.into(), None).await?; // Simplified

        // let mut credentials = Vec::new();
        // for row in rows {
        //     // Hydrate each for the list response
        //     if let Ok(c) = self
        //         .describe(
        //             ctx,
        //             CredentialDescribeParams {
        //                 id: Some(row.id.into()),
        //                 account_id: row.account_id.into(),
        //                 workspace_id: row.workspace_id.into(),
        //                 provider_id: None,
        //                 email: None,
        //             },
        //         )
        //         .await
        //     {
        //         credentials.push(c);
        //     }
        // }

        // Ok(ListResponse::new(credentials, total, options))
        todo!()
    }
}

// --- Update ---
impl<D: DbExecutor> CoreModelUpdateService<D> for CredentialService<D> {
    type UpdateParams = CredentialUpdateParams;
    const UPDATE_PERMISSION: &'static str = "credential:update";

    async fn update(
        &self,
        ctx: &mut CoreCtx,
        params: Self::UpdateParams,
    ) -> CoreResult<Self::CoreModel> {
        //     let store = self.store();
        //     let db_id: DbId = params.id.expect("ID required for update").into();

        //     let for_update = CredentialForUpdate {
        //         kind: params.kind,
        //         provider: params.provider,
        //         status: params.status,
        //         provider_id: params.new_provider_id,
        //         email: params.new_email,
        //         secret: params.secret,
        //         last_used_at: params.last_used_at,
        //         tags: params.tags,
        //         meta: params.meta,
        //     };

        //     store.update(&ctx.into(), &db_id, for_update).await?;

        //     self.describe(
        //         ctx,
        //         CredentialDescribeParams {
        //             id: Some(db_id.into()),
        //             account_id: params.account_id,
        //             workspace_id: params.workspace_id,
        //             provider_id: None,
        //             email: None,
        //         },
        //     )
        //     .await
        todo!()
    }
}

// --- Delete ---
impl<D: DbExecutor> CoreModelDeleteService<D> for CredentialService<D> {
    type DeleteParams = CredentialDeleteParams;
    const DELETE_PERMISSION: &'static str = "credential:delete";

    async fn delete(
        &self,
        ctx: &mut CoreCtx,
        params: Self::DeleteParams,
    ) -> CoreResult<Self::CoreModel> {
        // let store = self.store();
        // let db_id: DbId = params.id.expect("ID required for delete").into();

        // let entity = self
        //     .describe(
        //         ctx,
        //         CredentialDescribeParams {
        //             id: Some(db_id.into()),
        //             account_id: params.account_id,
        //             workspace_id: params.workspace_id,
        //             provider_id: None,
        //             email: None,
        //         },
        //     )
        //     .await?;

        // store.delete(&ctx.into(), &db_id).await?;

        // Ok(entity)
        todo!()
    }
}
