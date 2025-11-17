use std::sync::Arc;
use uuid::Uuid;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::{
            list::{ListResponse, RequestFilterParams},
            project::{
                Project, ProjectCreateParams, ProjectDeleteParams, ProjectDescribeParams,
                ProjectFilter, ProjectListParams, ProjectUpdateParams,
            },
            workspace::{Workspace, WorkspaceDescribeParams},
        },
        services::workspace::WorkspaceService,
    },
    store::{
        ctx::StoreCtx,
        entities::{
            id::DbId,
            project::{ProjectForCreate, ProjectForUpdate, ProjectRow},
        },
        error::StoreError,
        manager::StoreManager,
        stores::project::ProjectStore,
        traits::{crud::*, dbx::DbExecutor},
        utils::ListOptionsValidator,
    },
};

pub struct ProjectService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
    ws_svc: WorkspaceService<D>,
}

impl<D: DbExecutor> ProjectService<D> {
    pub fn new(sm: Arc<StoreManager<D>>) -> Self {
        Self {
            ws_svc: WorkspaceService::new(sm.clone()),
            sm,
        }
    }

    /// Creates a new Project, scoped to the provided workspace ID.
    pub async fn create(&self, ctx: &CoreCtx, params: ProjectCreateParams) -> CoreResult<Project> {
        let store = self.store();

        // 1. Validate and fetch the associated Workspace (ensures it exists and context is valid)
        let workspace = self.get_project_workspace(ctx, params.workspace_id).await?;

        // 2. Check if code already exists within this workspace scope
        if let Some(code) = &params.code {
            if store
                .get_by_code(&ctx.into(), code, &params.workspace_id.into())
                .await?
                .is_some()
            {
                return Err(CoreError::AlreadyExists(format!(
                    "Project code '{}' already exists in workspace {}",
                    code, params.workspace_id
                )));
            }
        }

        // 3. Map Core Params to Store ForCreate struct
        let n_project = ProjectForCreate {
            workspace_id: params.workspace_id,
            name: params.name,
            code: params.code,
            description: params.description,
            config: params.config,
            tags: params.tags,
            meta: params.meta,
        };

        // 4. Execute store creation
        let project_row = store.create(&ctx.into(), n_project).await?;

        // 5. Hydrate and return
        Project::from_row_with_workspace(project_row, workspace)
    }

    /// Retrieves a single Project, scoped by the CoreCtx workspace ID.
    pub async fn describe(
        &self,
        ctx: &CoreCtx,
        params: ProjectDescribeParams,
    ) -> CoreResult<Project> {
        let store = self.store();

        let ws_id = ctx.workspace_id();
        let workspace = self.get_project_workspace(ctx, ws_id).await?;

        let id_db = self
            .get_project_id(ctx, params.id, params.code, ws_id)
            .await?;

        // 2. Fetch Project Row (Scoped lookup is ensured by the store/SQL)
        let project_row = store.get(&ctx.into(), &id_db).await?;

        Project::from_row_with_workspace(project_row, workspace)
    }

    /// Updates an existing Project, scoped by the CoreCtx workspace ID.
    pub async fn update(&self, ctx: &CoreCtx, params: ProjectUpdateParams) -> CoreResult<Project> {
        let store = self.store();

        let ws_id = ctx.workspace_id();
        let workspace = self.get_project_workspace(ctx, ws_id).await?;

        // 1. Resolve Project ID (Scoped lookup)
        let id_db = self
            .get_project_id(ctx, params.id, params.code.clone(), ws_id)
            .await?;

        // 2. Check for new_code collision (if changing code)
        if let Some(new_code) = &params.new_code {
            if store
                .get_by_code(&ctx.into(), new_code, &ws_id.into())
                .await?
                .filter(|p| p.id != id_db) // Filter out the current project
                .is_some()
            {
                return Err(CoreError::AlreadyExists(format!(
                    "Project code '{}' already exists in workspace {}",
                    new_code, ws_id
                )));
            }
        }

        // 3. Map Core Params to Store ForUpdate struct
        let update_data = ProjectForUpdate {
            name: params.name,
            code: params.new_code, // Use the potentially changed code
            description: params.description,
            config: params.config,
            tags: params.tags,
            meta: params.meta,
        };

        // 4. Execute store update
        let project_row = store.update(&ctx.into(), &id_db, update_data).await?;

        // 5. Hydrate and return
        Project::from_row_with_workspace(project_row, workspace)
    }

    pub async fn delete(&self, ctx: &CoreCtx, params: ProjectDeleteParams) -> CoreResult<Project> {
        let store = self.store();

        let workspace = self.get_project_workspace(ctx, params.workspace_id).await?;

        let id_db = self
            .get_project_id(ctx, params.id, params.code, params.workspace_id)
            .await?;

        let deleted_row = store.delete(&ctx.into(), &id_db).await?;

        Project::from_row_with_workspace(deleted_row, workspace)
    }

    pub async fn list(
        &self,
        ctx: &CoreCtx,
        params: ProjectListParams,
    ) -> CoreResult<ListResponse<Project>> {
        let store = self.store();

        let ws_id = ctx.workspace_id();
        let workspace = self.get_project_workspace(&ctx, ws_id).await?;

        let ctx: StoreCtx = ctx.into();

        // 1. Prepare List Options and Filter
        let options = params.options.unwrap_or_else(ListOptionsValidator::default);

        // Filter must enforce workspace ID scoping
        let mut filter: ProjectFilter = params
            .filter
            .map(|f| f.validate())
            .transpose()?
            .map(|(_, f)| f)
            .flatten()
            .unwrap_or_default();

        // IMPLICIT SCOPING: Ensure the filter only returns projects in the current workspace
        filter.workspace_id = Some(
            filter
                .workspace_id
                .unwrap_or_default()
                .eq(ws_id.to_string()),
        );

        let data = store
            .list(&ctx, Some(filter.clone()), Some(options.clone()))
            .await?;
        let total = store.count(&ctx, Some(filter)).await?;

        // 3. Hydrate all rows
        let projects: Vec<Project> = data
            .into_iter()
            .map(|row| Project::from_row_with_workspace(row, workspace.clone()))
            .collect::<CoreResult<Vec<Project>>>()?; // Collect results, propagating any hydration error

        Ok(ListResponse::new(projects, total, options))
    }

    // --- HELPER METHODS ---

    fn store(&self) -> &ProjectStore<D> {
        &self.sm.project
    }

    /// Fetches the required Workspace entity for hydration and confirms context validity.
    async fn get_project_workspace(
        &self,
        ctx: &CoreCtx,
        workspace_id: Uuid,
    ) -> CoreResult<Workspace> {
        let params = WorkspaceDescribeParams {
            id: Some(workspace_id),
            slug: None,
        };

        self.ws_svc.describe(ctx, params).await
    }

    /// Resolves a Project's DbId from either Uuid or code, enforcing workspace scoping.
    async fn get_project_id(
        &self,
        ctx: &CoreCtx,
        id: Option<Uuid>,
        code: Option<String>,
        workspace_id: Uuid,
    ) -> CoreResult<DbId> {
        let store = self.store();

        let id_db: DbId = match (id, code) {
            (Some(id), _) => id.into(), // If UUID provided, use it directly (store handles scope)
            (None, Some(code)) => {
                // If code provided, lookup by code and ensure it's in the correct workspace
                match store
                    .get_by_code(&ctx.into(), &code, &workspace_id.into())
                    .await?
                {
                    Some(project_row) => project_row.id,
                    None => {
                        return Err(CoreError::StoreError(StoreError::EntityNotFound {
                            entity: "project".to_string(),
                            id: format!("code:'{}' in ws:'{}'", code, workspace_id),
                        }))
                    }
                }
            }
            (None, None) => {
                return Err(CoreError::InvalidParams(
                    "Project ID or code required for operation".to_string(),
                ))
            }
        };

        Ok(id_db)
    }
}
