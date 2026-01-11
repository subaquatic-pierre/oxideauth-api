use std::sync::Arc;

use serde_json::json;
use uuid::Uuid;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::{
            account::Account,
            list::ListResponse,
            workspace::{
                Workspace, WorkspaceCreateParams, WorkspaceDeleteParams, WorkspaceDescribeParams,
                WorkspaceListParams, WorkspaceUpdateParams,
            },
        },
        traits::list::RequestListParams,
    },
    store::{
        ctx::StoreCtx,
        dbx::PgDbx,
        entities::{
            account::{AccountFilter, AccountForCreate, AccountMeta},
            id::DbId,
            workspace::{
                WorkspaceConfig as StoreWorkspaceConfig, WorkspaceFilter, WorkspaceForCreate,
                WorkspaceForUpdate,
            },
        },
        error::StoreError,
        manager::StoreManager,
        stores::workspace::WorkspaceStore,
        traits::{contains::FilterByContains, crud::*, dbx::DbExecutor},
        utils::ListOptionsValidator,
    },
};

pub struct WorkspaceService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
}

impl<D: DbExecutor> WorkspaceService<D> {
    pub fn new(sm: Arc<StoreManager<D>>) -> Self {
        Self { sm }
    }

    /// Creates a new workspace.
    pub async fn create(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceCreateParams,
    ) -> CoreResult<Workspace> {
        let store = self.store();

        // 1. Check if slug already exists
        if store
            .get_by_slug_opt(&ctx.into(), &params.slug)
            .await?
            .is_some()
        {
            return Err(CoreError::AlreadyExists(
                "Workspace slug already exists".to_string(),
            ));
        }

        let config = StoreWorkspaceConfig::default();

        // 2. Map Core Params to Store ForCreate struct
        let n_ws = WorkspaceForCreate {
            name: params.name,
            slug: params.slug,
            description: params.description,
            config: config,
            tags: params.tags,
            meta: params.meta,
        };

        // 3. Execute store creation
        let new_workspace = store.create(&ctx.into(), n_ws).await?;

        Ok(new_workspace.into())
    }

    /// Retrieves a single workspace by ID or slug.
    pub async fn describe(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceDescribeParams,
    ) -> CoreResult<Workspace> {
        let store = self.store();

        let id = self.get_workspace_id(ctx, params.id, params.slug).await?;

        let res = store.get(&ctx.into(), &id).await?;

        Ok(res.into())
    }

    /// Updates an existing workspace.
    pub async fn update(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceUpdateParams,
    ) -> CoreResult<Workspace> {
        let store = self.store();

        let id = self
            .get_workspace_id(ctx, params.id, params.slug.clone())
            .await?;

        let config = StoreWorkspaceConfig::default();

        // 2. Map Core Params to Store ForUpdate struct
        let update_data = WorkspaceForUpdate {
            name: params.name,
            slug: params.slug,
            description: params.description,
            config: Some(config),
            tags: params.tags,
            meta: params.meta,
        };

        // 3. Execute store update
        let res = store.update(&ctx.into(), &id, update_data).await?;

        Ok(res.into())
    }

    /// Deletes a workspace by ID or slug.
    pub async fn delete(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceDeleteParams,
    ) -> CoreResult<Workspace> {
        // Returns the ID of the deleted item
        let store = self.store();

        let id = self.get_workspace_id(ctx, params.id, params.slug).await?;

        // 2. Execute store delete (returns the ID of the deleted item)
        let deleted = store.delete(&ctx.into(), &id).await?;

        Ok(deleted.into())
    }

    /// Lists workspaces based on filter and options.
    pub async fn list(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceListParams,
    ) -> CoreResult<ListResponse<Workspace>> {
        let store = self.store();
        let ctx: StoreCtx = ctx.into();

        let options = params.list_options();

        let tags_filter = params.validate_filter_tags()?;

        // filter by tags
        if let Some(tags) = tags_filter.tags() {
            let data = store
                .filter_by_tags_contain(&ctx, tags.clone(), Some(options.clone()))
                .await?;
            let total = store.count_by_tags_contain(&ctx, tags).await?;

            let accounts: Vec<Workspace> = data.into_iter().map(|el| el.into()).collect();
            return Ok(ListResponse::new(accounts, total, options));
        }

        // filter by filter
        if let Some(filter) = tags_filter.filter() {
            let filter = Some(filter);
            let data = store
                .list(&ctx, filter.clone(), Some(options.clone()))
                .await?;
            let total = store.count(&ctx, filter).await?;
            let accounts: Vec<Workspace> = data.into_iter().map(|el| el.into()).collect();
            return Ok(ListResponse::new(accounts, total, options));
        }

        // empty result
        Ok(ListResponse::default())
    }

    fn store(&self) -> &WorkspaceStore<D> {
        &self.sm.workspace
    }

    async fn get_workspace_id(
        &self,
        ctx: &CoreCtx,
        id: Option<Uuid>,
        slug: Option<String>,
    ) -> CoreResult<DbId> {
        let store = self.store();

        let id: DbId = match (id, slug) {
            (Some(id), _) => id.into(),
            (None, Some(slug)) => match store.get_by_slug_opt(&ctx.into(), &slug).await? {
                Some(ws) => ws.id,
                None => {
                    return Err(CoreError::StoreError(StoreError::EntityNotFound {
                        entity: "workspace".to_string(),
                        id: slug.to_string(),
                    }))
                }
            },
            (None, None) => {
                return Err(CoreError::InvalidParams(
                    "Workspace ID or slug required".to_string(),
                ))
            }
        };

        Ok(id)
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
            stores::workspace::WorkspaceStore,
            traits::{contains::FilterByContains, crud::*, join::GetOneToMany},
        },
    };
    use anyhow::Result;
    use modql::filter::{ListOptions, OpValsString};
    use serde_json::json;
    use serial_test::serial;
    use uuid::Uuid;
}
