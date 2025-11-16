use std::sync::Arc;

use serde_json::json;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::account::Account,
        models::workspace::{
            Workspace, WorkspaceCreateParams, WorkspaceDeleteParams, WorkspaceDescribeParams,
            WorkspaceListParams, WorkspaceUpdateParams,
        },
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        entities::{
            account::{AccountFilter, AccountForCreate, AccountMeta},
            workspace::{WorkspaceFilter, WorkspaceForCreate, WorkspaceForUpdate},
        },
        manager::StoreManager,
        stores::workspace::WorkspaceStore,
        traits::crud::*,
    },
};

pub struct WorkspaceService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
}

impl<D: DbExecutor> WorkspaceService<D> {
    pub fn new(sm: Arc<StoreManager<D>>) -> Self {
        Self { sm }
    }

    pub async fn create(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceCreateParams,
    ) -> CoreResult<Workspace> {
        let data = WorkspaceForCreate::default();

        let store = &self.sm.workspace;

        let res = store.create(&ctx.into(), data).await?;

        let n = res.into();

        Ok(n)
    }

    pub async fn delete(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceDeleteParams,
    ) -> CoreResult<Workspace> {
        let store = &self.sm.workspace;

        let res = store.delete(&ctx.into(), &params.id.into()).await?;

        let n = res.into();

        Ok(n)
    }
    pub async fn list(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceListParams,
    ) -> CoreResult<Vec<Workspace>> {
        let filter: WorkspaceFilter = json!({ "name": "placeholder" }).try_into()?;
        let store = self.store();

        let res = store.list(&ctx.into(), Some(filter.into()), None).await?;

        let res: Vec<Workspace> = res.into_iter().map(|el| el.into()).collect();

        Ok(res)
    }

    pub async fn update(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceUpdateParams,
    ) -> CoreResult<Workspace> {
        let data = WorkspaceForUpdate::default();
        let store = self.store();

        let res = store.update(&ctx.into(), &params.id.into(), data).await?;

        let n = res.into();

        Ok(n)
    }

    pub async fn describe(
        &self,
        ctx: &CoreCtx,
        params: WorkspaceDescribeParams,
    ) -> CoreResult<Workspace> {
        let store = self.store();

        let res = store.get(&ctx.into(), &params.id.into()).await?;

        let n = res.into();

        Ok(n)
    }

    fn store(&self) -> &WorkspaceStore<D> {
        &self.sm.workspace
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
