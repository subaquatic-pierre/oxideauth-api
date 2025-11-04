use serde_json::json;

use crate::{
    core::{
        ctx::CoreCtx,
        dto::membership::{MembershipCreateParams, MembershipDescribeParams},
        error::{CoreError, CoreResult},
        models::{account::Account, membership::Membership},
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        entities::account::{AccountFilter, AccountForCreate, AccountMeta},
        manager::StoreManager,
        stores::workspace::WorkspaceStore,
        traits::crud::*,
    },
};

pub struct WorkspaceService<'a, D: DbExecutor> {
    ws_store: &'a WorkspaceStore<D>,
}

impl<'a, D: DbExecutor> WorkspaceService<'a, D> {
    pub fn new(ws_store: &'a WorkspaceStore<D>) -> Self {
        Self { ws_store }
    }

    pub async fn create_membership(
        &self,
        ctx: &CoreCtx,
        params: MembershipCreateParams,
    ) -> CoreResult<Membership> {
        // ensure can create membership in this workspace
        let n = Membership::default();

        Ok(n)
    }

    pub async fn describe_membership(
        &self,
        ctx: &CoreCtx,
        _params: MembershipDescribeParams,
    ) -> CoreResult<Membership> {
        let n = Membership::default();

        Ok(n)
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

        let dbx = Arc::new(MockDbxAccountRegister);
        let ws_store = WorkspaceStore::new(dbx);

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
        let dbx = Arc::new(MockDbxAccountRegister);
        let ws_store = WorkspaceStore::new(dbx);
        let membership_svc = WorkspaceService::new(&ws_store);
        let ctx = CoreCtx::new_test();

        Ok(())
    }
}
