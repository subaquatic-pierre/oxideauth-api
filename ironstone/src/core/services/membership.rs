use std::sync::Arc;

use serde_json::json;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::account::Account,
        models::membership::{Membership, MembershipCreateParams, MembershipDescribeParams},
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        entities::account::{AccountFilter, AccountForCreate, AccountMeta},
        manager::StoreManager,
        stores::membership::MembershipStore,
        traits::crud::*,
    },
};

pub struct MembershipService<D: DbExecutor> {
    sm: Arc<StoreManager<D>>,
    // password_hasher: Arc<dyn PasswordHasher>, // Dependency for hashing
}

impl<D: DbExecutor> MembershipService<D> {
    pub fn new(sm: Arc<StoreManager<D>>) -> Self {
        Self { sm }
    }

    pub async fn create(
        &self,
        ctx: &CoreCtx,
        params: MembershipCreateParams,
    ) -> CoreResult<Membership> {
        // ensure can create membership in this workspace
        let n = Membership::default();

        Ok(n)
    }

    pub async fn describe(
        &self,
        ctx: &CoreCtx,
        _params: MembershipDescribeParams,
    ) -> CoreResult<Membership> {
        let n = Membership::default();

        Ok(n)
    }

    fn store(&self) -> &MembershipStore<D> {
        &self.sm.membership
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
            stores::membership::MembershipStore,
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
        let sm = Arc::new(StoreManager::new(dbx));
        let svc = MembershipService::new(sm);

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
        let sm = Arc::new(StoreManager::new(dbx));
        let svc = MembershipService::new(sm);
        let ctx = CoreCtx::new_test();

        Ok(())
    }
}
