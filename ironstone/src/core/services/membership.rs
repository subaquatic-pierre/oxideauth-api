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
        stores::membership::MembershipStore,
        traits::crud::*,
    },
};

pub struct MembershipService<'a, Dbx: DbExecutor> {
    membership_store: &'a MembershipStore<Dbx>,
    // password_hasher: Arc<dyn PasswordHasher>, // Dependency for hashing
}

impl<'a, Dbx: DbExecutor> MembershipService<'a, Dbx> {
    pub fn new(membership_store: &'a MembershipStore<Dbx>) -> Self {
        Self { membership_store }
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
        let membership_store = MembershipStore::new(dbx);

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
        let membership_store = MembershipStore::new(dbx);
        let membership_svc = MembershipService::new(&membership_store);
        let ctx = CoreCtx::new_test();

        Ok(())
    }
}
