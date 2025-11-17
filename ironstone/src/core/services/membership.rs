use std::sync::Arc;

use serde_json::json;

use crate::{
    cache::{manager::CacheManager, stores::membership::MembershipCache, traits::CacheExecutor},
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::{
            account::Account,
            membership::{
                CachedMembership, Membership, MembershipCreateParams, MembershipDescribeParams,
            },
        },
    },
    store::{
        dbx::PgDbx,
        entities::account::{AccountFilter, AccountForCreate, AccountMeta},
        manager::StoreManager,
        stores::membership::MembershipStore,
        traits::{crud::*, dbx::DbExecutor},
    },
};

pub struct MembershipService<D: DbExecutor, C: CacheExecutor> {
    sm: Arc<StoreManager<D>>,
    cm: Arc<CacheManager<C>>,
    // password_hasher: Arc<dyn PasswordHasher>, // Dependency for hashing
}

impl<D: DbExecutor, C: CacheExecutor> MembershipService<D, C> {
    pub fn new(sm: Arc<StoreManager<D>>, cm: Arc<CacheManager<C>>) -> Self {
        Self { sm, cm }
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

    pub fn get_cached(&self) -> Option<CachedMembership> {
        let cache = self.cache();
        None
    }

    fn cache(&self) -> &MembershipCache<C> {
        &self.cm.membership
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
        cache::redis::RedisChx,
        config::Config,
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

        let config = Config::test_config();

        // build store manager
        let dbx = Arc::new(MockDbxAccountRegister);
        let sm = Arc::new(StoreManager::new(dbx));

        // build cache manager
        let redis_cache = Arc::new(RedisChx::new(&config.redis_url).await);
        let cm = Arc::new(CacheManager::new(redis_cache));
        let svc = MembershipService::new(sm, cm);

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

        let config = Config::test_config();

        // build store manager
        let dbx = Arc::new(MockDbxAccountRegister);
        let sm = Arc::new(StoreManager::new(dbx));

        // build cache manager
        let redis_cache = Arc::new(RedisChx::new(&config.redis_url).await);
        let cm = Arc::new(CacheManager::new(redis_cache));
        let svc = MembershipService::new(sm, cm);

        Ok(())
    }
}
