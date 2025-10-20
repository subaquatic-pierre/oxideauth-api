use std::sync::Arc;

use serde_json::json;

use crate::{
    core::{
        ctx::CoreCtx,
        error::{CoreError, CoreResult},
        models::account::Account,
    },
    store::{
        dbx::{DbExecutor, PgDbx},
        entities::account::{AccountFilter, AccountForCreate},
        manager::StoreManager,
        stores::account::AccountStore,
        traits::crud::*,
    },
};

pub struct AccountService<'a, Dbx: DbExecutor> {
    acc_store: &'a AccountStore<Dbx>,
    // password_hasher: Arc<dyn PasswordHasher>, // Dependency for hashing
}

impl<'a, Dbx: DbExecutor> AccountService<'a, Dbx> {
    pub fn new(acc_store: &'a AccountStore<Dbx>) -> Self {
        Self { acc_store }
    }

    pub async fn register(
        &self,
        ctx: &CoreCtx,
        email: &str,
        password: &str,
    ) -> CoreResult<Account> {
        let filter: AccountFilter = json!({
            "email": email.to_string()
        })
        .try_into()?;

        if !self
            .acc_store
            .list(&ctx.into(), Some(filter), None)
            .await?
            .is_empty()
        {
            return Err(CoreError::AlreadyExists("email already exists".to_string()));
        }

        let n_acc = AccountForCreate::default();

        let new_account = self.acc_store.create(&ctx.into(), n_acc).await?;

        Ok(new_account.into())
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use super::*;
    use crate::{
        dev::init::init_test,
        store::{
            ctx::StoreCtx,
            entities::{
                account::AccountRow,
                credential::{CredentialForCreate, CredentialProvider},
            },
            error::StoreError,
            meta::StoreId,
            stores::account::AccountStore,
            traits::{contains::FilterByContains, crud::*, join::GetOneToMany},
        },
    };
    use anyhow::Result;
    use modql::filter::{ListOptions, OpValsString};
    use serde_json::json;
    use serial_test::serial;
    use uuid::Uuid;

    struct MockDbxCreateAccountSuccess;

    impl DbExecutor for MockDbxCreateAccountSuccess {
        async fn fetch_one<'q, O, A>(
            &self,
            query: sqlx::query::QueryAs<'q, sqlx::Postgres, O, A>,
        ) -> crate::store::error::StoreResult<O>
        where
            O: for<'r> sqlx::FromRow<'r, <sqlx::Postgres as sqlx::Database>::Row> + Send + Unpin,
            A: sqlx::IntoArguments<'q, sqlx::Postgres> + 'q,
        {
            // We know O is AccountRow in this test, so we create it.
            let acc = AccountRow::default();

            // This is a type-to-type cast. It's unsafe because the compiler
            // can't prove O and AccountRow are the same type.
            // We are telling the compiler "trust me."
            let result = unsafe { mem::transmute_copy::<AccountRow, O>(&acc) };

            // We must "forget" the original `acc` to prevent Rust
            // from dropping it, as its memory is now owned by `result`.
            mem::forget(acc);

            Ok(result)
        }

        async fn fetch_optional<'q, O, A>(
            &self,
            query: sqlx::query::QueryAs<'q, sqlx::Postgres, O, A>,
        ) -> crate::store::error::StoreResult<Option<O>>
        where
            O: for<'r> sqlx::FromRow<'r, <sqlx::Postgres as sqlx::Database>::Row> + Send + Unpin,
            A: sqlx::IntoArguments<'q, sqlx::Postgres> + 'q,
        {
            Ok(Some(self.fetch_one(query).await?))
        }

        async fn fetch_all<'q, O, A>(
            &self,
            query: sqlx::query::QueryAs<'q, sqlx::Postgres, O, A>,
        ) -> crate::store::error::StoreResult<Vec<O>>
        where
            O: for<'r> sqlx::FromRow<'r, <sqlx::Postgres as sqlx::Database>::Row> + Send + Unpin,
            A: sqlx::IntoArguments<'q, sqlx::Postgres> + 'q,
        {
            Ok(vec![])
        }

        async fn execute<'q, A>(
            &self,
            query: sqlx::query::Query<'q, sqlx::Postgres, A>,
        ) -> crate::store::error::StoreResult<u64>
        where
            A: sqlx::IntoArguments<'q, sqlx::Postgres> + 'q,
        {
            Ok(0)
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_create_account() -> CoreResult<()> {
        let dbx = Arc::new(MockDbxCreateAccountSuccess);
        let acc_store = AccountStore::new(dbx);
        let acc_svc = AccountService::new(&acc_store);
        let ctx = CoreCtx::new_test();
        let new_acc = acc_svc.register(&ctx, "user@user.com", "password").await?;

        println!("{:#?}", new_acc);
        Ok(())
    }
}
