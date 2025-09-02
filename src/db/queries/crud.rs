use modql::field::HasSeaFields;
use sea_query::{PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use sqlx::{postgres::PgRow, FromRow};
use uuid::Uuid;

use crate::db::dbx::Dbx;
use crate::db::error::Result;
use crate::db::stores::base::StoreMeta;
use crate::db::stores::utils::prepare_audit_fields;
use crate::db::{ctx::Ctx, store::DataStore};
use sea_query::{Iden, IntoIden, TableRef};

pub async fn create<C, R, DB>(ctx: &Ctx, store: &DB, data: C) -> Result<R>
where
    DB: StoreMeta,
    R: for<'r> FromRow<'r, PgRow> + HasSeaFields + Send + Sync + Unpin,
    C: HasSeaFields,
{
    let user_id = ctx.user_id();
    let mut fields = data.not_none_sea_fields();

    if store.has_audit() {
        prepare_audit_fields(&mut fields, user_id, true);
    }

    let ret = Query::returning().columns(R::sea_column_refs());
    let (cols, vals) = fields.for_sea_insert();
    let mut query = Query::insert();
    query
        .into_table(store.table_ref())
        .columns(cols)
        .values(vals)?
        .returning_all();

    let (sql, values) = query.build_sqlx(PostgresQueryBuilder);
    let sqlx_query = sqlx::query_as_with::<_, R, _>(&sql, values);

    let ret = store.db().fetch_one(sqlx_query).await?;

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serial_test::serial;
    use sqlx::{query_as, Postgres};

    use crate::{
        db::{
            schema::account::{AccountCreate, AccountRow},
            stores::account::AccountStore,
        },
        dev::init::init_test,
    };

    use super::*;

    #[tokio::test]
    #[serial]
    async fn test_create() -> Result<()> {
        let app = init_test().await;
        let dbx = app.ds.db().clone();

        let acc_store = AccountStore::new(dbx);

        let ctx = Ctx::new_root();
        let data = AccountCreate::default();

        let ret: AccountRow = create(&ctx, &acc_store, data).await?;

        let query = query_as::<_, AccountRow>("SELECT * FROM accounts WHERE id = $1").bind(ret.id);

        let found: AccountRow = acc_store.db().fetch_one(query).await?;

        assert_eq!(found.id, ret.id);
        Ok(())
    }
}
