use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use sqlx::{FromRow, Postgres, QueryBuilder};
use uuid::Uuid;

use crate::db::{
    init::PgPool,
    repos::params::{BindTarget, DbValue, Params, ToParams},
};

#[async_trait(?Send)]
pub trait Repo {
    type Row: for<'r> FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin;
    type NewRow<'a>: ToParams<'a>
    where
        Self: 'a;
    type UpdateRow<'a>: ToParams<'a>
    where
        Self: 'a;

    fn table(&self) -> &'static str;

    async fn get(&self, pool: &PgPool, id: Uuid) -> Result<Option<Self::Row>> {
        let sql = format!("SELECT * FROM {} WHERE id = $1", self.table());
        let row = sqlx::query_as::<_, Self::Row>(&sql)
            .bind(id)
            .fetch_optional(pool)
            .await
            .context("get failed")?;
        Ok(row)
    }

    async fn list(&self, pool: &PgPool) -> Result<Vec<Self::Row>> {
        let sql = format!("SELECT * FROM {}", self.table());
        let rows = sqlx::query_as::<_, Self::Row>(&sql)
            .fetch_all(pool)
            .await
            .context("list failed")?;
        Ok(rows)
    }

    async fn create<'a>(&self, pool: &PgPool, new: &'a Self::NewRow<'a>) -> Result<Self::Row>
    where
        Self: 'a,
    {
        let p = new.to_params();
        if p.is_empty() {
            bail!("create called with empty params");
        }

        let mut qb = QueryBuilder::<Postgres>::new(format!("INSERT INTO {} (", self.table()));

        // columns
        {
            let mut cols = qb.separated(", ");
            for col in &p.cols {
                cols.push(col); // safer for identifiers than `push`
            }
        }

        // values
        qb.push(") VALUES (");
        {
            let mut vals = qb.separated(", ");
            for v in &p.vals {
                vals.push_dbvalue(v);
            }
        }
        qb.push(") RETURNING *");

        let row = qb
            .build_query_as::<Self::Row>()
            .fetch_one(pool)
            .await
            .context("insert failed")?;

        Ok(row)
    }

    async fn update<'a>(
        &self,
        pool: &PgPool,
        id: Uuid,
        changes: &'a Self::UpdateRow<'a>,
    ) -> Result<Self::Row>
    where
        Self: 'a,
    {
        let p = changes.to_params_skip_none();
        if p.is_empty() {
            bail!("update called with empty params");
        }

        let mut qb = QueryBuilder::<Postgres>::new(format!("UPDATE {} SET ", self.table()));
        {
            let mut sets = qb.separated(", ");
            for (i, col) in p.cols.iter().enumerate() {
                sets.push(col).push(" = ");
                sets.push_dbvalue(&p.vals[i]);
            }
        }
        qb.push(" WHERE id = ");
        qb.push_bind(id);
        qb.push(" RETURNING *");

        let row = qb
            .build_query_as::<Self::Row>()
            .fetch_one(pool)
            .await
            .context("update failed")?;

        Ok(row)
    }

    async fn delete(&self, pool: &PgPool, id: Uuid) -> Result<u64> {
        let sql = format!("DELETE FROM {} WHERE id = $1", self.table());
        let res = sqlx::query(&sql).bind(id).execute(pool).await?;
        Ok(res.rows_affected())
    }

    async fn upsert<'a>(
        &self,
        pool: &PgPool,
        conflict_col: &str, // e.g., "id" or "email"
        new: &'a Self::NewRow<'a>,
        changes: &'a Self::UpdateRow<'a>,
    ) -> Result<Self::Row>
    where
        Self: 'a,
    {
        let insert = new.to_params();
        let update = changes.to_params_skip_none();

        if insert.is_empty() {
            anyhow::bail!("upsert: empty insert");
        }

        let mut qb = QueryBuilder::<Postgres>::new(format!("INSERT INTO {} (", self.table()));
        {
            let mut cols = qb.separated(", ");
            for c in &insert.cols {
                cols.push(c);
            }
        }
        qb.push(") VALUES (");
        {
            let mut vals = qb.separated(", ");
            for v in &insert.vals {
                vals.push_dbvalue(v);
            }
        }
        qb.push(") ON CONFLICT (").push(conflict_col).push(") DO ");

        if update.is_empty() {
            qb.push("NOTHING ");
        } else {
            qb.push("UPDATE SET ");
            let mut sets = qb.separated(", ");
            for (i, col) in update.cols.iter().enumerate() {
                sets.push(col).push(" = ");
                sets.push_dbvalue(&update.vals[i]);
            }
            qb.push(" ");
        }
        qb.push("RETURNING *");

        Ok(qb
            .build_query_as::<Self::Row>()
            .fetch_one(pool)
            .await
            .context("upsert failed")?)
    }

    async fn list_page(&self, pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<Self::Row>> {
        let mut qb = QueryBuilder::<Postgres>::new(format!("SELECT * FROM {} ", self.table()));
        qb.push("ORDER BY id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        Ok(qb
            .build_query_as::<Self::Row>()
            .fetch_all(pool)
            .await
            .context("list_page failed")?)
    }
}
