use std::sync::Arc;

// db/repos/account.rs
use anyhow::Result;
use async_trait::async_trait;
use chrono::NaiveDateTime;
use sqlx::FromRow;
use uuid::Uuid;

use crate::db::init::PgPool;
use crate::db::repos::base::Repo;
use crate::db::repos::params::{DbValue, Params, ToParams};

#[derive(Debug, FromRow)]
pub struct AccountRow {
    pub id: Uuid,
    pub email: String,
    pub active: bool,
    pub created_at: NaiveDateTime,
}

pub struct AccountNewRow<'a> {
    pub email: &'a str,
    pub active: bool,
}
impl<'a> ToParams<'a> for AccountNewRow<'a> {
    fn to_params(&'a self) -> Params<'a> {
        Params::new()
            .push("email", DbValue::Str(self.email))
            .push("active", DbValue::Bool(self.active))
    }
}

pub struct AccountUpdateRow<'a> {
    pub email: Option<&'a str>,
    pub active: Option<bool>,
}
impl<'a> ToParams<'a> for AccountUpdateRow<'a> {
    fn to_params(&'a self) -> Params<'a> {
        // For full PUT semantics (set NULLs explicitly), map Options accordingly.
        let mut p = Params::new();
        if let Some(email) = self.email {
            p = p.push("email", DbValue::Str(email));
        } else { /* if you need explicit NULL: p = p.push("email", DbValue::String("NULL".into())) */
        }
        if let Some(active) = self.active {
            p = p.push("active", DbValue::Bool(active));
        }
        p
    }
    fn to_params_skip_none(&'a self) -> Params<'a> {
        // PATCH semantics: only include present fields
        let mut p = Params::new();
        if let Some(email) = self.email {
            p = p.push("email", DbValue::Str(email));
        }
        if let Some(active) = self.active {
            p = p.push("active", DbValue::Bool(active));
        }
        p
    }
}

pub struct AccountRepo {
    pool: Arc<PgPool>,
}

#[async_trait]
impl Repo for AccountRepo {
    type Row = AccountRow;
    type NewRow<'a> = AccountNewRow<'a>;
    type UpdateRow<'a> = AccountUpdateRow<'a>;

    fn table(&self) -> &'static str {
        "accounts"
    }
}
