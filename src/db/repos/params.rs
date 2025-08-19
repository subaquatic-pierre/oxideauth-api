use chrono::{NaiveDate, NaiveDateTime};
use sqlx::query_builder::{QueryBuilder, Separated};
use sqlx::Postgres;
use std::fmt::Display;
use uuid::Uuid;

pub enum DbValue<'a> {
    Str(&'a str),
    String(String),
    Bool(bool),
    I64(i64),
    F64(f64),
    Uuid(Uuid),
    NaiveDate(NaiveDate),
    NaiveDateTime(NaiveDateTime),
    // add as needed
}

pub struct Params<'a> {
    pub cols: Vec<&'a str>,
    pub vals: Vec<DbValue<'a>>,
}

impl<'a> Params<'a> {
    pub fn new() -> Self {
        Self {
            cols: vec![],
            vals: vec![],
        }
    }
    pub fn push(mut self, col: &'a str, val: DbValue<'a>) -> Self {
        self.cols.push(col);
        self.vals.push(val);
        self
    }
    pub fn is_empty(&self) -> bool {
        self.cols.is_empty()
    }
}

// Each NewRow/UpdateRow implements this—no JSON involved.
pub trait ToParams<'a> {
    fn to_params(&'a self) -> Params<'a>;
    /// For PATCH-like updates: skip fields that are None.
    fn to_params_skip_none(&'a self) -> Params<'a> {
        self.to_params()
    }
}

/// Helper to bind DB values to QueryBuilder or Separated structs from SQLx QueryBuilder
pub trait BindTarget {
    fn push_dbvalue(&mut self, v: &DbValue);
}

impl<'a, 'b, S: Display> BindTarget for Separated<'a, 'b, Postgres, S> {
    fn push_dbvalue(&mut self, v: &DbValue) {
        match v {
            DbValue::Str(s) => {
                self.push_bind((*s).to_owned());
            }
            DbValue::String(s) => {
                self.push_bind(s.clone());
            }
            DbValue::Bool(b) => {
                self.push_bind(*b);
            }
            DbValue::I64(i) => {
                self.push_bind(*i);
            }
            DbValue::F64(f) => {
                self.push_bind(*f);
            }
            DbValue::Uuid(u) => {
                self.push_bind(*u);
            }
            DbValue::NaiveDate(d) => {
                self.push_bind(*d);
            }
            DbValue::NaiveDateTime(dt) => {
                self.push_bind(*dt);
            }
        }
    }
}

impl<'a> BindTarget for QueryBuilder<'a, Postgres> {
    fn push_dbvalue(&mut self, v: &DbValue) {
        match v {
            DbValue::Str(s) => {
                self.push_bind((*s).to_owned());
            }
            DbValue::String(s) => {
                self.push_bind(s.clone());
            }
            DbValue::Bool(b) => {
                self.push_bind(*b);
            }
            DbValue::I64(i) => {
                self.push_bind(*i);
            }
            DbValue::F64(f) => {
                self.push_bind(*f);
            }
            DbValue::Uuid(u) => {
                self.push_bind(*u);
            }
            DbValue::NaiveDate(d) => {
                self.push_bind(*d);
            }
            DbValue::NaiveDateTime(dt) => {
                self.push_bind(*dt);
            }
        }
    }
}
