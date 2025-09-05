use modql::field::HasSeaFields;
use sea_query::Iden; // for .to_string() on SeaField/Iden
use sqlx::{postgres::PgRow, FromRow, Postgres, QueryBuilder};
use uuid::Uuid;

// Bind a sea_query::Value into QueryBuilder with correct SQL type where possible.
// For None/nulls we push literal NULL (no binding).
pub fn push_sq_value(qb: &mut QueryBuilder<Postgres>, v: &sea_query::Value) {
    use sea_query::Value as V;
    match v {
        V::Bool(Some(x)) => {
            qb.push_bind(*x);
        }
        V::Int(Some(x)) => {
            qb.push_bind(*x);
        }
        V::BigInt(Some(x)) => {
            qb.push_bind(*x);
        }
        V::Unsigned(Some(x)) => {
            qb.push_bind(*x as i64);
        } // map to i64 if needed
        V::BigUnsigned(Some(x)) => {
            qb.push_bind(*x as i64);
        }
        V::Float(Some(x)) => {
            qb.push_bind(*x);
        }
        V::Double(Some(x)) => {
            qb.push_bind(*x);
        }
        V::String(Some(s)) => {
            qb.push_bind(s.to_string());
        }
        V::Char(Some(c)) => {
            let mut s = String::new();
            s.push(*c);
            qb.push_bind(s);
        }
        V::Uuid(Some(u)) => {
            qb.push_bind(**u);
        }
        V::Json(Some(j)) => {
            qb.push_bind(sqlx::types::Json(j.clone()));
        }
        // Bytes
        V::Bytes(Some(b)) => {
            qb.push_bind(*b.clone());
        }
        V::TimeDateTimeWithTimeZone(Some(t)) => {
            qb.push_bind(**t);
        }

        // Anything else or NULL → literal NULL
        _ => {
            qb.push("NULL");
        }
    }
}

pub fn pg_type_of(v: &sea_query::Value) -> &'static str {
    use sea_query::Value::*;
    match v {
        String(_) => "text",
        Bool(_) => "bool",
        Int(_) | SmallInt(_) | TinyInt(_) => "int4",
        BigInt(_) => "int8",
        Uuid(_) => "uuid",
        Json(_) => "jsonb",
        TimeDateTimeWithTimeZone(_) => "timestamptz",
        TimeDateTime(_) => "time",
        // add others you use…
        _ => "text", // safe fallback if you truly don’t know
    }
}
