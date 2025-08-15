use diesel::prelude::*;
use uuid::Uuid;

use crate::schema::{account_roles, accounts, roles};

// ------------ DB models (table-shaped) ------------
#[derive(Debug, Clone, Queryable, Identifiable)]
#[diesel(table_name = accounts)]
pub struct DbAccount {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    // pub password_hash: String,
    // pub acc_type: String, // "user" | "service"
    // pub provider: String, // "local" | "google" | ...
    // pub provider_id: Option<String>,
    // pub description: Option<String>,
    // pub image_url: Option<String>,
    // pub verified: bool,
    // pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = accounts)]
pub struct NewAccount<'a> {
    pub name: &'a str,
    pub email: &'a str,
    // pass lowercased
    // pub password_hash: &'a str,
    // pub acc_type: &'a str, // "user" | "service"
    // pub provider: &'a str, // "local" | "google"
    // pub provider_id: Option<&'a str>,
    // pub description: Option<&'a str>,
    // pub image_url: Option<&'a str>,
    // pub verified: bool,
    // pub enabled: bool,
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = accounts)]
pub struct AccountChanges<'a> {
    pub name: Option<&'a str>,
    pub email: Option<&'a str>, // only if you allow changing email
}
