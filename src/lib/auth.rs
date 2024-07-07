use actix_web::web::{scope, Data};
use actix_web::{web, App, HttpServer, Scope};
use std::{collections::HashSet, env};

use dotenv::dotenv;

use crate::routes::accounts::register_accounts_collection;
use crate::routes::auth::register_auth_collection;
use crate::routes::roles::register_roles_collection;
use crate::routes::services::register_services_collection;

use crate::models::{
    account::{Account, AccountType},
    role::RolePermissions,
};

use super::crypt::hash_password;

pub fn build_owner_account() -> Account {
    dotenv().ok();

    let owner_email = env::var("OWNER_EMAIL").unwrap_or("owner@email.com".to_string());
    let password = env::var("OWNER_PASSWORD").unwrap_or("password".to_string());

    let pw_hash = hash_password(&password).unwrap_or("unhashed_password".to_string());

    let owner_acc = Account::new(&owner_email, "owner", &pw_hash, AccountType::User, vec![]);
    owner_acc
}
