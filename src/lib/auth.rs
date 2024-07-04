use std::{collections::HashSet, env};

use dotenv::dotenv;

use crate::models::{
    account::{Account, AccountType},
    role::RolePermissions,
};

use super::crypt::hash_password;

pub fn contains_all<T: Eq + std::hash::Hash>(superset: &[T], subset: &[T]) -> bool {
    let set: HashSet<_> = superset.iter().collect();
    subset.iter().all(|item| set.contains(item))
}

pub fn build_owner_account() -> Account {
    dotenv().ok();

    let owner_email = env::var("OWNER_EMAIL").unwrap_or("owner@email.com".to_string());
    let password = env::var("OWNER_PASSWORD").unwrap_or("password".to_string());

    let pw_hash = hash_password(&password).unwrap_or("unhashed_password".to_string());

    let owner_acc = Account::new(&owner_email, "owner", &pw_hash, AccountType::User, vec![]);
    owner_acc
}
