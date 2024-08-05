use argon2::Config;
use rand::Rng;

use crate::models::api::{ApiError, ApiResult};

pub fn hash_password(password: &str) -> ApiResult<String> {
    let salt: [u8; 32] = rand::thread_rng().gen();
    let config = Config::default();

    let password_hash = argon2::hash_encoded(password.as_bytes(), &salt, &config)
        .map_err(|e| ApiError::new_400("unable to hash password"))?;

    Ok(password_hash)
}

pub fn verify_password(password_hash: &str, password: &str) -> Result<bool, ApiError> {
    argon2::verify_encoded(password_hash, password.as_bytes())
        .map_err(|_e| ApiError::new_400("invalid password"))
}
