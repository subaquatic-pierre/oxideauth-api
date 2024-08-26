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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password_success() {
        let password = "super_secret";
        let result = hash_password(password);

        assert!(result.is_ok(), "Password hashing should succeed");
        let password_hash = result.unwrap();
        assert_ne!(
            password_hash, password,
            "Hashed password should not match the original password"
        );
    }

    #[test]
    fn test_hash_password_failure() {
        let password = ""; // Argon2 might not like an empty password, but it should hash it anyway.
        let result = hash_password(password);

        assert!(
            result.is_ok(),
            "Hashing an empty password should still succeed"
        );
    }

    #[test]
    fn test_verify_password_success() {
        let password = "super_secret";
        let password_hash = hash_password(password).unwrap();
        let result = verify_password(&password_hash, password);

        assert!(result.is_ok(), "Password verification should succeed");
        assert!(result.unwrap(), "The password should match the hash");
    }

    #[test]
    fn test_verify_password_failure() {
        let password = "super_secret";
        let wrong_password = "not_the_password";
        let password_hash = hash_password(password).unwrap();
        let result = verify_password(&password_hash, wrong_password);

        let valid = result.unwrap();

        assert!(
            !valid,
            "Password verification should fail for a wrong password"
        );
    }
}
