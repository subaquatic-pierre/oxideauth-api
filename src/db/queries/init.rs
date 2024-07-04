use sqlx::PgPool;

pub async fn drop_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    // Drop all existing tables if they exist\
    sqlx::query(
        r#"
        DROP TABLE IF EXISTS role_bindings;
        DROP TABLE IF EXISTS permission_bindings;
        DROP TABLE IF EXISTS roles;
        DROP TABLE IF EXISTS permissions;
        DROP TABLE IF EXISTS accounts;
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            id UUID PRIMARY KEY,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            acc_type TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS roles (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permissions (
            id UUID,
            name TEXT PRIMARY KEY
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permission_bindings (
            role_id UUID NOT NULL,
            permission_name TEXT NOT NULL,
            PRIMARY KEY (role_id, permission_name),
            FOREIGN KEY (role_id) REFERENCES roles(id),
            FOREIGN KEY (permission_name) REFERENCES permissions(name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS role_bindings (
            account_id UUID NOT NULL,
            role_id UUID NOT NULL,
            PRIMARY KEY (account_id, role_id),
            FOREIGN KEY (account_id) REFERENCES accounts(id),
            FOREIGN KEY (role_id) REFERENCES roles(id)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[tokio::test]
//     async fn test_create_role() {}
// }
