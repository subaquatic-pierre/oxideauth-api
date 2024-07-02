use sqlx::sqlite::SqlitePool;

pub async fn establish_connection(database_url: &str) -> SqlitePool {
    SqlitePool::connect(database_url)
        .await
        .expect("Failed to create pool")
}

pub async fn init_db(pool: &SqlitePool, drop_tables: bool) -> Result<(), sqlx::Error> {
    // Drop all existing tables if they exist\
    if drop_tables {
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
    }

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            acc_type TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS roles (
            name TEXT PRIMARY KEY
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permissions (
            name TEXT PRIMARY KEY
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permission_bindings (
            role_name TEXT,
            permission_name TEXT,
            PRIMARY KEY (role_name, permission_name),
            FOREIGN KEY (role_name) REFERENCES roles(name),
            FOREIGN KEY (permission_name) REFERENCES permissions(name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS role_bindings (
            user_id TEXT,
            role_name TEXT,
            PRIMARY KEY (user_id, role_name),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (role_name) REFERENCES roles(name)
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
