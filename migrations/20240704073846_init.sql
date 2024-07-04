-- Add migration script here
CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    acc_type TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    id UUID,
    name TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS permission_bindings (
    role_id UUID NOT NULL,
    permission_name TEXT NOT NULL,
    PRIMARY KEY (role_id, permission_name),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_name) REFERENCES permissions(name)
);

CREATE TABLE IF NOT EXISTS role_bindings (
    account_id UUID NOT NULL,
    role_id UUID NOT NULL,
    PRIMARY KEY (account_id, role_id),
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);