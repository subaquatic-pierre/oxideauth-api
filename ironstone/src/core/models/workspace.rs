use uuid::Uuid;

use crate::core::models::oath::AuthProvider;

#[derive(Default, Clone, Debug)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub config: WorkspaceConfig,
}

#[derive(Default, Clone, Debug)]
pub struct WorkspaceConfig {
    allowed_auth_providers: Vec<AuthProvider>,
    jwt_max_age: u64,
    jwt_secret: String,
}
