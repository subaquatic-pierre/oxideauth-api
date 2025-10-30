use uuid::Uuid;

use crate::core::models::oath::AuthProvider;

#[derive(Default, Clone)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub config: WorkspaceConfig,
}

#[derive(Default, Clone)]
pub struct WorkspaceConfig {
    allowed_auth_providers: Vec<AuthProvider>,
}
