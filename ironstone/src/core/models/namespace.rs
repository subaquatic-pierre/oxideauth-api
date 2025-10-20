use uuid::Uuid;

use crate::core::models::oath::AuthProvider;

#[derive(Default)]
pub struct Namespace {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub config: NamespaceConfig,
}

#[derive(Default)]
pub struct NamespaceConfig {
    allowed_auth_providers: Vec<AuthProvider>,
}
