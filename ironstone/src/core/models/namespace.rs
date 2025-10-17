use uuid::Uuid;

use crate::core::models::oath::AuthProvider;

pub struct Namespace {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub config: NamespaceConfig,
}

pub struct NamespaceConfig {
    allowed_auth_providers: Vec<AuthProvider>,
}
