use uuid::Uuid;

use crate::{core::models::oath::AuthProvider, store::entities::workspace::WorkspaceRow};

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

impl From<WorkspaceRow> for Workspace {
    fn from(value: WorkspaceRow) -> Self {
        Workspace::default()
    }
}

pub struct WorkspaceCreateParams {}
pub struct WorkspaceListParams {}
pub struct WorkspaceDeleteParams {
    pub id: Uuid,
}
pub struct WorkspaceUpdateParams {
    pub id: Uuid,
}
pub struct WorkspaceDescribeParams {
    pub id: Uuid,
}
