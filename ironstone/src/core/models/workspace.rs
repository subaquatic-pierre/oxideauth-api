use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    core::models::{
        audit::CoreAuditFields,
        list::{RequestFilterParams, RequestListOptions},
        oath::AuthProvider,
    },
    store::entities::workspace::{
        WorkspaceConfig as StoreWorkspaceConfig, WorkspaceFilter as StoreWorkspaceFilter,
        WorkspaceMeta as StoreWorkspaceMeta, WorkspaceRow,
    },
};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Workspace {
    pub id: Uuid,

    // Identity
    pub name: String,
    pub slug: String,
    pub description: Option<String>,

    // Config
    pub config: WorkspaceConfig,

    pub tags: Vec<String>,
    pub meta: WorkspaceMeta,

    // Audit Fields (timestamps, creators, updaters)
    pub audit: CoreAuditFields,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    allowed_auth_providers: Vec<AuthProvider>,
    jwt_max_age: u64,
    jwt_secret: String,
}

impl From<StoreWorkspaceConfig> for WorkspaceConfig {
    fn from(value: StoreWorkspaceConfig) -> Self {
        WorkspaceConfig {
            allowed_auth_providers: vec![],
            jwt_max_age: 6000,
            jwt_secret: "secret".to_string(),
        }
    }
}

impl From<WorkspaceRow> for Workspace {
    fn from(row: WorkspaceRow) -> Self {
        // Assuming DbId can be directly converted to Uuid (common for SQLX/Postgres)
        let id: Uuid = row.id.into();

        let config = WorkspaceConfig::default();

        Self {
            id,
            name: row.name,
            slug: row.slug,
            description: row.description,
            config: config,
            tags: row.tags,
            meta: row.meta,
            audit: row.audit.into(),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct WorkspaceCreateParams {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,

    // Assuming these require values at creation based on store struct
    pub config: WorkspaceConfig,
    pub tags: Vec<String>,
    pub meta: WorkspaceMeta,
}

#[derive(Default, Clone, Debug)]
pub struct WorkspaceListParams {
    pub filter: Option<RequestFilterParams<WorkspaceFilter>>,
    pub options: Option<RequestListOptions>,
}

#[derive(Default, Clone, Debug)]
pub struct WorkspaceDeleteParams {
    pub id: Option<Uuid>,
    pub slug: Option<String>,
}

#[derive(Default, Clone, Debug)]
pub struct WorkspaceUpdateParams {
    // Workspace Identifier (one must be provided)
    pub id: Option<Uuid>,
    pub slug: Option<String>,

    // Fields to Update (mirroring WorkspaceForUpdate)
    pub name: Option<String>,
    pub description: Option<String>,
    pub config: Option<WorkspaceConfig>,
    pub tags: Option<Vec<String>>,
    pub meta: Option<WorkspaceMeta>,
}

#[derive(Default, Clone, Debug)]
pub struct WorkspaceDescribeParams {
    pub id: Option<Uuid>,
    pub slug: Option<String>,
}

pub type WorkspaceMeta = StoreWorkspaceMeta;
pub type WorkspaceFilter = StoreWorkspaceFilter;
