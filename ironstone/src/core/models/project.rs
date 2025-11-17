use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    core::{
        error::{CoreError, CoreResult},
        models::{
            audit::CoreAuditFields,
            list::{RequestFilterParams, RequestListOptions},
            workspace::Workspace,
        },
    },
    store::entities::project::{
        ProjectConfig as StoreProjectConfig, ProjectFilter as StoreProjectFilter,
        ProjectMeta as StoreProjectMeta, ProjectRow,
    },
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Project {
    pub id: Uuid,
    pub workspace: Workspace,

    // Project identity
    pub name: String,
    pub code: Option<String>,
    pub description: Option<String>,

    // Config
    pub config: ProjectConfig,

    pub tags: Vec<String>,
    pub meta: ProjectMeta,

    // Audit Fields
    pub audit: CoreAuditFields,
}

impl Project {
    /// Constructs a Project model by hydrating it with the full Workspace entity.
    /// This is used by the service layer after fetching both the row and the related entity.
    pub fn from_row_with_workspace(row: ProjectRow, workspace: Workspace) -> CoreResult<Self> {
        // Ensure the ID matches (useful for validation, though generally guaranteed by join/lookup)
        if row.workspace_id != workspace.id {
            return Err(CoreError::InvalidParams(
                "row.workspace_id does not match workspace.id".to_string(),
            ));
        }

        let new_project = Self {
            id: row.id.into(),
            workspace, // Use the provided full Workspace entity
            name: row.name,
            code: row.code,
            description: row.description,
            config: row.config,
            tags: row.tags,
            meta: row.meta,
            audit: row.audit.into(),
        };

        Ok(new_project)
    }
}

#[derive(Debug, Deserialize)]
pub struct ProjectCreateParams {
    pub workspace_id: Uuid,
    pub name: String,
    pub code: Option<String>,
    pub description: Option<String>,

    pub config: ProjectConfig,
    pub tags: Vec<String>,
    pub meta: ProjectMeta,
}

#[derive(Debug, Deserialize)]
pub struct ProjectDescribeParams {
    pub id: Option<Uuid>,
    pub code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectUpdateParams {
    // Identifier
    pub id: Option<Uuid>,
    pub code: Option<String>,

    pub workspace_id: Uuid,
    pub name: Option<String>,
    pub new_code: Option<String>,
    pub description: Option<String>,
    pub config: Option<ProjectConfig>,
    pub tags: Option<Vec<String>>,
    pub meta: Option<ProjectMeta>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectDeleteParams {
    pub id: Option<Uuid>,
    pub workspace_id: Uuid,
    pub code: Option<String>,
}

pub struct ProjectListParams {
    pub filter: Option<RequestFilterParams<ProjectFilter>>,
    pub options: Option<RequestListOptions>,
}

pub type ProjectConfig = StoreProjectConfig;
pub type ProjectMeta = StoreProjectMeta;
pub type ProjectFilter = StoreProjectFilter;
