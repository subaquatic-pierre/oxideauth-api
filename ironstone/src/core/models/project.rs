use modql::filter::{op_val_string, ListOptions, OpValsString};
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
        traits::{
            list::{HasWorkspaceId, RequestListParams},
            modql::OpValIsString,
        },
    },
    store::{
        entities::project::{
            ProjectConfig as StoreProjectConfig, ProjectFilter as StoreProjectFilter,
            ProjectMeta as StoreProjectMeta, ProjectRow,
        },
        utils::ListOptionsValidator,
    },
};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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

impl RequestListParams<ProjectFilter> for ProjectListParams {
    fn filter(&self) -> Option<RequestFilterParams<ProjectFilter>> {
        self.filter.clone()
    }

    fn options(&self) -> Option<RequestListOptions> {
        self.options.clone()
    }

    fn workspace_id(&self) -> Option<Uuid> {
        self.filter
            .as_ref() // Option<RequestFilterParams<ProjectFilter>> -> Option<&RequestFilterParams<ProjectFilter>>
            .and_then(|filter| filter.fields.as_ref()) // Option<&ProjectFilter>
            .and_then(|fields| fields.workspace_id.as_ref()) // Option<&OpValsString>
            .and_then(|op_vals| {
                // We only care about the first operator value (op_vals.0 is Vec<OpValString>)
                op_vals.0.first()
            })
            // Only proceed if the operator is OpValString::Eq and contains a string
            .and_then(|op_val_string| op_val_string.as_eq_string())
            // Attempt to parse the resulting string as a Uuid
            .and_then(|val_str| Uuid::try_parse(val_str).ok())
    }
}

pub type ProjectConfig = StoreProjectConfig;
pub type ProjectMeta = StoreProjectMeta;
pub type ProjectFilter = StoreProjectFilter;

impl HasWorkspaceId for ProjectFilter {
    fn get_workspace_id_opvals(&self) -> Option<&OpValsString> {
        self.workspace_id.as_ref()
    }
}
