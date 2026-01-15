use modql::filter::{OpValString, OpValsString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    core::{
        error::{CoreError, CoreResult},
        models::{
            account::Account,
            audit::CoreAuditFields,
            list::{RequestFilterParams, RequestListOptions},
            workspace::Workspace,
        },
        traits::{
            filter::{OpValAccountId, OpValWorkspaceId},
            list::RequestListParams,
        },
    },
    store::entities::credential::{
        CredentialFilter as StoreCredentialFilter, CredentialKind,
        CredentialMeta as StoreCredentialMeta, CredentialProvider, CredentialRow, CredentialStatus,
    },
};

pub type CredentialMeta = StoreCredentialMeta;
pub type CredentialFilter = StoreCredentialFilter;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential {
    pub id: Uuid,

    pub account: Account,
    pub workspace: Workspace,

    pub kind: CredentialKind,
    pub provider: CredentialProvider,
    pub status: CredentialStatus,
    pub provider_id: Option<String>,
    pub email: Option<String>,

    #[serde(skip_serializing)]
    pub secret: Option<String>,

    pub last_used_at: Option<OffsetDateTime>,
    pub tags: Vec<String>,
    pub meta: CredentialMeta,

    pub audit: CoreAuditFields,
}

impl Credential {
    pub fn from_row_with_entities(
        row: CredentialRow,
        account: Account,
        workspace: Workspace,
    ) -> CoreResult<Self> {
        if Uuid::from(row.account_id) != account.id {
            return Err(CoreError::InvalidParams(
                "row.account_id does not match account.id".to_string(),
            ));
        }
        if Uuid::from(row.workspace_id) != workspace.id {
            return Err(CoreError::InvalidParams(
                "row.workspace_id does not match workspace.id".to_string(),
            ));
        }

        Ok(Self {
            id: row.id.into(),
            account,
            workspace,
            kind: row.kind,
            provider: row.provider,
            status: row.status,
            provider_id: row.provider_id,
            email: row.email,
            secret: row.secret,
            last_used_at: row.last_used_at,
            tags: row.tags,
            meta: row.meta,
            audit: row.audit.into(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct CredentialCreateParams {
    pub account_id: Uuid,
    pub workspace_id: Uuid,
    pub kind: CredentialKind,
    pub provider: CredentialProvider,
    pub status: CredentialStatus,
    pub provider_id: Option<String>,
    pub email: Option<String>,
    pub secret: Option<String>,
    pub last_used_at: Option<OffsetDateTime>,
    pub tags: Vec<String>,
    pub meta: CredentialMeta,
}

#[derive(Debug, Deserialize)]
pub struct CredentialDescribeParams {
    pub id: Uuid,
    pub account_id: Uuid,
    pub workspace_id: Uuid,
    pub provider_id: Option<String>,
    pub email: Option<String>,
}

impl CredentialDescribeParams {
    pub fn validate(&self) -> CoreResult<()> {
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct CredentialUpdateParams {
    pub id: Option<Uuid>,
    pub provider_id: Option<String>,
    pub email: Option<String>,

    pub account_id: Uuid,
    pub workspace_id: Uuid,

    pub kind: Option<CredentialKind>,
    pub provider: Option<CredentialProvider>,
    pub status: Option<CredentialStatus>,
    pub new_provider_id: Option<String>,
    pub new_email: Option<String>,
    pub secret: Option<String>,
    pub last_used_at: Option<OffsetDateTime>,
    pub tags: Option<Vec<String>>,
    pub meta: Option<CredentialMeta>,
}

#[derive(Debug, Deserialize)]
pub struct CredentialDeleteParams {
    pub id: Option<Uuid>,
    pub account_id: Uuid,
    pub workspace_id: Uuid,
    pub provider_id: Option<String>,
    pub email: Option<String>,
}

pub struct CredentialListParams {
    pub filter: Option<RequestFilterParams<CredentialFilter>>,
    pub options: Option<RequestListOptions>,
}

impl RequestListParams<CredentialFilter> for CredentialListParams {
    fn filter(&self) -> Option<RequestFilterParams<CredentialFilter>> {
        self.filter.clone()
    }

    fn options(&self) -> Option<RequestListOptions> {
        self.options.clone()
    }
}

impl OpValWorkspaceId for CredentialFilter {
    fn get_workspace_id_opval(&self) -> Option<&OpValString> {
        self.workspace_id
            .as_ref()
            .and_then(|op_vals| op_vals.0.first())
    }
}

impl OpValAccountId for CredentialFilter {
    fn get_account_id_opval(&self) -> Option<&OpValString> {
        self.account_id
            .as_ref()
            .and_then(|op_vals| op_vals.0.first())
    }
}
