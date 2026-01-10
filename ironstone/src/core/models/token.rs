use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    core::models::membership::Membership,
    utils::time::{format_time, now_utc},
};

use modql::filter::OpValString;

use crate::{
    core::{
        error::CoreResult,
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
    store::entities::hash::Sha256Hash,
    store::entities::token_blacklist::{
        TokenBlacklistFilter as StoreTokenBlacklistFilter, TokenBlacklistRow,
    },
};

pub type TokenBlacklistFilter = StoreTokenBlacklistFilter;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenBlacklist {
    pub id: Uuid,
    pub token_hash: Sha256Hash,

    // Relations are optional in the blacklist context
    pub account: Option<Account>,
    pub workspace: Option<Workspace>,

    pub expires_at: OffsetDateTime,
    pub reason: Option<String>,

    pub audit: CoreAuditFields,
}

impl TokenBlacklist {
    pub fn from_row_with_entities(
        row: TokenBlacklistRow,
        account: Option<Account>,
        workspace: Option<Workspace>,
    ) -> CoreResult<Self> {
        Ok(Self {
            id: row.id.into(),
            token_hash: row.token_hash,
            account,
            workspace,
            expires_at: row.expires_at,
            reason: row.reason,
            audit: row.audit.into(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenBlacklistCreateParams {
    pub token_hash: Sha256Hash,
    pub account_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub reason: Option<String>,
}

pub struct TokenBlacklistListParams {
    pub filter: Option<RequestFilterParams<TokenBlacklistFilter>>,
    pub options: Option<RequestListOptions>,
}

impl RequestListParams<TokenBlacklistFilter> for TokenBlacklistListParams {
    fn filter(&self) -> Option<RequestFilterParams<TokenBlacklistFilter>> {
        self.filter.clone()
    }

    fn options(&self) -> Option<RequestListOptions> {
        self.options.clone()
    }
}

impl OpValWorkspaceId for TokenBlacklistFilter {
    fn get_workspace_id_opval(&self) -> Option<&OpValString> {
        self.workspace_id
            .as_ref()
            .and_then(|op_vals| op_vals.0.first())
    }
}

impl OpValAccountId for TokenBlacklistFilter {
    fn get_account_id_opval(&self) -> Option<&OpValString> {
        self.account_id
            .as_ref()
            .and_then(|op_vals| op_vals.0.first())
    }
}

impl Default for TokenBlacklist {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            token_hash: Sha256Hash::default(),
            account: None,
            workspace: None,
            expires_at: OffsetDateTime::now_utc(),
            reason: None,
            audit: CoreAuditFields::default(),
        }
    }
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Eq)]
pub struct TokenClaims {
    sub: String, // Account ID
    ws: String,  // Workspace ID
    mem: String, // Membership ID
    iss: String,
    aud: String,
    pub exp: usize,
    pub iat: usize,
    ty: TokenType,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy, Deserialize)]
pub enum TokenType {
    Auth,
    PasswordReset,
    Refresh,
    AccountConfirm,
}

impl TokenClaims {
    pub fn new(sub: Uuid, ws: Uuid, mem: Uuid, exp: OffsetDateTime, ty: TokenType) -> Self {
        Self {
            sub: sub.to_string(),
            ws: ws.to_string(),
            mem: mem.to_string(),
            iss: "ironstone.app".to_string(),
            aud: "ironstone.api".to_string(),
            iat: now_utc().unix_timestamp() as usize,
            exp: exp.unix_timestamp() as usize,
            ty,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = now_utc().unix_timestamp() as usize;
        if self.exp < now {
            true
        } else {
            false
        }
    }
}
