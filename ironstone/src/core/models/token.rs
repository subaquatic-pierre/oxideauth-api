use serde::{Deserialize, Serialize};
use std::str::FromStr;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    core::models::membership::Membership,
    store::entities::token::TokenKind,
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
    store::entities::token::{TokenFilter as StoreTokenFilter, TokenRow},
};

pub type TokenFilter = StoreTokenFilter;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Token {
    pub id: Uuid,
    pub hash: Sha256Hash,

    pub kind: TokenKind,

    // Relations are optional in the blacklist context
    pub account: Option<Account>,
    pub workspace: Option<Workspace>,

    pub expires_at: OffsetDateTime,
    pub reason: Option<String>,

    pub audit: CoreAuditFields,
}

impl Token {
    pub fn from_row_with_entities(
        row: TokenRow,
        account: Option<Account>,
        workspace: Option<Workspace>,
    ) -> CoreResult<Self> {
        Ok(Self {
            id: row.id.into(),
            hash: row.hash,
            kind: row.kind,
            account,
            workspace,
            expires_at: row.expires_at,
            reason: row.reason,
            audit: row.audit.into(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenDescribeParams {
    id: Uuid,
    workspace_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct TokenDeleteParams {
    id: Uuid,
    workspace_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct TokenCreateParams {
    pub hash: Sha256Hash,
    pub account_id: Option<Uuid>,
    pub workspace_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
    pub reason: Option<String>,
}

pub struct TokenListParams {
    pub filter: Option<RequestFilterParams<TokenFilter>>,
    pub options: Option<RequestListOptions>,
}

impl RequestListParams<TokenFilter> for TokenListParams {
    fn filter(&self) -> Option<RequestFilterParams<TokenFilter>> {
        self.filter.clone()
    }

    fn options(&self) -> Option<RequestListOptions> {
        self.options.clone()
    }
}

impl OpValWorkspaceId for TokenFilter {
    fn get_workspace_id_opval(&self) -> Option<&OpValString> {
        self.workspace_id
            .as_ref()
            .and_then(|op_vals| op_vals.0.first())
    }
}

impl OpValAccountId for TokenFilter {
    fn get_account_id_opval(&self) -> Option<&OpValString> {
        self.account_id
            .as_ref()
            .and_then(|op_vals| op_vals.0.first())
    }
}

impl Default for Token {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            hash: Sha256Hash::default(),
            kind: TokenKind::Auth,
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
