use modql::filter::ListOptions;
use uuid::Uuid;

use crate::{
    core::dto::list::{RequestFilterParams, RequestListOptions},
    store::entities::account::AccountFilter,
};

pub struct AccountCreateParams {
    pub email: String,
    pub password: String,
}

pub struct AccountDescribeParams {
    pub email: String,
}

pub struct AccountListParams {
    pub filter: Option<RequestFilterParams<AccountFilter>>,
    pub options: Option<RequestListOptions>,
}
