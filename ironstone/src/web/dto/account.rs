use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct AccountCreateReq {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct AccountDescribeReq {
    pub email: String,
}

#[derive(Serialize)]
pub struct AccountRes {
    pub id: Uuid,
    pub email: String,
}
