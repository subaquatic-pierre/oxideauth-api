use uuid::Uuid;

pub struct AccountCreateParams {
    pub email: String,
    pub password: String,
}

pub struct AccountDescribeParams {
    pub email: String,
}
