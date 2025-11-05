use uuid::Uuid;

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
