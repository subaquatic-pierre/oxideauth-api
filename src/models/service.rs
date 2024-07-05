use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    id: Uuid,
    name: String,
    description: String,
}
