use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Service {
    pub id: Uuid,
    pub name: String,
    pub endpoint: Option<String>,
    pub description: Option<String>,
}

impl Service {
    pub fn new(name: &str, endpoint: Option<String>, description: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.to_string(),
            endpoint,
            description,
        }
    }
}
