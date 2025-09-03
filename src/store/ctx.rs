use std::str::FromStr;

use uuid::Uuid;

pub struct Ctx {
    user_id: Uuid,
    ns_id: Uuid,
}

impl Ctx {
    pub fn new(user_id: Uuid, ns_id: Uuid) -> Self {
        Self { user_id, ns_id }
    }

    pub fn new_root() -> Self {
        let root_user_id: Uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let root_namespace_id: Uuid =
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

        Self {
            user_id: root_user_id,
            ns_id: root_namespace_id,
        }
    }

    pub fn user_id(&self) -> Uuid {
        self.user_id
    }
}
