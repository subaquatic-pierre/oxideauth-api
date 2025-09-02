use uuid::Uuid;

pub struct Ctx {
    user_id: Uuid,
}

pub async fn create<DS, R>(ctx: &Ctx) -> () {}
