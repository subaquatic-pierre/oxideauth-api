use modql::field::{SeaField, SeaFields};
use uuid::Uuid;

use crate::{store::schema::iden::AuditIden, utils::time::now_utc};

pub fn prepare_audit_fields(fields: &mut SeaFields, user_id: Uuid, is_create: bool) {
    let now = now_utc();

    if is_create {
        fields.push(SeaField::new(AuditIden::CreatedBy, user_id));
        fields.push(SeaField::new(AuditIden::CreatedAt, now));
    } else {
        fields.push(SeaField::new(AuditIden::UpdatedBy, user_id));
        fields.push(SeaField::new(AuditIden::UpdatedAt, now));
    }
}
