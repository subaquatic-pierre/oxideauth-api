use modql::field::{SeaField, SeaFields};
use uuid::Uuid;

use crate::{store::schema::iden::AuditIden, utils::time::now_utc};

pub fn prepare_audit_fields(fields: &mut SeaFields, user_id: Uuid, is_create: bool) {
    let now = now_utc();
    fields.push(SeaField::new(AuditIden::Mid, user_id));
    fields.push(SeaField::new(AuditIden::Mtime, now));

    if is_create {
        fields.push(SeaField::new(AuditIden::Cid, user_id));
        fields.push(SeaField::new(AuditIden::Ctime, now));
    }
}
