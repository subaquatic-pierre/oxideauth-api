use std::sync::Arc;

use crate::store::{
    dbx::Dbx,
    entities::role::{
        RoleFilter, RoleForCreate, RoleForUpdate, RoleIden, RoleRow, RoleWithPermissions,
    },
    queries::meta::{ContainsFilterQueryMeta, ManyToManyQueryMeta, MutateQueryMeta, ReadQueryMeta},
    traits::meta::{ContainsFilterStore, ManyToManyStore, MutateStore, ReadStore, Store},
};

/// The struct for our Role store, holding the database connection wrapper.
pub struct RoleStore {
    db: Arc<Dbx>,
}

impl RoleStore {
    /// Creates a new `RoleStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, RoleStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for RoleStore {
    type Iden = RoleIden;
    type Row = RoleRow;

    fn db(&self) -> &Dbx {
        &self.db
    }
}

impl ReadStore for RoleStore {
    type FilterStoreParams = RoleFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: RoleIden::Table,
            pk: RoleIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStore for RoleStore {
    type CreateStoreParams = RoleForCreate;
    type UpdateStoreParams = RoleForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: RoleIden::Table,
            pk: RoleIden::Id,
            has_audit: true,
        }
    }
}

impl ManyToManyStore for RoleStore {
    type ManyToManyRow = RoleWithPermissions;

    type FilterStoreParams = RoleFilter;

    fn many_to_many_meta(&self) -> ManyToManyQueryMeta<Self::Iden> {
        ManyToManyQueryMeta {
            single_table: RoleIden::Table,
            many_table: RoleIden::Permission,
            join_table: RoleIden::RolePermission,
            single_pk: RoleIden::Id,
            many_pk: RoleIden::PermissionPk,
            many_fk: RoleIden::PermissionId,
            join_fk: RoleIden::RoleId,
            agg_alias: RoleIden::Permissions,
            has_audit: true,
        }
    }
}

impl ContainsFilterStore for RoleStore {
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: RoleIden::Table,
            col: RoleIden::Tags,
        }
    }

    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: RoleIden::Table,
            col: RoleIden::Meta,
        }
    }
}

// -----------------------------------------------------------------------------
// endregion: --- Base Trait Implementations

// region:    --- Tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dev::init::init_test,
        store::{
            ctx::StoreCtx,
            entities::{
                namespace::NamespaceForCreate, permission::PermissionForCreate, role::RoleForCreate,
            },
            error::StoreError,
            traits::{
                contains::FilterByContains,
                crud::*,
                join::{GetManyToMany, LinkManyToMany},
            },
        },
    };
    use anyhow::Result;
    use serde_json::json;
    use serial_test::serial;
    use uuid::Uuid;

    /// Helper function to seed the necessary Namespace for a Role.
    async fn seed_prerequisite(ctx: &StoreCtx, app: &crate::app::AppData) -> Result<Uuid> {
        let namespace = app
            .sm
            .namespace
            .create(ctx, NamespaceForCreate::default())
            .await?;
        Ok(namespace.id.into())
    }

    #[tokio::test]
    #[serial]
    async fn test_create_get_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = RoleStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        let data = RoleForCreate {
            namespace_id,
            name: "test-role-create".to_string(),
            ..Default::default()
        };

        // -- Execute
        let created_role = store.create(&ctx, data).await?;
        let fetched_role = store.get(&ctx, &created_role.id).await?;

        // -- Assert
        assert_eq!(created_role.name, "test-role-create");
        assert_eq!(created_role.namespace_id, namespace_id);
        assert_eq!(fetched_role.id, created_role.id);
        assert_eq!(fetched_role.name, created_role.name);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = RoleStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        let created_role = store
            .create(
                &ctx,
                RoleForCreate {
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;

        let update_data = RoleForUpdate {
            name: Some("admin".to_string()),
            ..Default::default()
        };

        // -- Execute
        let updated_role = store.update(&ctx, &created_role.id, update_data).await?;
        let fetched_role = store.get(&ctx, &created_role.id).await?;

        // -- Assert
        assert_eq!(updated_role.name, "admin".to_string());
        assert_eq!(fetched_role.name, "admin".to_string());

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = RoleStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        let created_role = store
            .create(
                &ctx,
                RoleForCreate {
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;

        // -- Execute
        let deleted_role = store.delete(&ctx, &created_role.id).await?;
        let get_result = store.get(&ctx, &created_role.id).await;

        // -- Assert
        assert_eq!(deleted_role.id, created_role.id);
        assert!(
            matches!(get_result, Err(StoreError::EntityNotFound { .. })),
            "Getting the role after deletion should fail"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_with_filter_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = RoleStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        let roles_to_create = vec![
            RoleForCreate {
                namespace_id,
                name: "list-role-a".to_string(),
                ..Default::default()
            },
            RoleForCreate {
                namespace_id,
                name: "list-role-b".to_string(),
                ..Default::default()
            },
        ];
        store.create_many(&ctx, roles_to_create).await?;

        // -- Execute
        let filter: RoleFilter = json!({ "name": "list-role-b" }).try_into()?;
        let roles = store.list(&ctx, Some(filter), None).await?;

        // -- Assert
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "list-role-b");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_get_many_to_many_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = RoleStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        let role = store
            .create(
                &ctx,
                RoleForCreate {
                    namespace_id,
                    name: "role-with-perms".into(),
                    ..Default::default()
                },
            )
            .await?;

        // Create and link permissions
        let perm_read = app
            .sm
            .permission
            .create(
                &ctx,
                PermissionForCreate {
                    name: "entity:read".into(),
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;
        let perm_write = app
            .sm
            .permission
            .create(
                &ctx,
                PermissionForCreate {
                    name: "entity:write".into(),
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;

        app.sm
            .role
            .attach_link(&ctx, &role.id, &perm_read.id)
            .await?;
        app.sm
            .role
            .attach_link(&ctx, &role.id, &perm_write.id)
            .await?;

        // -- Execute
        let role_with_perms = store.get_many_to_many(&ctx, &role.id).await?;

        // -- Assert
        assert_eq!(role_with_perms.id, role.id);
        assert_eq!(
            role_with_perms.permissions.len(),
            2,
            "Should have 2 permissions attached"
        );

        let has_read = role_with_perms
            .permissions
            .iter()
            .any(|p| p.name == "entity:read");
        let has_write = role_with_perms
            .permissions
            .iter()
            .any(|p| p.name == "entity:write");
        assert!(has_read, "Should contain the 'entity:read' permission");
        assert!(has_write, "Should contain the 'entity:write' permission");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_filter_by_contains_tags() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = RoleStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        // -- Create test data with different tags
        store
            .create(
                &ctx,
                RoleForCreate {
                    namespace_id,
                    name: "tags-role-a".into(),
                    tags: vec!["billing".into(), "admin".into()],
                    ..Default::default()
                },
            )
            .await?;
        store
            .create(
                &ctx,
                RoleForCreate {
                    namespace_id,
                    name: "tags-role-b".into(),
                    tags: vec!["technical".into(), "editor".into()],
                    ..Default::default()
                },
            )
            .await?;

        // -- Execute & Assert
        let billing_roles = store
            .filter_by_tags_contain(&ctx, vec!["billing".into()])
            .await?;
        assert_eq!(
            billing_roles.len(),
            1,
            "Should find 1 role with 'billing' tag"
        );
        assert_eq!(billing_roles[0].name, "tags-role-a");

        let editor_roles = store
            .filter_by_tags_contain(&ctx, vec!["editor".into()])
            .await?;
        assert_eq!(
            editor_roles.len(),
            1,
            "Should find 1 role with 'editor' tag"
        );
        assert_eq!(editor_roles[0].name, "tags-role-b");

        Ok(())
    }
}
// -----------------------------------------------------------------------------
// endregion: --- Tests
