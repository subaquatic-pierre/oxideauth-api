use std::sync::Arc;

use crate::store::{
    dbx::{DbExecutor, PgDbx},
    entities::membership::{
        MembershipFilter, MembershipForCreate, MembershipForUpdate, MembershipIden, MembershipRow,
        MembershipWithRoles,
    },
    queries::meta::{ContainsFilterQueryMeta, ManyToManyQueryMeta, MutateQueryMeta, ReadQueryMeta},
    traits::meta::{ContainsFilterStore, ManyToManyStore, MutateStore, ReadStore, Store},
};

/// The struct for our Membership store, holding the database connection wrapper.
pub struct MembershipStore<Dbx: DbExecutor> {
    dbx: Arc<Dbx>,
}

impl<Dbx: DbExecutor> MembershipStore<Dbx> {
    /// Creates a new `MembershipStore`.
    pub fn new(dbx: Arc<Dbx>) -> Self {
        Self { dbx }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, MembershipStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl<Dbx: DbExecutor> Store for MembershipStore<Dbx> {
    type Iden = MembershipIden;
    type Row = MembershipRow;

    fn dbx(&self) -> impl DbExecutor {
        self.dbx.clone()
    }
}

impl<Dbx: DbExecutor> ReadStore for MembershipStore<Dbx> {
    type FilterStoreParams = MembershipFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: MembershipIden::Table,
            pk: MembershipIden::Id,
            has_audit: true,
        }
    }
}

impl<Dbx: DbExecutor> MutateStore for MembershipStore<Dbx> {
    type CreateStoreParams = MembershipForCreate;
    type UpdateStoreParams = MembershipForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: MembershipIden::Table,
            pk: MembershipIden::Id,
            has_audit: true,
        }
    }
}

impl<Dbx: DbExecutor> ManyToManyStore for MembershipStore<Dbx> {
    type ManyToManyRow = MembershipWithRoles;

    type FilterStoreParams = MembershipFilter;

    fn many_to_many_meta(&self) -> ManyToManyQueryMeta<Self::Iden> {
        ManyToManyQueryMeta {
            single_table: MembershipIden::Table,
            many_table: MembershipIden::Role,
            join_table: MembershipIden::MembershipRole,
            single_pk: MembershipIden::Id,
            many_pk: MembershipIden::RolePk,
            many_fk: MembershipIden::RoleId,
            join_fk: MembershipIden::MembershipId,
            agg_alias: MembershipIden::Roles,
            has_audit: true,
        }
    }
}

impl<Dbx: DbExecutor> ContainsFilterStore for MembershipStore<Dbx> {
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: MembershipIden::Table,
            col: MembershipIden::Tags,
        }
    }

    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: MembershipIden::Table,
            col: MembershipIden::Meta,
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
                account::AccountForCreate,
                id::DbId,
                membership::{MembershipForCreate, MembershipMeta},
                namespace::NamespaceForCreate,
                role::RoleForCreate,
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

    /// Helper function to seed the necessary Account and Space for a Membership.
    async fn seed_prerequisites(
        ctx: &StoreCtx,
        app: &crate::app::AppData,
    ) -> Result<(uuid::Uuid, uuid::Uuid)> {
        let account = app
            .sm
            .account
            .create(ctx, AccountForCreate::default())
            .await?;
        let namespace = app
            .sm
            .namespace
            .create(ctx, NamespaceForCreate::default())
            .await?;
        Ok((account.id.into(), namespace.id.into()))
    }

    #[tokio::test]
    #[serial]
    async fn test_create_get_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = MembershipStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let (account_id, namespace_id) = seed_prerequisites(&ctx, &app).await?;

        let data = MembershipForCreate {
            account_id,
            namespace_id,
            ..Default::default()
        };

        // -- Execute
        let created_membership = store.create(&ctx, data).await?;
        let fetched_membership = store.get(&ctx, &created_membership.id).await?;

        // -- Assert
        assert_eq!(created_membership.account_id, account_id);
        assert_eq!(created_membership.namespace_id, namespace_id);
        assert_eq!(fetched_membership.id, created_membership.id);
        assert_eq!(fetched_membership.account_id, created_membership.account_id);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = MembershipStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let (account_id, namespace_id) = seed_prerequisites(&ctx, &app).await?;

        let created_membership = store
            .create(
                &ctx,
                MembershipForCreate {
                    account_id,
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;

        let update_data = MembershipForUpdate {
            meta: Some(MembershipMeta {
                schema_version: "1".to_string(),
            }),
            ..Default::default()
        };

        // -- Execute
        let updated_membership = store
            .update(&ctx, &created_membership.id, update_data)
            .await?;
        let fetched_membership = store.get(&ctx, &created_membership.id).await?;

        // -- Assert
        assert_eq!(updated_membership.meta.schema_version, "1");
        assert_eq!(fetched_membership.meta.schema_version, "1");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = MembershipStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let (account_id, namespace_id) = seed_prerequisites(&ctx, &app).await?;

        let created_membership = store
            .create(
                &ctx,
                MembershipForCreate {
                    account_id,
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;

        // -- Execute
        let deleted_membership = store.delete(&ctx, &created_membership.id).await?;
        let get_result = store.get(&ctx, &created_membership.id).await;

        // -- Assert
        assert_eq!(deleted_membership.id, created_membership.id);
        assert!(
            matches!(get_result, Err(StoreError::EntityNotFound { .. })),
            "Getting the membership after deletion should fail"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_with_filter_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = MembershipStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let (account_id_1, space_id_1) = seed_prerequisites(&ctx, &app).await?;
        let (account_id_2, space_id_2) = seed_prerequisites(&ctx, &app).await?;

        let memberships_to_create = vec![
            MembershipForCreate {
                account_id: account_id_1,
                namespace_id: space_id_1,
                ..Default::default()
            },
            MembershipForCreate {
                account_id: account_id_2,
                namespace_id: space_id_2,
                ..Default::default()
            },
        ];
        store.create_many(&ctx, memberships_to_create).await?;

        // -- Execute
        let filter: MembershipFilter = json!({ "account_id": account_id_2 }).try_into()?;
        let memberships = store.list(&ctx, Some(filter), None).await?;

        // -- Assert
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].account_id, account_id_2);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_get_many_to_many_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = MembershipStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let (account_id, namespace_id) = seed_prerequisites(&ctx, &app).await?;
        let membership = store
            .create(
                &ctx,
                MembershipForCreate {
                    account_id,
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;

        // Create and link roles
        let role_admin = app
            .sm
            .role
            .create(
                &ctx,
                RoleForCreate {
                    name: "admin".into(),
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;
        let role_editor = app
            .sm
            .role
            .create(
                &ctx,
                RoleForCreate {
                    name: "editor".into(),
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;

        app.sm
            .membership
            .attach_link(&ctx, &membership.id, &role_admin.id)
            .await?;

        app.sm
            .membership
            .attach_link(&ctx, &membership.id, &role_editor.id)
            .await?;
        // -- Execute
        let membership_with_roles = store.get_many_to_many(&ctx, &membership.id).await?;

        // -- Assert
        assert_eq!(membership_with_roles.id, membership.id);
        assert_eq!(
            membership_with_roles.roles.len(),
            2,
            "Should have 2 roles attached"
        );

        let has_admin = membership_with_roles
            .roles
            .iter()
            .any(|r| r.name == "admin");
        let has_editor = membership_with_roles
            .roles
            .iter()
            .any(|r| r.name == "editor");
        assert!(has_admin, "Should contain the 'admin' role");
        assert!(has_editor, "Should contain the 'editor' role");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_filter_by_contains_tags() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = MembershipStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let (account_id, namespace_id) = seed_prerequisites(&ctx, &app).await?;

        // -- Create test data with different tags
        store
            .create(
                &ctx,
                MembershipForCreate {
                    account_id,
                    namespace_id,
                    tags: vec!["system".into(), "critical".into()],
                    ..Default::default()
                },
            )
            .await?;

        let (account_id, namespace_id) = seed_prerequisites(&ctx, &app).await?;
        store
            .create(
                &ctx,
                MembershipForCreate {
                    account_id,
                    namespace_id,
                    tags: vec!["user".into(), "general".into()],
                    ..Default::default()
                },
            )
            .await?;

        // -- Execute & Assert
        let system_memberships = store
            .filter_by_tags_contain(&ctx, vec!["system".into()])
            .await?;
        assert_eq!(
            system_memberships.len(),
            1,
            "Should find 1 membership with 'system' tag"
        );
        assert!(system_memberships[0].tags.contains(&"system".to_string()));

        let general_memberships = store
            .filter_by_tags_contain(&ctx, vec!["general".into()])
            .await?;
        assert_eq!(
            general_memberships.len(),
            1,
            "Should find 1 membership with 'general' tag"
        );
        assert!(general_memberships[0].tags.contains(&"general".to_string()));

        Ok(())
    }
}
// -----------------------------------------------------------------------------
// endregion: --- Tests
