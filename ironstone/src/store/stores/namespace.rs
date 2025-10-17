use std::sync::Arc;

use crate::store::{
    dbx::{DbExecutor, Dbx},
    entities::namespace::{
        NamespaceFilter, NamespaceForCreate, NamespaceForUpdate, NamespaceIden, NamespaceRow,
        NamespaceWithProjects,
    },
    queries::meta::{ContainsFilterQueryMeta, MutateQueryMeta, OneToManyQueryMeta, ReadQueryMeta},
    traits::meta::{ContainsFilterStore, MutateStore, OneToManyStore, ReadStore, Store},
};

/// The struct for our Namespace store, holding the database connection wrapper.
pub struct NamespaceStore {
    db: Arc<Dbx>,
}

impl NamespaceStore {
    /// Creates a new `NamespaceStore`.
    pub fn new(db: Arc<Dbx>) -> Self {
        Self { db }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, NamespaceStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl Store for NamespaceStore {
    type Iden = NamespaceIden;
    type Row = NamespaceRow;

    fn db(&self) -> impl DbExecutor {
        self.db.clone()
    }
}

impl ReadStore for NamespaceStore {
    type FilterStoreParams = NamespaceFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: NamespaceIden::Table,
            pk: NamespaceIden::Id,
            has_audit: true,
        }
    }
}

impl MutateStore for NamespaceStore {
    type CreateStoreParams = NamespaceForCreate;
    type UpdateStoreParams = NamespaceForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: NamespaceIden::Table,
            pk: NamespaceIden::Id,
            has_audit: true,
        }
    }
}

impl OneToManyStore for NamespaceStore {
    type OneToManyRow = NamespaceWithProjects;

    type FilterStoreParams = NamespaceFilter;

    fn one_to_many_meta(&self) -> OneToManyQueryMeta<Self::Iden> {
        OneToManyQueryMeta {
            single_table: NamespaceIden::Table,
            many_table: NamespaceIden::Project,
            single_pk: NamespaceIden::Id,
            many_pk: NamespaceIden::Id,
            many_fk: NamespaceIden::NamespaceId,
            agg_alias: NamespaceIden::Projects,
            has_audit: true,
        }
    }
}

impl ContainsFilterStore for NamespaceStore {
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: NamespaceIden::Table,
            col: NamespaceIden::Tags,
        }
    }

    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: NamespaceIden::Table,
            col: NamespaceIden::Meta,
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
            entities::{namespace::NamespaceForCreate, project::ProjectForCreate},
            error::StoreError,
            traits::{contains::FilterByContains, crud::*, join::GetOneToMany},
        },
    };
    use anyhow::Result;
    use serde_json::json;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_create_get_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = NamespaceStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let data = NamespaceForCreate {
            name: "test-namespace-create".to_string(),
            ..Default::default()
        };

        // -- Execute
        let created_namespace = store.create(&ctx, data).await?;
        let fetched_namespace = store.get(&ctx, &created_namespace.id).await?;

        // -- Assert
        assert_eq!(created_namespace.name, "test-namespace-create");
        assert_eq!(fetched_namespace.id, created_namespace.id);
        assert_eq!(fetched_namespace.name, created_namespace.name);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = NamespaceStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let created_namespace = store.create(&ctx, NamespaceForCreate::default()).await?;

        let update_data = NamespaceForUpdate {
            name: Some("updated-namespace-name".to_string()),
            ..Default::default()
        };

        // -- Execute
        let updated_namespace = store
            .update(&ctx, &created_namespace.id, update_data)
            .await?;
        let fetched_namespace = store.get(&ctx, &created_namespace.id).await?;

        // -- Assert
        assert_eq!(updated_namespace.name, "updated-namespace-name");
        assert_eq!(fetched_namespace.name, "updated-namespace-name");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = NamespaceStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let created_namespace = store.create(&ctx, NamespaceForCreate::default()).await?;

        // -- Execute
        let deleted_namespace = store.delete(&ctx, &created_namespace.id).await?;
        let get_result = store.get(&ctx, &created_namespace.id).await;

        // -- Assert
        assert_eq!(deleted_namespace.id, created_namespace.id);
        assert!(
            matches!(get_result, Err(StoreError::EntityNotFound { .. })),
            "Getting the namespace after deletion should fail"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_with_filter_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = NamespaceStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let ns_to_create = vec![
            NamespaceForCreate {
                name: "list-ns-a".to_string(),
                ..Default::default()
            },
            NamespaceForCreate {
                name: "list-ns-b".to_string(),
                ..Default::default()
            },
        ];
        store.create_many(&ctx, ns_to_create).await?;

        // -- Execute
        let filter: NamespaceFilter = json!({ "name": "list-ns-b" }).try_into()?;
        let namespaces = store.list(&ctx, Some(filter), None).await?;

        // -- Assert
        assert_eq!(namespaces.len(), 1);
        assert_eq!(namespaces[0].name, "list-ns-b");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_get_one_to_many_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = NamespaceStore::new(dbx);
        let ctx = StoreCtx::new_root();

        let namespace = store
            .create(
                &ctx,
                NamespaceForCreate {
                    name: "one-to-many-ns".into(),
                    ..Default::default()
                },
            )
            .await?;

        // Manually insert related projects
        app.sm
            .project
            .create(
                &ctx,
                ProjectForCreate {
                    namespace_id: namespace.id.into(),
                    name: "project-a".into(),
                    ..Default::default()
                },
            )
            .await?;
        app.sm
            .project
            .create(
                &ctx,
                ProjectForCreate {
                    namespace_id: namespace.id.into(),
                    name: "project-b".into(),
                    ..Default::default()
                },
            )
            .await?;

        // -- Execute
        let ns_with_projects = store.get_one_to_many(&ctx, &namespace.id).await?;

        // -- Assert
        assert_eq!(ns_with_projects.id, namespace.id);
        assert_eq!(
            ns_with_projects.projects.len(),
            2,
            "Should have 2 projects attached"
        );

        let has_project_a = ns_with_projects
            .projects
            .iter()
            .any(|p| p.name == "project-a");
        let has_project_b = ns_with_projects
            .projects
            .iter()
            .any(|p| p.name == "project-b");
        assert!(has_project_a, "Should contain project-a");
        assert!(has_project_b, "Should contain project-b");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_filter_by_contains_tags() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = NamespaceStore::new(dbx);
        let ctx = StoreCtx::new_root();

        // -- Create test data with different tags
        store
            .create(
                &ctx,
                NamespaceForCreate {
                    name: "tags-ns-a".into(),
                    tags: vec!["org".into(), "production".into()],
                    ..Default::default()
                },
            )
            .await?;
        store
            .create(
                &ctx,
                NamespaceForCreate {
                    name: "tags-ns-b".into(),
                    tags: vec!["user".into(), "personal".into()],
                    ..Default::default()
                },
            )
            .await?;

        // -- Execute & Assert
        let org_namespaces = store
            .filter_by_tags_contain(&ctx, vec!["org".into()])
            .await?;
        assert_eq!(
            org_namespaces.len(),
            1,
            "Should find 1 namespace with 'org' tag"
        );
        assert_eq!(org_namespaces[0].name, "tags-ns-a");

        let personal_namespaces = store
            .filter_by_tags_contain(&ctx, vec!["personal".into()])
            .await?;
        assert_eq!(
            personal_namespaces.len(),
            1,
            "Should find 1 namespace with 'personal' tag"
        );
        assert_eq!(personal_namespaces[0].name, "tags-ns-b");

        Ok(())
    }
}
// -----------------------------------------------------------------------------
// endregion: --- Tests
