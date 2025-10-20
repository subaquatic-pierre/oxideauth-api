use std::sync::Arc;

use crate::store::{
    dbx::{DbExecutor, PgDbx},
    entities::project::{
        ProjectFilter, ProjectForCreate, ProjectForUpdate, ProjectIden, ProjectRow,
    },
    queries::meta::{ContainsFilterQueryMeta, MutateQueryMeta, ReadQueryMeta},
    traits::meta::{ContainsFilterStore, MutateStore, ReadStore, Store},
};

/// The struct for our Project store, holding the database connection wrapper.
pub struct ProjectStore<Dbx: DbExecutor> {
    // Added generic
    dbx: Arc<Dbx>, // Use generic
}

impl<Dbx: DbExecutor> ProjectStore<Dbx> {
    // Added generic
    /// Creates a new `ProjectStore`.
    pub fn new(dbx: Arc<Dbx>) -> Self {
        // Use generic
        Self { dbx }
    }
}

// region:    --- Base Trait Implementations
// -----------------------------------------------------------------------------
// By implementing these meta traits, ProjectStore implicitly gains all of the
// CRUD, Batch, and Query capabilities from the blanket implementations.

impl<Dbx: DbExecutor> Store for ProjectStore<Dbx> {
    // Added generic
    type Iden = ProjectIden;
    type Row = ProjectRow;

    fn dbx(&self) -> impl DbExecutor {
        self.dbx.clone()
    }
}

impl<Dbx: DbExecutor> ReadStore for ProjectStore<Dbx> {
    // Added generic
    type FilterStoreParams = ProjectFilter;

    fn read_meta(&self) -> ReadQueryMeta<Self::Iden> {
        ReadQueryMeta {
            table: ProjectIden::Table,
            pk: ProjectIden::Id,
            has_audit: true,
        }
    }
}

impl<Dbx: DbExecutor> MutateStore for ProjectStore<Dbx> {
    // Added generic
    type CreateStoreParams = ProjectForCreate;
    type UpdateStoreParams = ProjectForUpdate;

    fn mutate_meta(&self) -> MutateQueryMeta<Self::Iden> {
        MutateQueryMeta {
            table: ProjectIden::Table,
            pk: ProjectIden::Id,
            has_audit: true,
        }
    }
}

impl<Dbx: DbExecutor> ContainsFilterStore for ProjectStore<Dbx> {
    // Added generic
    fn contains_tags_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: ProjectIden::Table,
            col: ProjectIden::Tags,
        }
    }

    fn contains_json_meta(&self) -> ContainsFilterQueryMeta<Self::Iden> {
        ContainsFilterQueryMeta {
            table: ProjectIden::Table,
            col: ProjectIden::Meta,
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
            traits::{contains::FilterByContains, crud::*},
        },
    };
    use anyhow::Result;
    use serde_json::json;
    use serial_test::serial;
    use uuid::Uuid;

    /// Helper function to seed the necessary Namespace for a Project.
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
        let store = ProjectStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        let data = ProjectForCreate {
            namespace_id,
            name: "test-project-create".to_string(),
            ..Default::default()
        };

        // -- Execute
        let created_project = store.create(&ctx, data).await?;
        let fetched_project = store.get(&ctx, &created_project.id).await?;

        // -- Assert
        assert_eq!(created_project.name, "test-project-create");
        assert_eq!(created_project.namespace_id, namespace_id);
        assert_eq!(fetched_project.id, created_project.id);
        assert_eq!(fetched_project.name, created_project.name);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_update_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = ProjectStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        let created_project = store
            .create(
                &ctx,
                ProjectForCreate {
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;

        let update_data = ProjectForUpdate {
            name: Some("updated-project-name".to_string()),
            ..Default::default()
        };

        // -- Execute
        let updated_project = store.update(&ctx, &created_project.id, update_data).await?;
        let fetched_project = store.get(&ctx, &created_project.id).await?;

        // -- Assert
        assert_eq!(updated_project.name, "updated-project-name");
        assert_eq!(fetched_project.name, "updated-project-name");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = ProjectStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        let created_project = store
            .create(
                &ctx,
                ProjectForCreate {
                    namespace_id,
                    ..Default::default()
                },
            )
            .await?;

        // -- Execute
        let deleted_project = store.delete(&ctx, &created_project.id).await?;
        let get_result = store.get(&ctx, &created_project.id).await;

        // -- Assert
        assert_eq!(deleted_project.id, created_project.id);
        assert!(
            matches!(get_result, Err(StoreError::EntityNotFound { .. })),
            "Getting the project after deletion should fail"
        );

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_list_with_filter_ok() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = ProjectStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        let projects_to_create = vec![
            ProjectForCreate {
                namespace_id,
                name: "list-proj-a".to_string(),
                ..Default::default()
            },
            ProjectForCreate {
                namespace_id,
                name: "list-proj-b".to_string(),
                ..Default::default()
            },
        ];
        store.create_many(&ctx, projects_to_create).await?;

        // -- Execute
        let filter: ProjectFilter = json!({ "name": "list-proj-b" }).try_into()?;
        let projects = store.list(&ctx, Some(filter), None).await?;

        // -- Assert
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "list-proj-b");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_filter_by_contains_tags() -> Result<()> {
        // -- Setup
        let app = init_test().await;
        let dbx = app.sm.dbx().clone();
        let store = ProjectStore::new(dbx);
        let ctx = StoreCtx::new_root();
        let namespace_id = seed_prerequisite(&ctx, &app).await?;

        // -- Create test data with different tags
        store
            .create(
                &ctx,
                ProjectForCreate {
                    namespace_id,
                    name: "tags-proj-a".into(),
                    tags: vec!["frontend".into(), "critical".into()],
                    ..Default::default()
                },
            )
            .await?;
        store
            .create(
                &ctx,
                ProjectForCreate {
                    namespace_id,
                    name: "tags-proj-b".into(),
                    tags: vec!["backend".into(), "api".into()],
                    ..Default::default()
                },
            )
            .await?;

        // -- Execute & Assert
        let frontend_projects = store
            .filter_by_tags_contain(&ctx, vec!["frontend".into()])
            .await?;
        assert_eq!(
            frontend_projects.len(),
            1,
            "Should find 1 project with 'frontend' tag"
        );
        assert_eq!(frontend_projects[0].name, "tags-proj-a");

        let api_projects = store
            .filter_by_tags_contain(&ctx, vec!["api".into()])
            .await?;
        assert_eq!(
            api_projects.len(),
            1,
            "Should find 1 project with 'api' tag"
        );
        assert_eq!(api_projects[0].name, "tags-proj-b");

        Ok(())
    }
}
// -----------------------------------------------------------------------------
// endregion: --- Tests
