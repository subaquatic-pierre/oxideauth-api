use log::{debug, error, info};
use sqlx::{Error, PgPool, Result};
use uuid::Uuid;

use crate::models::{account::Account, service::Service};

pub async fn get_all_services_db(pool: &PgPool) -> Result<Vec<Service>> {
    // TODO: Implement Limit paging for query all
    let services = sqlx::query_as!(
        Service,
        r#"
        SELECT * FROM services
      "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(services)
}

pub async fn get_service_db(pool: &PgPool, id_or_name: &str) -> Result<Service> {
    struct SvcR {
        pub id: Uuid,
        pub name: String,
        pub endpoint: Option<String>,
        pub description: Option<String>,
    }

    let svc_r = match Uuid::parse_str(id_or_name) {
        Ok(id) => {
            if let Some(r) = sqlx::query!(
                r#"
              SELECT * FROM services
              WHERE id = $1 
            "#,
                id,
            )
            .fetch_optional(pool)
            .await?
            {
                SvcR {
                    id: r.id,
                    name: r.name,
                    description: r.description,
                    endpoint: r.endpoint,
                }
            } else {
                return Err(Error::RowNotFound);
            }
        }
        Err(_) => {
            if let Some(r) = sqlx::query!(
                r#"
                SELECT * FROM services
                WHERE name = $1 
            "#,
                id_or_name,
            )
            .fetch_optional(pool)
            .await?
            {
                SvcR {
                    id: r.id,
                    name: r.name,
                    description: r.description,
                    endpoint: r.endpoint,
                }
            } else {
                return Err(Error::RowNotFound);
            }
        }
    };

    Ok(Service {
        id: svc_r.id,
        name: svc_r.name,
        description: svc_r.description,
        endpoint: svc_r.endpoint,
    })
}

pub async fn create_service_db(pool: &PgPool, service: &Service) -> Result<Service> {
    let r = sqlx::query!(
        r#"
        INSERT INTO services (id,name,endpoint,description)
        VALUES ($1, $2, $3, $4)
        RETURNING *
      "#,
        service.id,
        service.name,
        service.endpoint,
        service.description
    )
    .fetch_one(pool)
    .await?;

    let service = Service::new(&r.name, r.endpoint, r.description);

    Ok(service)
}

pub async fn update_service_db(pool: &PgPool, service: &Service) -> Result<Service> {
    let r = sqlx::query!(
        r#"
        UPDATE services
        SET name = $1,
            endpoint = $2,
            description = $3
        RETURNING *
      "#,
        service.name,
        service.endpoint,
        service.description
    )
    .fetch_one(pool)
    .await?;

    let service = Service {
        id: r.id,
        name: r.name,
        endpoint: r.endpoint,
        description: r.description,
    };

    Ok(service)
}

pub async fn delete_service_db(pool: &PgPool, service: &Service) -> Result<()> {
    sqlx::query!(
        r#"
          DELETE FROM services
          WHERE id = $1
        "#,
        service.id
    )
    .execute(pool)
    .await?;

    Ok(())
}
