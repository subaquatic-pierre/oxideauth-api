#![deny(unused_must_use)]
use std::{env, io};

use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::web::Data;
use actix_web::{http::header, web as ActixWeb, App, HttpServer, Scope};
use oxideauth::app::new_dev_app_data;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod app;
mod cli;
mod config;
mod db;
mod dev;
mod models;
mod routes;
mod rpc;
mod services;
mod utils;
mod web;

use app::{new_app_data, register_all_services};

use crate::dev::init::init_dev;

#[actix_web::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .without_time() // For early local development.
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let app = new_app_data().await;

    let app_data = Data::new(app);

    info!(
        "Server listening at {:}:{:}...",
        app_data.config.host, app_data.config.port
    );

    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .send_wildcard()
            .allowed_methods(vec!["GET", "POST", "OPTIONS", "DELETE"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
            ]);

        App::new()
            .app_data(app_data.clone())
            .service(register_all_services())
            .wrap(Logger::default())
            .wrap(cors)
    })
    .bind("0.0.0.0:8080")?
    .run();

    server.await
}
