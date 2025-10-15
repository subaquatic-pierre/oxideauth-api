#![deny(unused_must_use)]
use std::{env, io, str::FromStr};

use dotenv::dotenv;
use tracing::info;
use tracing_subscriber::EnvFilter;

use axum::{routing::get, Router};
use std::net::SocketAddr;

mod app;
mod config;
mod core;
mod dev;
mod store;
mod utils;
mod web;

use app::new_app_data;
use web::routes::root::root_handler;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt()
        .without_time() // For early local development.
        .with_target(false)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let app = new_app_data().await;
    let bind_addr = format!("{}:{}", app.config.host, app.config.port);

    // Define the application's routes.
    let app = Router::new().route("/", get(root_handler));

    // Define the address to run the server on.
    let addr = SocketAddr::from_str(&bind_addr);
    info!("Server listening at {bind_addr} ... ",);

    // Create a TCP listener and serve the application.
    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
