use std::io;

use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use app::new_app_data;
use db::init::init_db;

mod app;
mod cli;
mod db;
mod models;
mod routes;
mod utils;

use log::info;
use routes::auth::register_auth_collection;
use routes::roles::register_roles_collection;
use routes::users::register_users_collection;

const SERVER_HOST: (&str, u16) = ("127.0.0.1", 8080);

#[actix_web::main]
async fn main() -> io::Result<()> {
    let app_data = new_app_data().await;
    env_logger::init();

    info!(
        "Server listening at {:}:{:}...",
        SERVER_HOST.0, SERVER_HOST.1
    );

    init_db(&app_data.db_pool, false)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let server = HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_data.clone())
            .service(register_auth_collection())
            .service(register_roles_collection())
            .service(register_users_collection())
    })
    .bind("0.0.0.0:8080")?
    .run();

    // Save the PID to a file
    // let pid = std::process::id();
    // let mut file = File::create("server.pid").expect("Failed to create PID file");
    // writeln!(file, "{}", pid).expect("Failed to write PID to file");

    // // Handle termination signal
    // let server_handle = server.handle();
    // ctrlc::set_handler(move || {
    //     println!("Shutting down server...");
    //     server_handle.stop(true);
    // })
    // .expect("Error setting Ctrl-C handler");

    server.await
}
