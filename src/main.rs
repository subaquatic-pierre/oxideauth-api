use std::{env, io};

use actix_web::middleware::Logger;
use actix_web::web::scope;
use actix_web::{web, App, HttpServer, Scope};
use db::init::init_db;

mod app;
mod cli;
mod db;
mod lib;
mod models;
mod routes;

use dotenv::dotenv;
use lib::auth::build_owner_account;
use log::info;
use models::account::Account;
use models::role::RolePermissions;

use app::{new_app_data, register_all_services};

const SERVER_HOST: (&str, u16) = ("127.0.0.1", 8080);

#[actix_web::main]
async fn main() -> io::Result<()> {
    let app_data = new_app_data().await;

    env_logger::init();

    info!(
        "Server listening at {:}:{:}...",
        SERVER_HOST.0, SERVER_HOST.1
    );

    // CHnage again

    let owner_acc = build_owner_account();

    init_db(&app_data.db, &owner_acc, true)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let server = HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_data.clone())
            .service(register_all_services())
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
