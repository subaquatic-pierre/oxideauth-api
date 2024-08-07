use std::{env, io};

use actix_cors::Cors;
use actix_web::middleware::Logger;
use actix_web::{http::header, web, App, HttpServer, Scope};
use db::init::init_db;

mod app;
mod cli;
mod db;
mod models;
mod routes;
// mod templates;
mod utils;

use log::info;
use utils::auth::build_owner_account;

use app::{new_app_data, register_all_services};

#[actix_web::main]
async fn main() -> io::Result<()> {
    let app_data = new_app_data().await;

    env_logger::init();

    let app_host = format!("{:}:{:}", app_data.config.host, app_data.config.port);
    info!("Server listening at {app_host}...",);

    // CHnage again

    let owner_acc = build_owner_account();

    init_db(
        &app_data.db,
        &owner_acc,
        app_data.config.drop_tables,
        &app_data.config,
    )
    .await
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let server = HttpServer::new(move || {
        // let cors = Cors::default()
        //     .allowed_origin(&app_data.config.client_origin)
        //     .allowed_origin("http://localhost:8000")
        //     .allowed_methods(vec!["GET", "POST", "OPTIONS"])
        //     .allowed_headers(vec![
        //         header::CONTENT_TYPE,
        //         header::AUTHORIZATION,
        //         header::ACCEPT,
        //     ])
        //     .supports_credentials();
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
