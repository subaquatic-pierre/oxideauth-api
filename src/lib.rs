#![deny(unused_must_use)]
use std::{env, io};

use actix_cors::Cors;
use actix_http::Request;
use actix_web::dev::Server;
use actix_web::middleware::Logger;
use actix_web::{http::header, test, web, App, HttpServer, Scope};

pub mod app;
pub mod cli;
pub mod config;
pub mod db;
pub mod dev;
pub mod models;
pub mod routes;
pub mod services;
pub mod utils;

use log::info;
use utils::auth::build_owner_account;

use app::{new_app_data, register_all_services};

// use actix_http::Request;
use actix_web::dev::{Service, ServiceResponse};
