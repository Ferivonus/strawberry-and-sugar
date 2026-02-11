use actix_cors::Cors;
use actix_web::{http, web, App, HttpServer};
use dotenvy::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::env;

mod auth;
mod handlers;
mod models;
mod routes;

use models::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL yok!");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET yok!");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .expect("Veritabanı bağlantı hatası!");

    println!("The program is working at http://localhost:8080");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                http::header::AUTHORIZATION,
                http::header::CONTENT_TYPE,
            ])
            .supports_credentials();

        App::new()
            .app_data(web::Data::new(AppState {
                db: pool.clone(),
                jwt_secret: jwt_secret.clone(),
            }))
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            .configure(routes::config)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
