use actix_cors::Cors;
use actix_web::{http, web, App, HttpServer};
use dotenvy::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::env;

// --- MODÜL TANIMLARI ---
mod auth;
mod handlers; // Artık bir klasör olduğu için Rust bunu "handlers/mod.rs" olarak arayacak.
mod models;
mod routes;

// Modellerden AppState'i içeri alıyoruz
use models::AppState;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 1. Loglama Ayarları
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    dotenv().ok(); // .env dosyasını yükle
    env_logger::init(); // Logger'ı başlat

    // 2. Çevresel Değişkenleri Oku
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL bulunamadı!");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET bulunamadı!");

    // 3. Veritabanı Bağlantı Havuzu
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .expect("Veritabanına bağlanılamadı!");

    println!("Ferivonizm Mabedi Sunucusu Aktif: http://127.0.0.1:8080");

    // 4. HTTP Sunucusunu Başlat
    HttpServer::new(move || {
        // CORS (Frontend ile iletişim izni)
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000") // Frontend adresi
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                http::header::AUTHORIZATION,
                http::header::CONTENT_TYPE,
            ])
            .supports_credentials(); // Cookie gönderimi için şart

        App::new()
            // Veritabanı ve JWT verisini tüm route'lara taşı
            .app_data(web::Data::new(AppState {
                db: pool.clone(),
                jwt_secret: jwt_secret.clone(),
            }))
            .wrap(cors) // CORS Middleware
            .wrap(actix_web::middleware::Logger::default()) // Log Middleware
            .configure(routes::config) // Rotaları ayarla
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
