use actix_web::web;

use crate::handlers::{
    admin::{get_audit_logs, list_disciples},
    auth::{get_me, login_handler, logout_handler, register_handler},
    petitions::{create_petition, delete_petition, get_petitions, update_petition_status},
    posts::{create_post, delete_post, get_my_posts, get_posts},
};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            // --- AUTH ---
            .service(
                web::scope("/auth")
                    .route("/login", web::post().to(login_handler))
                    .route("/register", web::post().to(register_handler)) // Admin Only
                    .route("/me", web::get().to(get_me))
                    .route("/logout", web::post().to(logout_handler)),
            )
            // --- POSTS ---
            .service(
                web::scope("/posts")
                    .route("", web::get().to(get_posts))
                    .route("", web::post().to(create_post))
                    .route("/my", web::get().to(get_my_posts))
                    .route("/{id}", web::delete().to(delete_post)), // Admin/Owner
            )
            // --- ADMIN ---
            .service(
                web::scope("/admin")
                    .route("/logs", web::get().to(get_audit_logs)) // Admin Only
                    .route("/disciples", web::get().to(list_disciples)), // Admin Only
            )
            // --- PETITIONS ---
            .service(
                web::scope("/petitions")
                    .route("", web::post().to(create_petition))
                    .route("", web::get().to(get_petitions)) // Admin Only
                    .route("/{id}", web::delete().to(delete_petition)) // Admin Only
                    .route("/{id}/status", web::put().to(update_petition_status)), // Admin Only
            ),
    );
}
