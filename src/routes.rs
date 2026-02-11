use crate::handlers::{
    create_petition, create_post, delete_petition, delete_post, get_audit_logs, get_me,
    get_my_posts, get_petitions, get_posts, list_disciples, login_handler, logout_handler,
    register_handler, update_petition_status,
};
use actix_web::web;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            // Authentication
            .route("/auth/login", web::post().to(login_handler))
            .route("/auth/register", web::post().to(register_handler)) // admin only
            .route("/auth/me", web::get().to(get_me))
            .route("/auth/logout", web::post().to(logout_handler))
            // Posts
            .route("/posts", web::get().to(get_posts))
            .route("/posts", web::post().to(create_post))
            .route("/posts/my", web::get().to(get_my_posts))
            .route("/posts/{id}", web::delete().to(delete_post)) // Admin Only
            // Admin
            .route("/admin/logs", web::get().to(get_audit_logs))
            .route("/admin/disciples", web::get().to(list_disciples))
            // Dilekçeler
            .route("/petitions", web::post().to(create_petition)) //  Public
            .route("/petitions", web::get().to(get_petitions)) // Admin Only
            .route("/petitions/{id}", web::delete().to(delete_petition)) // Admin Only
            .route("/petitions/{id}", web::put().to(update_petition_status)), // Admin Only
    );
}
