use crate::auth::AuthenticatedUser;
use crate::models::{AppState, CreatePostPayload, PostResponse, UserRole};
use actix_web::{web, HttpResponse, Responder};
use sqlx::Row;
use validator::Validate;

pub async fn create_post(
    data: web::Data<AppState>,
    user: AuthenticatedUser,
    body: web::Json<CreatePostPayload>,
) -> impl Responder {
    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "İçerik Hatası", "details": e}));
    }

    let result = sqlx::query(
        "INSERT INTO posts (title, content, user_id) VALUES ($1, $2, $3) RETURNING id, title, content, created_at"
    )
    .bind(&body.title)
    .bind(&body.content)
    .bind(user.id)
    .fetch_one(&data.db)
    .await;

    match result {
        Ok(row) => {
            let new_post = PostResponse {
                id: row.get("id"),
                title: row.get("title"),
                content: row.get("content"),
                author_name: user.username,
                created_at: row.get("created_at"),
            };
            HttpResponse::Ok().json(new_post)
        }
        Err(_) => HttpResponse::InternalServerError().body("Vahiy kaydedilemedi."),
    }
}

pub async fn get_posts(data: web::Data<AppState>) -> impl Responder {
    let sql = r#"
        SELECT p.id, p.title, p.content, p.created_at, u.username as author_name 
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    "#;

    let result = sqlx::query_as::<_, PostResponse>(sql)
        .fetch_all(&data.db)
        .await;

    match result {
        Ok(posts) => HttpResponse::Ok().json(posts),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

pub async fn get_my_posts(data: web::Data<AppState>, user: AuthenticatedUser) -> impl Responder {
    let sql = r#"
        SELECT p.id, p.title, p.content, p.created_at, u.username as author_name 
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id = $1
        ORDER BY p.created_at DESC
    "#;

    let result = sqlx::query_as::<_, PostResponse>(sql)
        .bind(user.id)
        .fetch_all(&data.db)
        .await;

    match result {
        Ok(posts) => HttpResponse::Ok().json(posts),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

pub async fn delete_post(
    data: web::Data<AppState>,
    user: AuthenticatedUser,
    path: web::Path<uuid::Uuid>,
) -> impl Responder {
    let post_id = path.into_inner();

    let post_owner_check = sqlx::query("SELECT user_id FROM posts WHERE id = $1")
        .bind(post_id)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    if let Some(row) = post_owner_check {
        let owner_id: uuid::Uuid = row.get("user_id");

        // Enum kontrolü: Modeline uygun Türkçe isimler
        let is_admin = user.role == UserRole::MutlakIrade || user.role == UserRole::YuceHiclik;
        let is_owner = user.id == owner_id;

        if is_owner || is_admin {
            let _ = sqlx::query("DELETE FROM posts WHERE id = $1")
                .bind(post_id)
                .execute(&data.db)
                .await;

            if is_admin && !is_owner {
                let log_detail = format!("Vahiy Silindi. Post ID: {}", post_id);
                let _ = sqlx::query(
                    "INSERT INTO audit_logs (action, performed_by, target_details) VALUES ($1, $2, $3)"
                )
                .bind("ICERIK_SILME")
                .bind(user.id)
                .bind(log_detail)
                .execute(&data.db)
                .await;
            }

            return HttpResponse::Ok().json(serde_json::json!({"msg": "Vahiy yoklukta kayboldu."}));
        } else {
            return HttpResponse::Forbidden().body("Bu yazıya hükmedemezsin.");
        }
    }

    HttpResponse::NotFound().body("Böyle bir vahiy yok.")
}
