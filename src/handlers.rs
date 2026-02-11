use actix_web::{web, HttpResponse, Responder};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use sqlx::Row;
use validator::Validate;

use crate::auth::AuthenticatedUser;
use crate::models::AuditLogResponse;
use crate::models::{
    AppState, Claims, CreatePetitionPayload, CreatePostPayload, DiscipleResponse, LoginPayload,
    PetitionResponse, PetitionStatus, PostResponse, RegisterPayload, UpdatePetitionStatusPayload,
    User,
};

use actix_web::cookie::{Cookie, SameSite};

pub async fn login_handler(
    data: web::Data<AppState>,
    body: web::Json<LoginPayload>,
) -> impl Responder {
    // 1. Validasyon
    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Girdi Hatası", "details": e}));
    }

    let user_result = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(&body.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    if let Some(user) = user_result {
        let parsed_hash = PasswordHash::new(&user.password_hash).unwrap();

        if Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            let expiration = Utc::now()
                .checked_add_signed(Duration::hours(24))
                .expect("Zaman hatası")
                .timestamp() as usize;

            let claims = Claims {
                sub: user.id.to_string(),
                username: user.username.clone(),
                role: user.role.clone(),
                exp: expiration,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(data.jwt_secret.as_bytes()),
            )
            .unwrap();

            // --- GÜVENLİK DEVRİMİ BURADA ---
            let cookie = Cookie::build("auth_token", token)
                .path("/")
                .http_only(true) // JS erişemez (XSS Koruması)
                .secure(false) // Localhost'ta false, HTTPS'te true olmalı!
                .same_site(SameSite::Lax) // CSRF Koruması
                .max_age(actix_web::cookie::time::Duration::days(1))
                .finish();

            // Token'ı JSON olarak dönmüyoruz, sadece kullanıcı bilgisini dönüyoruz.
            // Token "Set-Cookie" header'ı ile gidiyor.
            return HttpResponse::Ok().cookie(cookie).json(serde_json::json!({
                "msg": "Mühürlendi.",
                "username": user.username,
                "role": user.role
            }));
        }
    }
    HttpResponse::Unauthorized().body("Kimlik doğrulanamadı. Gölgede kal.")
}

// ÇIKIŞ YAP (Mührü Kır)
// Cookie'yi silmek için süresini geçmişe ayarlarız.
pub async fn logout_handler() -> impl Responder {
    let cookie = Cookie::build("auth_token", "")
        .path("/")
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::seconds(-1)) // Geçmiş zaman
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({"msg": "Mühür kırıldı. Artık gölgesizsin."}))
}

pub async fn get_me(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "id": user.id,
        "username": user.username,
        "role": user.role
    }))
}

pub async fn register_handler(
    data: web::Data<AppState>,
    admin: AuthenticatedUser,
    body: web::Json<RegisterPayload>,
) -> impl Responder {
    if admin.role != "MUTLAK İRADE" && admin.role != "Yüce Hiçlik" {
        return HttpResponse::Forbidden().body("Bu mührü vurmaya yetkin yok.");
    }

    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Validasyon Hatası", "details": e}));
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .expect("Hash hatası")
        .to_string();

    let new_role = body.role.clone().unwrap_or_else(|| "MÜRİT".to_string());

    let mut tx = match data.db.begin().await {
        Ok(tx) => tx,
        Err(_) => return HttpResponse::InternalServerError().body("DB Hatası"),
    };

    let user_insert = sqlx::query(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING username",
    )
    .bind(&body.username)
    .bind(&password_hash)
    .bind(&new_role)
    .fetch_one(&mut *tx)
    .await;

    let created_username: String = match user_insert {
        Ok(row) => row.get("username"),
        Err(_) => {
            let _ = tx.rollback().await;
            return HttpResponse::Conflict().body("Bu isim zaten alınmış.");
        }
    };

    let log_detail = format!("Yeni Ruh Eklendi: {} (Rol: {})", created_username, new_role);
    let _ = sqlx::query(
        "INSERT INTO audit_logs (action, performed_by, target_details) VALUES ($1, $2, $3)",
    )
    .bind("KAYIT_OLUSTURMA")
    .bind(admin.id)
    .bind(log_detail)
    .execute(&mut *tx)
    .await;

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError().body("Transaction hatası");
    }

    HttpResponse::Ok()
        .json(serde_json::json!({"msg": "Kayıt başarılı", "username": created_username}))
}

pub async fn get_audit_logs(data: web::Data<AppState>, admin: AuthenticatedUser) -> impl Responder {
    if admin.role != "MUTLAK İRADE" && admin.role != "Yüce Hiçlik" {
        return HttpResponse::Forbidden().finish();
    }

    let sql = r#"
        SELECT 
            a.id, a.action, a.target_details, a.created_at,
            u.username as performed_by_name
        FROM audit_logs a
        LEFT JOIN users u ON a.performed_by = u.id
        ORDER BY a.created_at DESC
        LIMIT 100
    "#;

    let logs = sqlx::query_as::<_, AuditLogResponse>(sql)
        .fetch_all(&data.db)
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(logs)
}

pub async fn list_disciples(data: web::Data<AppState>, admin: AuthenticatedUser) -> impl Responder {
    if admin.role != "MUTLAK İRADE" && admin.role != "Yüce Hiçlik" {
        return HttpResponse::Forbidden().finish();
    }

    let users = sqlx::query_as::<_, DiscipleResponse>(
        "SELECT username, role, created_at FROM users ORDER BY created_at DESC",
    )
    .fetch_all(&data.db)
    .await
    .unwrap_or_default();

    HttpResponse::Ok().json(users)
}

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

        let is_admin = user.role == "MUTLAK İRADE" || user.role == "Yüce Hiçlik";
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

pub async fn create_petition(
    data: web::Data<AppState>,
    body: web::Json<CreatePetitionPayload>,
) -> impl Responder {
    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validasyon Hatası",
            "details": e
        }));
    }

    let result = sqlx::query(
        "INSERT INTO petitions (sender_name, sender_email, subject, message) VALUES ($1, $2, $3, $4) RETURNING id"
    )
    .bind(&body.sender_name)
    .bind(&body.sender_email)
    .bind(&body.subject)
    .bind(&body.message)
    .fetch_one(&data.db)
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"msg": "Arzuhal Konsey'e iletildi."})),
        Err(e) => {
            eprintln!("Arzuhal hatası: {}", e);
            HttpResponse::InternalServerError().body("Mühür basılamadı.")
        }
    }
}

pub async fn get_petitions(data: web::Data<AppState>, admin: AuthenticatedUser) -> impl Responder {
    if admin.role != "MUTLAK İRADE" && admin.role != "Yüce Hiçlik" {
        return HttpResponse::Forbidden().body("Yetkisiz Erişim.");
    }

    let _ = sqlx::query(
        "INSERT INTO audit_logs (action, performed_by, target_details) VALUES ($1, $2, $3)",
    )
    .bind("ARZUHAL_OKUMA")
    .bind(admin.id)
    .bind("Arzuhal Arşivi İncelendi")
    .execute(&data.db)
    .await;

    let query_result = sqlx::query_as::<_, PetitionResponse>(
        "SELECT id, sender_name, sender_email, subject, message, status, created_at FROM petitions ORDER BY created_at DESC"
    )
    .fetch_all(&data.db)
    .await;

    match query_result {
        Ok(petitions) => HttpResponse::Ok().json(petitions),
        Err(e) => {
            eprintln!("Arzuhal arşiv hatası: {}", e);
            HttpResponse::InternalServerError().body("Arşiv hatası.")
        }
    }
}

pub async fn update_petition_status(
    data: web::Data<AppState>,
    admin: AuthenticatedUser,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdatePetitionStatusPayload>,
) -> impl Responder {
    if admin.role != "MUTLAK İRADE" && admin.role != "Yüce Hiçlik" {
        return HttpResponse::Forbidden().body("Yetkisiz Erişim.");
    }

    let petition_id = path.into_inner();
    let new_status = &body.status;

    let current_info: Option<(PetitionStatus, String)> =
        sqlx::query_as("SELECT status, sender_name FROM petitions WHERE id = $1")
            .bind(petition_id)
            .fetch_optional(&data.db)
            .await
            .unwrap_or(None);

    if current_info.is_none() {
        return HttpResponse::NotFound().body("Arzuhal bulunamadı.");
    }

    let (old_status, sender_name) = current_info.unwrap();

    if &old_status == new_status {
        return HttpResponse::Ok().json(serde_json::json!({"msg": "Durum zaten aynı."}));
    }

    let update_result = sqlx::query("UPDATE petitions SET status = $1 WHERE id = $2")
        .bind(new_status)
        .bind(petition_id)
        .execute(&data.db)
        .await;

    match update_result {
        Ok(_) => {
            let log_detail = format!(
                "Arzuhal Durumu Değişti. Gönderen: {}. ({:?} -> {:?})",
                sender_name, old_status, new_status
            );
            let _ = sqlx::query(
                "INSERT INTO audit_logs (action, performed_by, target_details) VALUES ($1, $2, $3)",
            )
            .bind("DURUM_GUNCELLEME")
            .bind(admin.id)
            .bind(log_detail)
            .execute(&data.db)
            .await;

            HttpResponse::Ok().json(serde_json::json!({
                "msg": "Arzuhal statüsü mühürlendi.",
                "new_status": new_status
            }))
        }
        Err(_) => HttpResponse::InternalServerError().body("Durum güncellenemedi."),
    }
}

pub async fn delete_petition(
    data: web::Data<AppState>,
    admin: AuthenticatedUser,
    path: web::Path<uuid::Uuid>,
) -> impl Responder {
    if admin.role != "MUTLAK İRADE" && admin.role != "Yüce Hiçlik" {
        return HttpResponse::Forbidden().finish();
    }

    let petition_id = path.into_inner();

    let target_info: Option<(String, String)> =
        sqlx::query_as("SELECT sender_name, subject FROM petitions WHERE id = $1")
            .bind(petition_id)
            .fetch_optional(&data.db)
            .await
            .unwrap_or(None);

    if target_info.is_none() {
        return HttpResponse::NotFound().body("Yakılacak arzuhal bulunamadı.");
    }
    let (sender_name, subject) = target_info.unwrap();

    let result = sqlx::query("DELETE FROM petitions WHERE id = $1")
        .bind(petition_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => {
            let log_detail = format!(
                "Arzuhal İmha Edildi. Gönderen: {}, Konu: {}, ID: {}",
                sender_name, subject, petition_id
            );

            let _ = sqlx::query(
                "INSERT INTO audit_logs (action, performed_by, target_details) VALUES ($1, $2, $3)",
            )
            .bind("ARZUHAL_SILME")
            .bind(admin.id)
            .bind(log_detail)
            .execute(&data.db)
            .await;

            HttpResponse::Ok().json(serde_json::json!({"msg": "Arzuhal yakıldı."}))
        }
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}
