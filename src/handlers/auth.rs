use actix_web::cookie::{Cookie, SameSite};
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
use crate::models::{AppState, Claims, LoginPayload, RegisterPayload, User, UserRole};

pub async fn login_handler(
    data: web::Data<AppState>,
    body: web::Json<LoginPayload>,
) -> impl Responder {
    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Validation Error", "details": e}));
    }

    let user_result = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(&body.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    if let Some(user) = user_result {
        let parsed_hash = match PasswordHash::new(&user.password_hash) {
            Ok(hash) => hash,
            Err(_) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "System error (Hash)."
                }));
            }
        };

        if Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            let expiration = Utc::now()
                .checked_add_signed(Duration::hours(24))
                .expect("Time error")
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

            let cookie = Cookie::build("auth_token", token)
                .path("/")
                .http_only(true)
                .secure(false)
                .same_site(SameSite::Lax)
                .max_age(actix_web::cookie::time::Duration::days(1))
                .finish();

            return HttpResponse::Ok().cookie(cookie).json(serde_json::json!({
                "msg": "Sealed.",
                "username": user.username,
                "role": user.role
            }));
        }
    }

    HttpResponse::Unauthorized().json(serde_json::json!({
        "error": "Invalid credentials."
    }))
}

pub async fn logout_handler() -> impl Responder {
    let cookie = Cookie::build("auth_token", "")
        .path("/")
        .http_only(true)
        .max_age(actix_web::cookie::time::Duration::seconds(-1))
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({"msg": "Seal broken. You are now shadowless."}))
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
    if admin.role != UserRole::MutlakIrade && admin.role != UserRole::YuceHiclik {
        return HttpResponse::Forbidden().body("You do not have the authority to place this seal.");
    }

    if let Err(e) = body.validate() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Validation Error", "details": e}));
    }

    let new_role = body.role.clone().unwrap_or(UserRole::Murit);

    if new_role == UserRole::MutlakIrade && admin.role != UserRole::MutlakIrade {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Only Absolute Will can create another Absolute Will."
        }));
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .expect("Hash error")
        .to_string();

    let mut tx = match data.db.begin().await {
        Ok(tx) => tx,
        Err(_) => return HttpResponse::InternalServerError().body("DB Error"),
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
            return HttpResponse::Conflict().body("This username is already taken.");
        }
    };

    let log_detail = format!(
        "New Soul Added: {} (Role: {:?})",
        created_username, new_role
    );
    let _ = sqlx::query(
        "INSERT INTO audit_logs (action, performed_by, target_details) VALUES ($1, $2, $3)",
    )
    .bind("KAYIT_OLUSTURMA")
    .bind(admin.id)
    .bind(log_detail)
    .execute(&mut *tx)
    .await;

    if tx.commit().await.is_err() {
        return HttpResponse::InternalServerError().body("Transaction error");
    }

    HttpResponse::Ok()
        .json(serde_json::json!({"msg": "Registration successful", "username": created_username}))
}
