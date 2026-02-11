use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use validator::Validate;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub jwt_secret: String,
}

#[derive(Debug, Serialize, Deserialize, Type, PartialEq, Clone)]
#[sqlx(type_name = "user_role", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserRole {
    #[serde(rename = "MUTLAK İRADE")]
    #[sqlx(rename = "MUTLAK İRADE")]
    MutlakIrade,

    #[serde(rename = "Yüce Hiçlik")]
    #[sqlx(rename = "Yüce Hiçlik")]
    YuceHiclik,

    #[serde(rename = "YARGIÇ")]
    #[sqlx(rename = "YARGIÇ")]
    Yargic,

    #[serde(rename = "MÜRİT")]
    #[sqlx(rename = "MÜRİT")]
    Murit,
}

#[derive(Serialize, FromRow)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
}

#[derive(Deserialize, Validate)]
pub struct RegisterPayload {
    #[validate(length(min = 3, message = "Kullanıcı adı en az 3 karakter olmalı"))]
    pub username: String,

    #[validate(length(min = 6, message = "Şifre en az 6 karakter olmalı"))]
    pub password: String,

    pub role: Option<UserRole>,
}

#[derive(Deserialize, Validate)]
pub struct LoginPayload {
    #[validate(length(min = 1, message = "Kullanıcı adı boş olamaz"))]
    pub username: String,

    #[validate(length(min = 1, message = "Şifre boş olamaz"))]
    pub password: String,
}

#[derive(Deserialize, Validate)]
pub struct CreatePostPayload {
    #[validate(length(min = 5, max = 100, message = "Başlık 5-100 karakter arası olmalı"))]
    pub title: String,

    #[validate(length(min = 10, message = "İçerik çok kısa, biraz daha detay ver."))]
    pub content: String,
}

#[derive(Deserialize, Validate)]
pub struct CreatePetitionPayload {
    #[validate(length(min = 2, message = "İsim çok kısa"))]
    pub sender_name: String,

    #[validate(email(message = "Geçersiz e-posta formatı"))]
    #[validate(contains(pattern = ".com", message = "E-posta adresi .com ile bitmelidir"))]
    pub sender_email: String,

    #[validate(length(min = 3, message = "Konu başlığı çok kısa"))]
    pub subject: String,

    #[validate(length(
        min = 10,
        max = 2000,
        message = "Mesajınız 10 ile 2000 karakter arasında olmalı"
    ))]
    pub message: String,
}

#[derive(Serialize, FromRow)]
pub struct PostResponse {
    pub id: uuid::Uuid,
    pub title: String,
    pub content: String,
    pub author_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: UserRole,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize, Type, PartialEq, Clone)]
#[sqlx(type_name = "petition_status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PetitionStatus {
    BEKLEMEDE,
    OKUNDU,
    ONAYLANDI,
    REDDEDİLDİ,
}

#[derive(Deserialize)]
pub struct UpdatePetitionStatusPayload {
    pub status: PetitionStatus,
}

#[derive(Serialize, FromRow)]
pub struct PetitionResponse {
    pub id: uuid::Uuid,
    pub sender_name: String,
    pub sender_email: String,
    pub subject: String,
    pub message: String,
    pub status: PetitionStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AuditLogResponse {
    pub id: uuid::Uuid,
    pub action: String,
    pub target_details: String,
    pub performed_by_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct DiscipleResponse {
    pub username: String,
    pub role: UserRole,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
