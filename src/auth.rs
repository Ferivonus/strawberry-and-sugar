use actix_web::{dev::Payload, error::ErrorUnauthorized, web, FromRequest, HttpRequest};
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::future::{ready, Ready};
use uuid::Uuid;

use crate::models::{AppState, Claims, UserRole};
pub struct AuthenticatedUser {
    pub id: Uuid,
    pub username: String,
    pub role: UserRole,
}

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let data = req.app_data::<web::Data<AppState>>().unwrap();

        // I don't wanna feel alone.
        let auth_token = match req.cookie("auth_token") {
            Some(cookie) => cookie.value().to_string(),
            None => return ready(Err(ErrorUnauthorized("Giriş yapmanız gerekiyor."))),
        };

        let token_data = decode::<Claims>(
            &auth_token,
            &DecodingKey::from_secret(data.jwt_secret.as_bytes()),
            &Validation::default(),
        );

        match token_data {
            Ok(token) => {
                let user_id = Uuid::parse_str(&token.claims.sub).unwrap_or_default();

                ready(Ok(AuthenticatedUser {
                    id: user_id,
                    username: token.claims.username,
                    role: token.claims.role,
                }))
            }
            Err(_) => ready(Err(ErrorUnauthorized("Geçersiz veya süresi dolmuş mühür."))),
        }
    }
}
