use actix_web::{
    dev::Payload, error::ErrorUnauthorized, http, web, Error, FromRequest, HttpRequest,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::future::{ready, Ready};
use uuid::Uuid;

use crate::models::{AppState, Claims};

pub struct AuthenticatedUser {
    pub id: Uuid,
    pub username: String,
    pub role: String,
}

impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let token_cookie = req.cookie("auth_token");

        let token = if let Some(cookie) = token_cookie {
            cookie.value().to_string()
        } else {
            let auth_header = req.headers().get(http::header::AUTHORIZATION);

            if let Some(header_val) = auth_header {
                let auth_str = header_val.to_str().unwrap_or("");
                if auth_str.starts_with("Bearer ") {
                    auth_str[7..].to_string()
                } else {
                    return ready(Err(ErrorUnauthorized(
                        "Geçersiz mühür formatı! (Bearer eksik)",
                    )));
                }
            } else {
                // Ne Cookie var ne Header -> Erişim Reddedildi
                return ready(Err(ErrorUnauthorized(
                    "Mühür bulunamadı! Giriş yapmalısın.",
                )));
            }
        };

        let data = req.app_data::<web::Data<AppState>>().unwrap();
        let decoding_key = DecodingKey::from_secret(data.jwt_secret.as_bytes());
        let validation = Validation::new(Algorithm::HS256);

        match decode::<Claims>(&token, &decoding_key, &validation) {
            Ok(token_data) => {
                let user_id = Uuid::parse_str(&token_data.claims.sub).unwrap_or_default();
                ready(Ok(AuthenticatedUser {
                    id: user_id,
                    username: token_data.claims.username,
                    role: token_data.claims.role,
                }))
            }
            Err(_) => ready(Err(ErrorUnauthorized("Mühür kırık veya zamanı geçmiş!"))),
        }
    }
}
