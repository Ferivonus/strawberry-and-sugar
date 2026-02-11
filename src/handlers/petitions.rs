use crate::auth::AuthenticatedUser;
use crate::models::{
    AppState, CreatePetitionPayload, PetitionResponse, PetitionStatus, UpdatePetitionStatusPayload,
    UserRole,
};
use actix_web::{web, HttpResponse, Responder};
use validator::Validate;

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
        Err(_) => HttpResponse::InternalServerError().body("Mühür basılamadı."),
    }
}

pub async fn get_petitions(data: web::Data<AppState>, admin: AuthenticatedUser) -> impl Responder {
    // Türkçe Enum kontrolü
    if admin.role != UserRole::MutlakIrade && admin.role != UserRole::YuceHiclik {
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
        Err(_) => HttpResponse::InternalServerError().body("Arşiv hatası."),
    }
}

pub async fn update_petition_status(
    data: web::Data<AppState>,
    admin: AuthenticatedUser,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdatePetitionStatusPayload>,
) -> impl Responder {
    // Türkçe Enum kontrolü
    if admin.role != UserRole::MutlakIrade && admin.role != UserRole::YuceHiclik {
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
    // Türkçe Enum kontrolü
    if admin.role != UserRole::MutlakIrade && admin.role != UserRole::YuceHiclik {
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
