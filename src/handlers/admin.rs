use crate::auth::AuthenticatedUser;
use crate::models::{AppState, AuditLogResponse, DiscipleResponse, UserRole};
use actix_web::{web, HttpResponse, Responder};

pub async fn get_audit_logs(data: web::Data<AppState>, admin: AuthenticatedUser) -> impl Responder {
    if admin.role != UserRole::MutlakIrade && admin.role != UserRole::YuceHiclik {
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
    if admin.role != UserRole::MutlakIrade && admin.role != UserRole::YuceHiclik {
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
