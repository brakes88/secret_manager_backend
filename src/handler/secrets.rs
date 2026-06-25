use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::Query,
    response::IntoResponse,
    routing::{get, post, put},
};
use validator::Validate;

use crate::{
    AppState,
    dtos::{
        EditSecretDto, FilterSecretDto, RequestQueryDto, Response, SaveSecretDto, SecretResponse,
        SecretResponseDto,
    },
    error::HttpError,
    middleware::JWTAuthMiddleware,
    secret::{PostgresSecretRepository, SecretRepository},
    utils::{connect_user_database::connect_to_user_database, decrypt::decrypt, encrypt::encrypt},
};

pub fn secrets_handler() -> Router {
    Router::new()
        .route("/get", get(get_secrets))
        .route("/save", post(save_secrets))
        .route("/update", put(edit_secrets))
}

#[derive(Debug)]
pub struct SavedSecret {
    pub secret_name: String,
    pub encrypted_secret_value: Vec<u8>,
    pub version: i32,
}

pub async fn get_secrets(
    Query(query_params): Query<RequestQueryDto>,
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, HttpError> {
    query_params
        .validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = user.user;

    let db_connection = &user
        .db_connection
        .ok_or_else(|| HttpError::server_error("DB Connection not found".to_string()))?;

    let user_db_pool = connect_to_user_database(db_connection).await?;

    let repo: PostgresSecretRepository<'_> = PostgresSecretRepository::new(&user_db_pool);

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    let (total_count, secrets) = repo.get_secrets(page as u32, limit as u32).await?;

    let encryption_method = &user
        .encryption_method
        .ok_or_else(|| HttpError::server_error("Encryption method not found".to_string()))?;

    let encryption_key = &user
        .keys
        .ok_or_else(|| HttpError::server_error("Encryption key not found".to_string()))?;

    let mut send_secrets: Vec<SecretResponse> = Vec::new();

    for secret in secrets {
        let decrpyted_value_bytes = decrypt(
            &encryption_method,
            &encryption_key,
            &secret.encrypted_secret_value,
        );

        let decrypted_value = String::from_utf8(decrpyted_value_bytes).map_err(|e| {
            HttpError::server_error(format!("Decryption Failed: {}", e.to_string()))
        })?;

        send_secrets.push(SecretResponse {
            id: secret.id,
            secret_name: secret.secret_name,
            secret_value: decrypted_value,
            version: secret.version,
            created_at: secret.created_at,
            updated_at: secret.updated_at,
        });
    }

    let filter_secrets = FilterSecretDto::filter_secrets(&send_secrets);

    let response = SecretResponseDto {
        secret: filter_secrets,
        total_count,
    };

    Ok(Json(response))
}

pub async fn save_secrets(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<Vec<SaveSecretDto>>,
) -> Result<impl IntoResponse, HttpError> {
    for dto in &body {
        dto.validate()
            .map_err(|e| HttpError::bad_request(e.to_string()))?;
    }

    let user = user.user;

    let encryption_method = &user
        .encryption_method
        .ok_or_else(|| HttpError::server_error("Encryption method not found".to_string()))?;

    let encryption_key = &user
        .keys
        .ok_or_else(|| HttpError::server_error("Encryption key not found".to_string()))?;

    let mut saved_secrets: Vec<SavedSecret> = Vec::new();

    for dto in body {
        let encrypted_secret_value = encrypt(
            &encryption_method,
            &encryption_key,
            &dto.secret_value.as_bytes(),
        );

        saved_secrets.push(SavedSecret {
            secret_name: dto.secret_name,
            encrypted_secret_value,
            version: 1,
        });
    }

    let db_connection = &user
        .db_connection
        .ok_or_else(|| HttpError::server_error("DB Connection not found".to_string()))?;

    let user_db_pool = connect_to_user_database(db_connection).await?;

    let repo: PostgresSecretRepository<'_> = PostgresSecretRepository::new(&user_db_pool);

    repo.save_secrets(saved_secrets)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        status: "success",
        message: "Secrets saved successfully".to_string(),
    };

    Ok(Json(response))
}

pub async fn edit_secrets(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<EditSecretDto>,
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = user.user;

    let encryption_method = &user
        .encryption_method
        .ok_or_else(|| HttpError::server_error("Encryption method not found".to_string()))?;

    let encryption_key = &user
        .keys
        .ok_or_else(|| HttpError::server_error("Encryption key not found".to_string()))?;

    let encrypted_secret_value = encrypt(
        &*encryption_method,
        &encryption_key,
        &body.secret_value.as_bytes(),
    );

    let db_connection = &user
        .db_connection
        .ok_or_else(|| HttpError::server_error("DB Connection not found".to_string()))?;

    let user_db_pool = connect_to_user_database(db_connection).await?;

    let repo: PostgresSecretRepository<'_> = PostgresSecretRepository::new(&user_db_pool);

    repo.edit_secrets(body.id, body.secret_name, encrypted_secret_value)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        status: "success",
        message: "Secrets updated successfully".to_string(),
    };

    Ok(Json(response))
}
