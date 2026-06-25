use std::sync::Arc;

use axum::{Extension, Json, Router, extract::Query, response::IntoResponse, routing::get};

use crate::{
    AppState,
    db::UserExt,
    dtos::{RequestQuerySecretByKeyDto, RequestQuerySecretByKeyResponseDto},
    error::{ErrorMessage, HttpError},
    secret::{PostgresSecretRepository, SecretRepository},
    utils::{connect_user_database::connect_to_user_database, decrypt::decrypt},
};

pub fn keys_handler() -> Router {
    Router::new().route("/secret", get(get_secret_by_key))
}

pub async fn get_secret_by_key(
    Query(query_params): Query<RequestQuerySecretByKeyDto>,
    Extension(app_state): Extension<Arc<AppState>>,
) -> Result<impl IntoResponse, HttpError> {
    let user_api_key = query_params.key;

    let result = app_state
        .db_client
        .get_user(None, None, None, Some(&user_api_key))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result
        .ok_or_else(|| HttpError::unauthorized(ErrorMessage::UserNoLongerExist.to_string()))?;

    let db_connection = &user
        .db_connection
        .ok_or_else(|| HttpError::server_error("DB Connection not found".to_string()))?;

    let user_db_pool = connect_to_user_database(db_connection).await?;

    let repo = PostgresSecretRepository::new(&user_db_pool);

    let secret_id = query_params.secret;
    let secret = repo.get_secret_by_id(secret_id).await?;

    let encryption_method = &user
        .encryption_method
        .ok_or_else(|| HttpError::server_error("Encryption method not found".to_string()))?;

    let encryption_key = &user
        .keys
        .ok_or_else(|| HttpError::server_error("Encryption key not found".to_string()))?;

    let decrypted_value_bytes = decrypt(
        &encryption_method,
        &encryption_key,
        &secret.encrypted_secret_value,
    );

    let decrypted_value = String::from_utf8(decrypted_value_bytes)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = RequestQuerySecretByKeyResponseDto {
        value: decrypted_value,
    };

    Ok(Json(response))
}
