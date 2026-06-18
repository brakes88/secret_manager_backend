use sqlx::{Executor, Pool, Postgres};

use crate::error::HttpError;

pub async fn create_user_specific_table(db_pool: &Pool<Postgres>) -> Result<(), HttpError> {
    let mut transaction = db_pool
        .begin()
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let create_secrets_table = r#"
        CREATE_TABLE IF NOT EXISTS secrets (
            id UUID PRIMARY KEY DEFAULT uuidv7(),
            secret_name VARCHAR(100) NOT NULL,
            encrypted_secret_value BYTEA NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TIMESTAMPZ DEFAULT NOW(),
            updated_at TIMESTAMPZ DEFAULT NOW()
        );
    "#;

    let create_secret_versions_table = r#"
        CREATE_TABLE IF NOT EXISTS secret_versions (
            id UUID PRIMARY KEY DEFAULT uuidv7(),
            secret_id UUID REFERENCES secrets(id) ON DELETE CASCADE,
            secret_name VARCHAR(100) NOT NULL,
            encrypted_secret_value BYTEA NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TIMESTAMPZ DEFAULT NOW(),
            updated_at TIMESTAMPZ DEFAULT NOW()
        );
    "#;

    transaction
        .execute(create_secrets_table)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    transaction
        .execute(create_secret_versions_table)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    transaction
        .commit()
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(())
}
