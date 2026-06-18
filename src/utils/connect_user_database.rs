use sqlx::{PgPool, Pool, Postgres, postgres::PgConnectOptions};

use crate::{error::HttpError, models::DbConnection};

pub async fn connect_to_user_database(body: &DbConnection) -> Result<Pool<Postgres>, HttpError> {
    let connect_option = PgConnectOptions::new()
        .host(&body.host)
        .port(body.port)
        .username(&body.username)
        .password(&body.password)
        .database(&body.database);

    let pool = PgPool::connect_with(connect_option)
        .await
        .map_err(|_| HttpError::server_error("Failed to connect to Postgresql Database"))?;

    Ok(pool)
}
