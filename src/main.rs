use axum::{
    Router,
    http::{
        HeaderValue, Method,
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    },
};
use sqlx::postgres::PgPoolOptions;
use tower_http::cors::CorsLayer;
use tracing_subscriber::filter::LevelFilter;

use crate::{config::Config, db::DBClient};

mod config;
mod db;
mod dtos;
mod error;
mod handler;
mod middleware;
mod models;
mod secret;
mod utils;
#[derive(Debug, Clone)]
pub struct AppState {
    pub env: Config,
    pub db_client: DBClient,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .init();

    dotenvy::dotenv().ok();

    let config = Config::init();

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("✅ Connection to the database is successful");
            pool
        }
        Err(err) => {
            eprintln!("❌ Failed to connecto to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    let cors = CorsLayer::new()
        .allow_origin(
            format!("http://localhost:{}", &config.port)
                .parse::<HeaderValue>()
                .unwrap(),
        )
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE])
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT]);

    let db_client = DBClient::new(pool);

    let app_state = AppState {
        env: config.clone(),
        db_client,
    };

    let app = Router::<()>::new().layer(cors);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &config.port))
        .await
        .unwrap();

    println!(
        "{}",
        format!("🚀 Server is running on http://localhost:{}", &config.port)
    );

    axum::serve(listener, app).await.unwrap();
}
