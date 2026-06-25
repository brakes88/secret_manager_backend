use std::sync::Arc;

use axum::{Extension, Router, middleware};
use tower_http::trace::TraceLayer;

use crate::{
    AppState,
    handler::{
        auth::auth_handler, keys::keys_handler, secrets::secrets_handler,
        secrets_version::secrets_version_handler, settings::settings_handler, user::users_handler,
    },
    middleware::auth,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    let api_route = Router::new()
        .nest("/auth", auth_handler())
        .nest("/user", users_handler().layer(middleware::from_fn(auth)))
        .nest(
            "/settings",
            settings_handler().layer(middleware::from_fn(auth)),
        )
        .nest(
            "/secrets",
            secrets_handler().layer(middleware::from_fn(auth)),
        )
        .nest(
            "/secrets_version",
            secrets_version_handler().layer(middleware::from_fn(auth)),
        )
        .nest("/keys", keys_handler())
        .layer(TraceLayer::new_for_http())
        .layer(Extension(app_state));

    Router::new().nest("/api", api_route)
}
