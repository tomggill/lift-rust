use axum::{routing::get, Router};

use crate::{
    handler::auth_handler::{auth_callback, google_auth},
    index, logout, protected, AppState,
};

pub async fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/auth/google", get(google_auth))
        .route("/auth/authorized", get(auth_callback))
        .route("/protected", get(protected))
        .route("/logout", get(logout))
        .with_state(app_state)
}
