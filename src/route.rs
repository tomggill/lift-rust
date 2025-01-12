use axum::{routing::get, Router};

use crate::{google_auth, index, login_authorized, logout, protected, AppState};

pub async fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/auth/google", get(google_auth))
        .route("/auth/authorized", get(login_authorized))
        .route("/protected", get(protected))
        .route("/logout", get(logout))
        .with_state(app_state)
}
