use axum::{middleware, routing::get, Router};

use crate::{
    handler::auth_handler::{auth_callback, google_auth},
    index, logout,
    middleware::auth as auth_middleware,
    protected, AppState,
};

pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/auth/google", get(google_auth))
        .route("/auth/authorized", get(auth_callback))
}

pub fn protected_routes(app_state: AppState) -> Router<AppState> {
    Router::new()
        .route("/protected", get(protected))
        .route("/logout", get(logout))
        .layer(middleware::from_fn_with_state(
            app_state,
            auth_middleware::auth_2,
        ))
}

pub async fn create_router(app_state: AppState) -> Router {
    Router::new()
        .merge(public_routes())
        .merge(protected_routes(app_state.clone()))
        .with_state(app_state)
}
