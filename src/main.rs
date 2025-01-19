mod config;
mod errors;
mod handler;
mod middleware;
mod route;
mod service;
mod state;
mod repository;

use anyhow::{Context, Result};
use axum::{extract::State, response::IntoResponse};
use config::parameter;
use errors::AppError;
use http::Method;
use middleware::log;
use route::create_router;
use serde::{Deserialize, Serialize};
use state::app_state::AppState;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    parameter::init();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("sqlx=debug,{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting up the application...");


    let app_state = AppState::new().await?;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    let app = create_router(app_state)
        .await
        .layer(cors)
        .layer(axum::middleware::from_fn(log::log_request));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .context("failed to bind TcpListener")
        .unwrap();

    tracing::debug!(
        "Application started - Listening on {}",
        listener
            .local_addr()
            .context("failed to return local address")
            .unwrap()
    );

    axum::serve(listener, app).await.unwrap();

    Ok(())
}

// TODO - Bad naming - need to redo the structs for google responses.
#[derive(Debug, Serialize, Deserialize)]
struct User {
    sub: String,
    given_name: String,
    family_name: String,
    email: String,
}

async fn index(State(app_state): State<AppState>) -> impl IntoResponse {
    match app_state.user_context.read().await.as_ref() {
        Some(user) => format!(
            "Hey {}! You're logged in!\nYou may now access `/protected`.\nLog out with `/logout`.",
            user.name
        ),
        None => "You're not logged in.\nVisit `/auth/google` to do so.".to_string(),
    }
}

async fn protected(State(app_state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    match app_state.user_context.read().await.as_ref() {
        Some(user) => Ok(format!("Welcome to the protected area, {}!", user.name)),
        None => Err(anyhow::anyhow!("You're not logged in.").into()),
    }
}
