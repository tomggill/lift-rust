mod config;
mod errors;
mod handler;
mod middleware;
mod route;
mod service;

use anyhow::{Context, Result};
use axum::{extract::{FromRef, State}, response::{IntoResponse, Redirect, Response}
};
use dotenv::dotenv;
use errors::AppError;
use http::Method;
use middleware::log;
use reqwest::Client;
use route::create_router;
use serde::{Deserialize, Serialize};
use service::google_token_service::{GoogleTokenService, TokenServiceTrait};
use sqlx::{mysql::MySqlPoolOptions, MySqlPool};
use tokio::sync::RwLock;
use std::{env, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct UserContext {
    user_id: u64,
    email: String,
    name: String,
}


#[derive(Clone)]
struct AppState {
    http_client: Client,
    db: MySqlPool,
    user_context: Arc<RwLock<Option<UserContext>>>,
    google_token_service: GoogleTokenService,
}

impl FromRef<AppState> for GoogleTokenService {
    fn from_ref(state: &AppState) -> Self {
        state.google_token_service.clone()
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting up the application...");

    let db = get_sql_pool().await.unwrap();
    let http_client = Client::new();
    let app_state = AppState {
        db,
        http_client,
        user_context: Arc::new(RwLock::new(None)),
        google_token_service: GoogleTokenService::new(),
    };

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
}

async fn get_sql_pool() -> Result<MySqlPool, AppError> {
    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .context("Failed to connect to the database")?;
    tracing::info!("Connection to the database is successful!");
    Ok(pool)
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    sub: String,
    given_name: String,
    family_name: String,
    email: String,
}

// Session is optional
async fn index(State(app_state): State<AppState>) -> impl IntoResponse {
    match app_state.user_context.read().await.as_ref() {
        Some(user) => format!(
            "Hey {}! You're logged in!\nYou may now access `/protected`.\nLog out with `/logout`.",
            user.name
        ),
        None => "You're not logged in.\nVisit `/auth/discord` to do so.".to_string(),
    }
}

// Valid user session required. If there is none, redirect to the auth page
async fn protected(State(app_state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    match app_state.user_context.read().await.as_ref() {
        Some(user) => Ok(format!("Welcome to the protected area, {}!", user.name)),
        None => Err(anyhow::anyhow!("You're not logged in.").into()),
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequest {
    code: String,
    state: String,
}

struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/auth/google").into_response()
    }
}
