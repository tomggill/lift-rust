mod client;
mod config;
mod errors;
mod handler;
mod middleware;
mod route;

use anyhow::{Context, Result};
use async_session::{MemoryStore, SessionStore};
use axum::{
    extract::{FromRef, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::{extract::cookie::Cookie, headers, TypedHeader};
use dotenv::dotenv;
use errors::AppError;
use http::{header::SET_COOKIE, HeaderMap, Method};
use oauth2::{basic::BasicClient, reqwest::async_http_client, AccessToken, AuthUrl, ClientId, ClientSecret, RedirectUrl, RevocableToken, RevocationUrl, StandardRevocableToken, TokenUrl};
use reqwest::Client;
use route::create_router;
use serde::{Deserialize, Serialize};
use sqlx::{mysql::MySqlPoolOptions, MySqlPool};
use tokio::sync::RwLock;
use std::{env, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static COOKIE_NAME: &str = "SESSION";

#[derive(Clone)]
struct UserContext {
    user_id: u64,
    email: String,
    name: String,
}


#[derive(Clone)]
struct AppState {
    oauth_client: BasicClient,
    http_client: Client,
    db: MySqlPool,
    user_context: Arc<RwLock<Option<UserContext>>>,

}

impl FromRef<AppState> for BasicClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
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

    // `MemoryStore` is just used as an example. Don't use this in production.
    let oauth_client = oauth_client().unwrap();
    let db = get_sql_pool().await.unwrap();
    let http_client = Client::new();
    let app_state = AppState {
        oauth_client,
        db,
        http_client,
        user_context: Arc::new(RwLock::new(None)),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any);

    let app = create_router(app_state).await.layer(cors);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .context("failed to bind TcpListener")
        .unwrap();

    tracing::debug!(
        "listening on {}",
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

fn oauth_client() -> Result<BasicClient, AppError> {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").context("Missing CLIENT_ID!")?;
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").context("Missing CLIENT_SECRET!")?;
    let redirect_url = std::env::var("GOOGLE_REDIRECT_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000/auth/authorized".to_string());

    let auth_url = std::env::var("GOOGLE_AUTH_URL")
        .unwrap_or_else(|_| "https://accounts.google.com/o/oauth2/v2/auth".to_string());

    let token_url = std::env::var("GOOGLE_TOKEN_URL")
        .unwrap_or_else(|_| "https://oauth2.googleapis.com/token".to_string());

    let revocation_url = std::env::var("GOOGLE_REVOCATION_URL")
        .unwrap_or_else(|_| "https://oauth2.googleapis.com/revoke".to_string());


    Ok(BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url).context("failed to create new authorization server URL")?,
        Some(TokenUrl::new(token_url).context("failed to create new token endpoint URL")?),
    )
    .set_redirect_uri(
        RedirectUrl::new(redirect_url).context("failed to create new redirection URL")?,
    )
    .set_revocation_uri(
        RevocationUrl::new(revocation_url).context("failed to create new revocation URL")?,
    )
    )
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

async fn logout(
    State(app_state): State<AppState>,
    State(oauth_client): State<BasicClient>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    // TODO: Revocation of access and refresh token not necessary as revoking a refresh 
    // token in Google OAUTH 2.0 also revokes the associated access token and vice versa.
    // See: https://cloud.google.com/apigee/docs/api-platform/security/oauth/validating-and-invalidating-access-tokens
    if let Some(refresh_token) = cookies.get("refresh_token") {
        revoke_token(refresh_token.to_string(), &oauth_client).await?;
    }

    {
        let mut user_context_lock = app_state.user_context.write().await;
        *user_context_lock = None;
    }

    // TODO - refactor
    let empty_access_token = Cookie::build(("access_token", ""))
        .path("/")
        .http_only(true)
        .build();
    let empty_refresh_token = Cookie::build(("refresh_token", ""))
        .path("/")
        .http_only(true)
        .build();

    let mut headers = HeaderMap::new();
    headers.append(
        SET_COOKIE,
        empty_access_token.to_string().parse().unwrap(),
    );
    headers.append(
        SET_COOKIE,
        empty_refresh_token.to_string().parse().unwrap(),
    );


    // Redirect to the home page
    Ok((headers, Redirect::to("/")))
}

async fn revoke_token(token: String, oauth_client: &BasicClient) -> Result<(), AppError> {
    let token = AccessToken::new(token);
    let revocable_token: StandardRevocableToken = token.into();

    let response = oauth_client.revoke_token(revocable_token)?.request_async(async_http_client).await;

    if let Err(error) = response {
        return Err(AppError::from(error));
    } 
    Ok(())
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