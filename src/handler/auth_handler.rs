use anyhow::{anyhow, Context};
use async_session::{base64, MemoryStore, Session, SessionStore};
use axum::{
    extract::{Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{IntoResponse, Redirect},
};
use axum_extra::{headers, TypedHeader};
use chrono::{DateTime, Duration, Utc};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope,
    TokenResponse,
};
use rand::RngCore;

use crate::{errors::AppError, AppState, AuthRequest, User};

static SESSION_COOKIE_NAME: &str = "SESSION";

pub async fn google_auth(
    State(client): State<BasicClient>,
    State(app_state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            std::env::var("GOOGLE_EMAIL_SCOPE").context("Missing GOOGLE_EMAIL_SCOPE!")?,
        ))
        .add_scope(Scope::new(
            std::env::var("GOOGLE_PROFILE_SCOPE").context("Missing GOOGLE_PROFILE_SCOPE!")?,
        ))
        .add_extra_param("access_type", "offline")
        .add_extra_param("prompt", "consent")
        .url();

    let session_id = generate_session_id();
    let csrf_token_secret = csrf_token.secret();
    let expires_at = Utc::now() + Duration::hours(1);

    // Store CSRF token
    sqlx::query!(
        r#"
            INSERT INTO sessions (session_id, csrf_token, expires_at)
            VALUES (?, ?, ?)
            "#,
        session_id,
        csrf_token_secret,
        expires_at
    )
    .execute(&app_state.db)
    .await?;

    // Attach the session cookie to the response header
    let cookies = [
        // format!("{COOKIE_NAME}={cookie}; SameSite=None; HttpOnly; Secure; Path=/"),
        format!("{SESSION_COOKIE_NAME}={session_id}; SameSite=Lax; HttpOnly; Secure; Path=/"),
    ];
    let mut headers = HeaderMap::new();
    for cookie in cookies {
        headers.append(
            SET_COOKIE,
            cookie.parse().context("Failed to parse cookie")?,
        );
    }

    Ok((headers, Redirect::to(auth_url.as_ref())))
}

pub async fn auth_callback(
    Query(query): Query<AuthRequest>,
    State(store): State<MemoryStore>,
    State(oauth_client): State<BasicClient>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    State(app_state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    csrf_token_validation_workflow(&app_state, &query, &cookies).await?;

    // Get an auth token
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .context("failed in sending request request to authorization server")?;

    let access_token = token.access_token().secret().to_string();

    let refresh_token = token
        .refresh_token()
        .map(|rt| rt.secret().to_string())
        .context("Refresh token missing on callback")?;

    // Fetch user data from google
    let client = reqwest::Client::new();
    let user_data: User = client
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access_token.clone())
        .send()
        .await
        .context("failed in sending request to target Url")?
        .json::<User>()
        .await
        .context("failed to deserialize response as JSON")?;

    // Create a new session filled with user data
    let mut session = Session::new();
    session
        .insert("user", &user_data)
        .context("failed in inserting serialized value into session")?;

    // Store session and get corresponding cookie
    let cookie = store
        .store_session(session)
        .await
        .context("failed to store session")?
        .context("unexpected error retrieving cookie value")?;

    let cookies = [
        format!("{SESSION_COOKIE_NAME}={cookie}; SameSite=Lax; HttpOnly; Secure; Path=/"),
        format!("access_token={access_token}; SameSite=Lax; HttpOnly; Secure; Path=/"),
        format!("refresh_token={refresh_token}; SameSite=Lax; HttpOnly; Secure; Path=/"),
    ];
    let mut headers = HeaderMap::new();
    for cookie in cookies {
        headers.append(
            SET_COOKIE,
            cookie.parse().context("Failed to parse cookie")?,
        );
    }

    Ok((headers, Redirect::to("/")))
}

async fn csrf_token_validation_workflow(
    app_state: &AppState,
    auth_request: &AuthRequest,
    cookies: &headers::Cookie,
) -> Result<(), AppError> {
    // Extract the cookie from the request
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .context("unexpected error getting cookie name")?
        .to_string();

    let stored_csrf_token = get_csrf_token_by_session(app_state, &session_id)
        .await?
        .context("Session not found")?;

    expire_session(app_state, &session_id).await?;

    // Validate CSRF token is the same as the one in the auth request
    if stored_csrf_token != auth_request.state {
        return Err(anyhow!("CSRF token mismatch").into());
    }

    Ok(())
}

fn generate_session_id() -> String {
    let mut key = vec![0u8; 64];
    rand::thread_rng().fill_bytes(&mut key);
    base64::encode(key)
}

async fn get_csrf_token_by_session(
    app_state: &AppState,
    session_id: &String,
) -> Result<Option<String>, AppError> {
    let row = sqlx::query!(
        r#"
            SELECT csrf_token FROM sessions WHERE session_id = ? AND expires_at > NOW()
        "#,
        session_id
    )
    .fetch_optional(&app_state.db)
    .await?;

    Ok(row.map(|r| r.csrf_token))
}

async fn expire_session(app_state: &AppState, session_id: &String) -> Result<(), AppError> {
    sqlx::query!(
        r#"
            UPDATE sessions
            SET expires_at = NOW()
            WHERE session_id = ?
        "#,
        session_id
    )
    .execute(&app_state.db)
    .await?;

    Ok(())
}
