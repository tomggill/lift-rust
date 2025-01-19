use anyhow::{anyhow, Context};
use async_session::base64;
use axum::{
    extract::{Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{IntoResponse, Redirect},
};
use axum_extra::{extract::cookie::Cookie, headers, TypedHeader};
use chrono::{Duration, Utc};
use rand::RngCore;

use crate::{config::database::DatabaseTrait, errors::AppError, service::google_token_service::{GoogleTokenService, TokenServiceTrait}, state::app_state::UserContext, AppState, AuthRequest, User};

static SESSION_COOKIE_NAME: &str = "SESSION";

pub async fn google_auth(
    State(app_state): State<AppState>,
    State(google_token_service): State<GoogleTokenService>,
) -> Result<impl IntoResponse, AppError> {
    let (auth_url, csrf_token) = google_token_service.generate_authorisation_url().await?;

    let session_id = generate_session_id();

    store_csrf_token(&session_id, csrf_token.secret(), &app_state).await?;

    let cookies = [format!(
        "{SESSION_COOKIE_NAME}={session_id}; SameSite=Lax; HttpOnly; Secure; Path=/"
    )];
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
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    State(app_state): State<AppState>,
    State(google_token_service): State<GoogleTokenService>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Handling google auth callback");
    csrf_token_validation_workflow(&app_state, &query, &cookies).await?;

    let (access_token, refresh_token) = google_token_service.exchange_authorisation_code(query.code.clone()).await?;

    let access_token = access_token.secret().to_string();

    let refresh_token = refresh_token.secret().to_string();

    let user_data = google_token_service.get_user_info(&access_token).await?;


    let user_context = app_state.user_service.get_or_insert_user(&user_data).await?;
    {
        let mut user_context_lock = app_state.user_context.write().await;
        *user_context_lock = Some(user_context.clone());
    }

    let cookies = [
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
    tracing::debug!("Validating CSRF token for google auth callback");
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .context("unexpected error getting cookie name")?
        .to_string();

    let stored_csrf_token = get_csrf_token_by_session(app_state, &session_id)
        .await?
        .context("Session not found")?;

    expire_session(app_state, &session_id).await?;

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
    .fetch_optional(app_state.database.get_pool())
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
    .execute(app_state.database.get_pool())
    .await?;

    Ok(())
}

pub async fn logout(
    State(app_state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    State(google_token_service): State<GoogleTokenService>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(user_id) = app_state.get_user_id().await {
        tracing::debug!("Logging out user with ID: {}", user_id);
    }
    // TODO: Revocation of access and refresh token not necessary as revoking a refresh 
    // token in Google OAUTH 2.0 also revokes the associated access token and vice versa.
    // See: https://cloud.google.com/apigee/docs/api-platform/security/oauth/validating-and-invalidating-access-tokens
    if let Some(refresh_token) = cookies.get("refresh_token") {
        google_token_service.revoke_token(refresh_token.to_string()).await?;
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

    Ok((headers, Redirect::to("/")))
}

pub async fn store_csrf_token(session_id: &String, csrf_token_secret: &String, app_state: &AppState) -> Result<(), AppError> {
    let expires_at = Utc::now() + Duration::hours(1);
    sqlx::query!(
        r#"
            INSERT INTO sessions (session_id, csrf_token, expires_at)
            VALUES (?, ?, ?)
            "#,
        session_id,
        csrf_token_secret,
        expires_at
    )
    .execute(app_state.database.get_pool())
    .await?;

    Ok(())
}
