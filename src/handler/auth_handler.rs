use anyhow::{anyhow, Context};
use async_session::base64;
use axum::{
    extract::{Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{IntoResponse, Redirect},
};
use axum_extra::{extract::cookie::Cookie, headers, TypedHeader};
use rand::RngCore;
use serde::Deserialize;

use crate::{errors::AppError, repository::session_repository::SessionRepositoryTrait, service::google_token_service::{GoogleTokenService, TokenServiceTrait}, AppState};

static SESSION_COOKIE_NAME: &str = "SESSION";

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuthRequest {
    code: String,
    state: String,
}

pub async fn google_auth(
    State(app_state): State<AppState>,
    State(google_token_service): State<GoogleTokenService>,
) -> Result<impl IntoResponse, AppError> {
    let (auth_url, csrf_token) = google_token_service.generate_authorisation_url().await?;

    let session_id = generate_session_id();
    app_state.session_repository.add_csrf_token(&session_id, csrf_token.secret()).await?;

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
    validate_csrf_token(&app_state, &query, &cookies).await?;

    let (access_token, refresh_token) = google_token_service.exchange_authorisation_code(query.code.clone()).await?;

    let access_token = access_token.secret().to_string();

    let refresh_token = refresh_token.secret().to_string();

    let user_data = google_token_service.get_user_info(&access_token).await?;

    let user_context = app_state.user_service.get_or_insert_user(&user_data).await?;
    app_state.set_user_context(user_context).await;

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

async fn validate_csrf_token(
    app_state: &AppState,
    auth_request: &AuthRequest,
    cookies: &headers::Cookie,
) -> Result<(), AppError> {
    tracing::debug!("Validating CSRF token for google auth callback");
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .context("unexpected error getting cookie name")?
        .to_string();

    let stored_csrf_token = app_state.session_repository.get_csrf_token_by_session_id(&session_id).await?;
    app_state.session_repository.expire_session(&session_id).await?;

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

    app_state.clear_user_context().await;

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
