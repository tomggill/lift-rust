use anyhow::Context;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Redirect},
    http::header::SET_COOKIE,
};

use axum_extra::extract::cookie::{Cookie, CookieJar};

use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AccessToken, RefreshToken, TokenResponse,
};

use crate::{client::google_client::GoogleClient, errors::AppError, handler::auth_handler::get_user, AppState, UserContext};

// TODO - Add appropriate error responses
pub async fn auth(
    State(app_state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    let cookies = CookieJar::from_headers(&req.headers());
    if let Some(access_token_cookie) = cookies.get("access_token") {
        let access_token = access_token_cookie.value().to_string();
        if let Some(_) = validate_and_set_user_context(&app_state, &access_token).await? {
            return Ok(next.run(req).await);
        }
    }

    if let Some(refresh_token_cookie) = cookies.get("refresh_token") {
        let refresh_token = refresh_token_cookie.value().to_string();
        return handle_refresh_token(&app_state, &refresh_token, req, next).await;
    }
    Ok(Redirect::to("/").into_response())
}

async fn validate_and_set_user_context(
    app_state: &AppState,
    access_token: &str,
) -> Result<Option<UserContext>, AppError> {
    let google_client = GoogleClient::new(&app_state.http_client);
    if let Ok(google_token_info) = google_client.validate_access_token(access_token).await {
        let existing_user = get_user(&google_token_info.user_id, app_state).await?;
        if let Some(user_context) = existing_user {
            let mut user_context_lock = app_state.user_context.write().await;
            *user_context_lock = Some(user_context.clone());
            return Ok(Some(user_context));
        }
    }
    Ok(None)
}

async fn handle_refresh_token(
    app_state: &AppState,
    refresh_token: &str,
    req: Request,
    next: Next,
) -> Result<http::Response<axum::body::Body>, AppError> {
    if let Ok(new_access_token) = refresh_access_token(refresh_token, &app_state.oauth_client).await {
        let new_access_token_cookie = Cookie::build(("access_token", new_access_token.secret().to_string()))
            .path("/")
            .http_only(true)
            .build();
        let mut response = next.run(req).await.into_response();
        response.headers_mut().append(
            SET_COOKIE,
            new_access_token_cookie.to_string().parse().unwrap(),
        );
        if let Some(_) = validate_and_set_user_context(app_state, new_access_token.secret()).await? {
            return Ok(response);
        }
    }
    Ok(Redirect::to("/").into_response())
}

async fn refresh_access_token(
    refresh_token: &str,
    client: &BasicClient,
) -> Result<AccessToken, AppError> {
    let token_response = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
        .request_async(async_http_client)
        .await
        .context("failed to refresh access token")?;

    Ok(token_response.access_token().to_owned())
}
