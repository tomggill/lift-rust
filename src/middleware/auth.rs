use anyhow::Context;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};

use axum_extra::extract::CookieJar;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AccessToken, RefreshToken, TokenResponse,
};

use crate::{client::google_client::GoogleClient, errors::AppError, AppState};

pub async fn auth_2(
    State(app_state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    let cookies = CookieJar::from_headers(&req.headers());
    for cookie in cookies.iter() {
        println!(
            "Cookie name: {}, Cookie value: {}",
            cookie.name(),
            cookie.value()
        );
    }
    let google_client = GoogleClient::new(&app_state.http_client);
    if let Some(access_token_cookie) = cookies.get("access_token") {
        let access_token = access_token_cookie.value().to_string();
        let google_token_info = google_client.validate_access_token(&access_token).await?;
    }

    // Continue validation...

    Ok(next.run(req).await)
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
