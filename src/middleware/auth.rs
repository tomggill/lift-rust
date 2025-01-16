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

use crate::{client::google_client::GoogleClient, errors::AppError, AppState};

pub async fn auth(
    State(app_state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    let cookies = CookieJar::from_headers(&req.headers());
    let google_client = GoogleClient::new(&app_state.http_client);
    if let Some(access_token_cookie) = cookies.get("access_token") {
        let access_token = access_token_cookie.value().to_string();
        if let Ok(google_token_info) = google_client.validate_access_token(&access_token).await {
            // Modify app_state to hold user details
            // app_state.user_details = Some(token_info);
            println!("{:?}", google_token_info);
            return Ok(next.run(req).await);
        }
    }

    if let Some(refresh_token_cookie) = cookies.get("refresh_token") {
        let refresh_token = refresh_token_cookie.value().to_string();
        if let Ok(new_access_token) = refresh_access_token(&refresh_token, &app_state.oauth_client).await {
            let new_access_token_cookie = Cookie::build(("access_token", new_access_token.secret().to_string()))
                .path("/")
                .http_only(true)
                .build();
            let mut response = next.run(req).await.into_response();
            response.headers_mut().append(
                SET_COOKIE,
                new_access_token_cookie.to_string().parse().unwrap(),
            );
            if let Ok(google_token_info) = google_client.validate_access_token(&new_access_token.secret().to_string()).await {
                // Modify app_state to hold user details
                // app_state.user_details = Some(token_info);
                println!("{:?}", google_token_info);
                return Ok(response);
            } 
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
