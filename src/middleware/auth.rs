use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Redirect},
    http::header::SET_COOKIE,
};

use axum_extra::extract::cookie::{Cookie, CookieJar};

use crate::{ errors::AppError, repository::user_repository::UserRepositoryTrait, service::google_token_service::{GoogleTokenService, TokenServiceTrait}, state::app_state::UserContext, AppState};

// TODO - Add appropriate error responses
pub async fn auth(
    State(app_state): State<AppState>,
    State(google_token_service): State<GoogleTokenService>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Authenticating request");
    let cookies = CookieJar::from_headers(req.headers());
    if let Some(access_token_cookie) = cookies.get("access_token") {
        let access_token = access_token_cookie.value().to_string();
        if (validate_and_set_user_context(&app_state, &google_token_service, &access_token).await?).is_some() {
            return Ok(next.run(req).await);
        }
    }

    if let Some(refresh_token_cookie) = cookies.get("refresh_token") {
        let refresh_token = refresh_token_cookie.value().to_string();
        return handle_refresh_token(&app_state, &google_token_service, &refresh_token, req, next).await;
    }
    Ok(Redirect::to("/").into_response())
}

async fn validate_and_set_user_context(
    app_state: &AppState,
    google_token_service: &GoogleTokenService,
    access_token: &str,
) -> Result<Option<UserContext>, AppError> {
    if let Ok(google_token_info) = google_token_service.get_token_info(access_token).await {
        let existing_user = app_state.user_repository.find_user_by_google_id(&google_token_info.user_id).await?;
        if let Some(user_context) = existing_user {
            app_state.set_user_context(user_context.clone()).await;
            return Ok(Some(user_context));
        }
    }
    Ok(None)
}

async fn handle_refresh_token(
    app_state: &AppState,
    google_token_service: &GoogleTokenService,
    refresh_token: &str,
    req: Request,
    next: Next,
) -> Result<http::Response<axum::body::Body>, AppError> {
    if let Ok(new_access_token) = 
    google_token_service.refresh_access_token(refresh_token.to_string()).await {
        let new_access_token_cookie = Cookie::build(("access_token", new_access_token.secret().to_string()))
            .path("/")
            .http_only(true)
            .build();
        let mut response = next.run(req).await.into_response();
        response.headers_mut().append(
            SET_COOKIE,
            new_access_token_cookie.to_string().parse().unwrap(),
        );
        if (validate_and_set_user_context(app_state, google_token_service, new_access_token.secret()).await?).is_some() {
            return Ok(response);
        }
    }
    Ok(Redirect::to("/").into_response())
}
