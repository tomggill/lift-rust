use axum::{body::Body, extract::Request, middleware::Next, response::Response};

use crate::errors::AppError;

pub async fn log_request(req: Request, next: Next) -> Result<Response<Body>, AppError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();
    let headers_to_log: Vec<_> = req
        .headers()
        .iter()
        .filter(|(key, _)| *key == "host" || *key == "user-agent")
        .map(|(key, value)| (key.clone(), value.to_str().unwrap_or("[unreadable]").to_string()))
        .collect();

    tracing::info!(
        ?method,
        ?uri,
        ?version,
        headers = ?headers_to_log,
        "Received request"
    );

    let response = next.run(req).await;

    let status = response.status();


    tracing::info!(?status, "Response sent");

    Ok(response)
}