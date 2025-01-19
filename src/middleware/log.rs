use axum::{body::Body, extract::Request, middleware::Next, response::Response};

use crate::errors::AppError;

pub async fn log_request(req: Request, next: Next) -> Result<Response<Body>, AppError> {
    let method = req.method().clone();
    let uri = req.uri().clone();

    tracing::debug!("Request {{path=\"{}\", method=\"{}\"}} Received", uri.path(), method);

    let response = next.run(req).await;
    let status = response.status();

    tracing::info!(
        status = %status,
        "Response sent"
    );

    Ok(response)
}
