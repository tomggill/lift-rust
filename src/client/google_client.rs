use anyhow::Context;
use http::StatusCode;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{errors::AppError, User};

#[derive(Deserialize, Serialize, Debug)]
pub struct GoogleTokenInfo {
    audience: String,  // The audience for which the token was issued
    email: String,     // The email associated with the access token
    expires_in: i64,   // Expiration time in seconds
    issued_to: String, // The client_id the token was issued to
    user_id: String,   // The user's unique ID
}

pub struct GoogleClient<'a> {
    http_client: &'a Client,
}

impl<'a> GoogleClient<'a> {
    pub fn new(http_client: &'a Client) -> Self {
        GoogleClient { http_client }
    }

    pub async fn validate_access_token(
        &self,
        access_token: &str,
    ) -> Result<GoogleTokenInfo, AppError> {
        // https://www.googleapis.com/oauth2/v1/tokeninfo
        let google_token_info = self
            .http_client
            .get("https://www.googleapis.com/oauth2/v1/tokeninfo")
            .bearer_auth(access_token)
            .send()
            .await
            .context("failed in sending request to target Url")?
            .json::<GoogleTokenInfo>()
            .await
            .context("Invalid or expired token")?;

        Ok(google_token_info)
    }

    pub async fn fetch_user_info(&self, access_token: &str) -> Result<User, AppError> {
        let user_data: User = self
            .http_client
            .get("https://openidconnect.googleapis.com/v1/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .context("failed in sending request to target Url")?
            .json::<User>()
            .await
            .context("failed to deserialize response as JSON")?;

        Ok(user_data)
    }
}
