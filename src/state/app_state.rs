use std::sync::Arc;

use axum::extract::FromRef;
use reqwest::Client;
use sqlx::MySqlPool;
use tokio::sync::RwLock;

use crate::service::google_token_service::{GoogleTokenService, TokenServiceTrait};

#[derive(Clone)]
pub struct UserContext {
    pub user_id: u64,
    pub email: String,
    pub name: String,
}

#[derive(Clone)]
pub struct AppState {
    pub http_client: Client,
    pub db: MySqlPool,
    pub user_context: Arc<RwLock<Option<UserContext>>>,
    pub google_token_service: GoogleTokenService,
}

impl FromRef<AppState> for GoogleTokenService {
    fn from_ref(state: &AppState) -> Self {
        state.google_token_service.clone()
    }
}

impl AppState {
    pub fn new(db: MySqlPool) -> Self {
        Self {
            http_client: Client::new(),
            db,
            user_context: Arc::new(RwLock::new(None)),
            google_token_service: GoogleTokenService::new(),
        }
    }

    pub async fn get_user_id(&self) -> Option<u64> {
        self.user_context.read().await.as_ref().map(|user| user.user_id)
    }
}
