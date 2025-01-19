use std::sync::Arc;

use axum::extract::FromRef;
use reqwest::Client;
use tokio::sync::RwLock;

use crate::{config::database::{Database, DatabaseTrait}, errors::AppError, repository::{session_repository::{SessionRepository, SessionRepositoryTrait}, user_repository::{UserRepository, UserRepositoryTrait}}, service::{google_token_service::{GoogleTokenService, TokenServiceTrait}, user_service::UserService}};

#[derive(Clone)]
pub struct UserContext {
    pub user_id: u64,
    pub email: String,
    pub name: String,
}

#[derive(Clone)]
pub struct AppState {
    pub database: Arc<Database>,
    pub http_client: Client,
    pub user_context: Arc<RwLock<Option<UserContext>>>,
    pub google_token_service: GoogleTokenService,
    pub user_service: UserService,
    pub user_repository: UserRepository,
    pub session_repository: SessionRepository,
}

impl FromRef<AppState> for GoogleTokenService {
    fn from_ref(state: &AppState) -> Self {
        state.google_token_service.clone()
    }
}

impl AppState {
    pub async fn new() -> Result<Self, AppError> {
        let db_conn = Arc::new(Database::new().await?);
        Ok(Self {
            database: db_conn.clone(),
            http_client: Client::new(),
            user_context: Arc::new(RwLock::new(None)),
            google_token_service: GoogleTokenService::new(),
            user_service: UserService::new(&db_conn),
            user_repository: UserRepository::new(&db_conn),
            session_repository: SessionRepository::new(&db_conn),
        })
    }

    pub async fn get_user_id(&self) -> Option<u64> {
        self.user_context.read().await.as_ref().map(|user| user.user_id)
    }

    pub async fn set_user_context(&self, user_context: UserContext) {
        let mut user_context_lock = self.user_context.write().await;
        *user_context_lock = Some(user_context);
    }

    pub async fn clear_user_context(&self) {
        let mut user_context_lock = self.user_context.write().await;
        *user_context_lock = None;
    }
}
