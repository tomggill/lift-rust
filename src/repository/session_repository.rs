use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};

use crate::{config::database::{Database, DatabaseTrait}, errors::AppError};


#[derive(Clone)]
pub struct SessionRepository {
    pub(crate) db_conn: Arc<Database>,
}

#[async_trait]
pub trait SessionRepositoryTrait {
    fn new(db_conn: &Arc<Database>) -> Self;
    async fn add_csrf_token(&self, session_id: &str, csrf_token: &str) -> Result<(), AppError>;
    async fn expire_session(&self, session_id: &str) -> Result<(), AppError>;
    async fn get_csrf_token_by_session_id(&self, session_id: &str) -> Result<String, AppError>;
}

#[async_trait]
impl SessionRepositoryTrait for SessionRepository {
    fn new(db_conn: &Arc<Database>) -> Self {
        Self {
            db_conn: Arc::clone(db_conn),
        }
    }

    async fn add_csrf_token(&self, session_id: &str, csrf_token: &str) -> Result<(), AppError> {
        let expires_at = Utc::now() + Duration::hours(1);
        sqlx::query!(
            r#"
                INSERT INTO sessions (session_id, csrf_token, expires_at)
                VALUES (?, ?, ?)
                "#,
            session_id,
            csrf_token,
            expires_at
        )
        .execute(self.db_conn.get_pool())
        .await?;
    
        Ok(())
    }
    
    async fn expire_session(&self, session_id: &str) -> Result<(), AppError> {
        sqlx::query!(
            r#"
                UPDATE sessions
                SET expires_at = NOW()
                WHERE session_id = ?
            "#,
            session_id
        )
        .execute(self.db_conn.get_pool())
        .await?;
    
        Ok(())
    }

    async fn get_csrf_token_by_session_id (&self, session_id: &str) -> Result<String, AppError> {
        let session = sqlx::query!(
            r#"
                SELECT csrf_token FROM sessions WHERE session_id = ? AND expires_at > NOW()
            "#,
            session_id
        )
        .fetch_one(self.db_conn.get_pool())
        .await?;
    
        Ok(session.csrf_token)
    }
}
