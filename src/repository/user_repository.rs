use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;

use crate::{config::database::{Database, DatabaseTrait}, errors::AppError, state::app_state::UserContext};


#[derive(Clone)]
pub struct UserRepository {
    pub(crate) db_conn: Arc<Database>,
}

#[async_trait]
pub trait UserRepositoryTrait {
    fn new(db_conn: &Arc<Database>) -> Self;
    async fn add_user(&self, google_id: &str, email: &str, first_name: &str, last_name: &str) -> Result<u64, AppError>;
    async fn find_user_by_google_id(&self, google_id: &str) -> Result<Option<UserContext>, AppError>;
}

#[async_trait]
impl UserRepositoryTrait for UserRepository {
    fn new(db_conn: &Arc<Database>) -> Self {
        Self {
            db_conn: Arc::clone(db_conn),
        }
    }

    async fn add_user(&self, google_id: &str, email: &str, first_name: &str, last_name: &str) -> Result<u64, AppError> {
        tracing::debug!("Creating a new user");
        let user = sqlx::query!(
            r#"
                INSERT INTO users (google_id, email, first_name, last_name)
                VALUES (?, ?, ?, ?)
            "#,
            google_id,
            email,
            first_name,
            last_name,
        )
        .execute(self.db_conn.get_pool())
        .await
        .context("Failed to insert user into database")?;

        Ok(user.last_insert_id())
    }

    async fn find_user_by_google_id(&self, google_id: &str) -> Result<Option<UserContext>, AppError> {
        let user_context = sqlx::query_as!(
            UserContext,
            r#"
            SELECT 
                CAST(id as unsigned) AS user_id, 
                email, 
                first_name AS name
            FROM users
            WHERE google_id = ?
            "#,
            google_id
        )
        .fetch_optional(self.db_conn.get_pool())
        .await?;
    
        Ok(user_context)
    }
}
