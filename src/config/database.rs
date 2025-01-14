use async_trait::async_trait;
use dotenv::dotenv;
use sqlx::{MySql, MySqlPool, Pool};

use crate::errors::AppError;

use super::parameter;

pub struct Database {
    pool: Pool<MySql>,
}

#[async_trait]
pub trait DatabaseTrait {
    async fn init() -> Result<Self, AppError>
    where
        Self: Sized;
    fn get_pool(&self) -> &Pool<MySql>;
}

#[async_trait]
impl DatabaseTrait for Database {
    async fn init() -> Result<Self, AppError> {
        let database_url = parameter::get("DATABASE_URL");
        let pool = MySqlPool::connect(&database_url).await?;
        Ok(Self { pool })
    }

    fn get_pool(&self) -> &Pool<MySql> {
        &self.pool
    }
}
