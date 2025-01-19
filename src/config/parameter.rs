use anyhow::Context;
use dotenv;

use crate::errors::AppError;

pub fn init() {
    dotenv::dotenv().expect("Failed to load .env file");
}

pub fn get(parameter: &str) -> Result<String, AppError> {
    std::env::var(parameter)
        .with_context(|| format!("{} is not defined in the environment.", parameter))
        .map_err(AppError::from)
}