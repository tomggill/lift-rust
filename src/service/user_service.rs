use std::sync::Arc;

use crate::{config::database::Database, errors::AppError, repository::user_repository::{UserRepository, UserRepositoryTrait}, state::app_state::UserContext, User};


#[derive(Clone)]
pub struct UserService {
    user_repository: UserRepository,
}

impl UserService {
    pub fn new(db_conn: &Arc<Database>) -> Self {
        Self {
            user_repository: UserRepository::new(db_conn),
        }
    }

    pub async fn get_or_insert_user(&self, user_data: &User) -> Result<UserContext, AppError> {
        let existing_user = self.user_repository.find_user_by_google_id(&user_data.sub).await?;
        if let Some(user_context) = existing_user {
            return Ok(user_context);
        }
    
        let user_id = self.user_repository.add_user(
                &user_data.sub,
                &user_data.email, 
                &user_data.given_name, 
                &user_data.family_name).await?;
    
        Ok(UserContext {
            user_id,
            email: user_data.email.clone(),
            name: user_data.given_name.clone(),
        })
    }
}
