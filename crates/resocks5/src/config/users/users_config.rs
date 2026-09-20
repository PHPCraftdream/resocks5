use serde::{Deserialize, Serialize};

use crate::config::User;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct UsersConfig {
    #[serde(default)]
    pub users: Vec<User>,
}
