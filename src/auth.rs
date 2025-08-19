use anyhow::Result;
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
pub struct AuthState {
    secret: String,
    users: HashMap<String, String>, // username -> password_hash
}

impl AuthState {
    pub fn new() -> Self {
        let mut auth = Self {
            secret: Uuid::new_v4().to_string(),
            users: HashMap::new(),
        };

        // Carregar usuários ou criar usuário padrão
        if let Err(_) = auth.load_users() {
            // Criar usuário admin padrão se não existir arquivo de usuários
            let password_hash = hash("admin123", DEFAULT_COST).unwrap();
            auth.users.insert("admin".to_string(), password_hash);
            auth.save_users().ok();
        }

        auth
    }

    pub fn verify_credentials(&self, username: &str, password: &str) -> Result<bool> {
        if let Some(password_hash) = self.users.get(username) {
            Ok(verify(password, password_hash)?)
        } else {
            Ok(false)
        }
    }

    pub fn create_token(&self, username: &str) -> Result<String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let claims = Claims {
            sub: username.to_string(),
            exp: (now + 3600) as usize, // 1 hora
            iat: now as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )?;

        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default(),
        )?;

        Ok(token_data.claims)
    }

    fn load_users(&mut self) -> Result<()> {
        let content = fs::read_to_string("users.json")?;
        self.users = serde_json::from_str(&content)?;
        Ok(())
    }

    fn save_users(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.users)?;
        fs::write("users.json", content)?;
        Ok(())
    }

    pub fn add_user(&mut self, username: String, password: &str) -> Result<()> {
        let password_hash = hash(password, DEFAULT_COST)?;
        self.users.insert(username, password_hash);
        self.save_users()?;
        Ok(())
    }

    pub fn remove_user(&mut self, username: &str) -> Result<bool> {
        let removed = self.users.remove(username).is_some();
        if removed {
            self.save_users()?;
        }
        Ok(removed)
    }
}

pub struct SessionManager {
    sessions: HashMap<String, Session>,
}

#[derive(Debug)]
struct Session {
    username: String,
    created_at: SystemTime,
    last_accessed: SystemTime,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn create_session(&mut self, username: String, token: String) {
        let now = SystemTime::now();
        let session = Session {
            username,
            created_at: now,
            last_accessed: now,
        };
        self.sessions.insert(token, session);
        self.cleanup_expired_sessions();
    }

    pub fn is_valid_session(&mut self, token: &str) -> bool {
        if let Some(session) = self.sessions.get_mut(token) {
            let now = SystemTime::now();
            
            // Verificar se a sessão não expirou (1 hora = 3600 segundos)
            if let Ok(duration) = now.duration_since(session.created_at) {
                if duration.as_secs() > 3600 {
                    self.sessions.remove(token);
                    return false;
                }
            }

            // Atualizar último acesso
            session.last_accessed = now;
            true
        } else {
            false
        }
    }

    pub fn invalidate_session(&mut self, token: &str) {
        self.sessions.remove(token);
    }

    fn cleanup_expired_sessions(&mut self) {
        let now = SystemTime::now();
        self.sessions.retain(|_, session| {
            if let Ok(duration) = now.duration_since(session.created_at) {
                duration.as_secs() <= 3600
            } else {
                false
            }
        });
    }

    pub fn get_session_username(&self, token: &str) -> Option<&str> {
        self.sessions.get(token).map(|s| s.username.as_str())
    }
}
