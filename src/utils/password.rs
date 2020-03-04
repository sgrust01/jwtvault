use std::ops::Deref;

use crate::prelude::*;

pub struct ArgonPasswordHasher {
    secret_key: String
}

impl Deref for ArgonPasswordHasher {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.secret_key.as_str()
    }
}

impl ArgonPasswordHasher {
    pub fn new<T: AsRef<str>>(secret_key: T) -> Self {
        let secret_key = secret_key.as_ref().to_string();
        Self { secret_key }
    }
}

impl Default for ArgonPasswordHasher {
    fn default() -> Self {
        let manager = CertificateManger::default();
        let secret_key = manager.password_hashing_secret();
        ArgonPasswordHasher::from(secret_key)
    }
}

impl<'a> PasswordHasher<ArgonHasher<'a>> for ArgonPasswordHasher {
    fn hash_user_password<T: AsRef<str>>(&self, user: T, password: T) -> Result<String, Error> {
        let secret_key = self.secret_key.as_str();
        let result = hash_password_with_argon(password.as_ref(), secret_key.as_ref()).map_err(|e| {
            let msg = format!("Login failed for user: {}", user.as_ref());
            let reason = e.to_string();
            LoginFailed::PasswordHashingFailed(msg, reason).into()
        });
        result
    }
    fn verify_user_password<T: AsRef<str>>(&self, user: T, password: T, hash: T) -> Result<bool, Error> {
        let secret_key = self.secret_key.as_str();
        let result = verify_user_password_with_argon(
            password.as_ref(), secret_key.as_ref(), hash.as_ref(),
        ).map_err(|e| {
            let reason = e.to_string();
            let msg = format!("Login verification for user: {} Reason: {}", user.as_ref(), reason);
            let reason = e.to_string();
            LoginFailed::PasswordVerificationFailed(msg, reason).into()
        });
        result
    }
}

impl From<PrivateKey> for ArgonPasswordHasher {
    fn from(secret_key: PrivateKey) -> Self {
        ArgonPasswordHasher::new(secret_key.as_str())
    }
}