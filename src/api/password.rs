use crate::prelude::*;

pub trait PasswordHasher<H: Default> {
    /// Implementation Required
    fn hash_user_password<T: AsRef<str>>(&self, user: T, password: T) -> Result<String, Error>;
    fn verify_user_password<T: AsRef<str>>(&self, user: T, password: T, hash: T) -> Result<bool, Error>;
}