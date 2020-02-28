use std::i64;

// 15 * 60 (15 minutes)
pub const DEFAULT_AUTHENTICATION_MAX_EXPIRY_IN_SECONDS: i64 = 900;
// 15 * 60 (15 minutes)
pub const DEFAULT_AUTHENTICATION_MIN_EXPIRY_IN_SECONDS: i64 = 800;
// Never Expire
pub const DEFAULT_REFRESH_WITH_NO_EXPIRY: i64 = i64::MAX;


pub const DEFAULT_PUBLIC_AUTHENTICATION_TOKEN_PATH: &str = "store/public_authentication_token.pem";
pub const DEFAULT_PRIVATE_AUTHENTICATION_TOKEN_PATH: &str = "store/private_authentication_token.pem";

pub const DEFAULT_PUBLIC_REFRESH_TOKEN_PATH: &str = "store/public_refresh_token.pem";
pub const DEFAULT_PRIVATE_REFRESH_TOKEN_PATH: &str = "store/private_refresh_token.pem";

pub const DEFAULT_PASSWORD_HASHING_SECRET_PATH: &str = "store/password_hashing_secret.pem";

