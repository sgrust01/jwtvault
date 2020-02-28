use failure::Fail;

#[derive(Debug, Fail)]
pub enum CertificateError {
    #[fail(display = "{} - Reason: {}", 0, 1)]
    BadFile(String, String),
    #[fail(display = "{} - Reason: {}", 0, 1)]
    FileReadError(String, String),
}

#[derive(Debug, Fail)]
pub enum TokenErrors {
    #[fail(display = "{} - Reason: {}", 0, 1)]
    TokenEncodingFailed(String, String),

    #[fail(display = "{} - Reason: {}", 0, 1)]
    TokenDecodingFailed(String, String),

    #[fail(display = "{} - Reason: {}", 0, 1)]
    MissingServerRefreshToken(String, String),

    #[fail(display = "{} - Reason: {}", 0, 1)]
    InvalidServerRefreshToken(String, String),

    #[fail(display = "{} - Reason: {}", 0, 1)]
    InvalidClientAuthenticationToken(String, String),
}

#[derive(Debug, Fail)]
pub enum LoginFailed {
    #[fail(display = "{} - Reason: {}", 0, 1)]
    MissingPassword(String, String),

    #[fail(display = "{} - Reason: {}", 0, 1)]
    InvalidPassword(String, String),

    #[fail(display = "{} - Reason: {}", 0, 1)]
    InvalidTokenOwner(String, String),

    #[fail(display = "{} - Reason: {}", 0, 1)]
    PasswordHashingFailed(String, String),

    #[fail(display = "{} - Reason: {}", 0, 1)]
    PasswordVerificationFailed(String, String),

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_certificate_error() {
        let err = CertificateError::BadFile("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2");

        let err = CertificateError::FileReadError("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2")
    }

    #[test]
    fn validate_token_error() {
        let err = TokenErrors::TokenEncodingFailed("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2");

        let err = TokenErrors::TokenDecodingFailed("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2");

        let err = TokenErrors::MissingServerRefreshToken("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2");

        let err = TokenErrors::InvalidServerRefreshToken("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2");

        let err = TokenErrors::InvalidClientAuthenticationToken("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2");
    }

    #[test]
    fn validate_login_error() {
        let err = LoginFailed::MissingPassword("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2");

        let err = LoginFailed::InvalidPassword("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2");

        let err = LoginFailed::InvalidTokenOwner("1".to_string(), "2".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg.as_str(), "1 - Reason: 2");
    }
}