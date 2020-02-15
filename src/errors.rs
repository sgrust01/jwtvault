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
}