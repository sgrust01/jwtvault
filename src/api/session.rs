//! # Session Documentation
//!
//! ## [Session](struct.Session.html)
//! **Purpose**
//! ___
//! Stores user session information
//!
//! * client
//!
//!     * Represent data to be sent back to client
//!     * Information may be binary/text
//!     * Encryption may be required
//!
//! * server
//!
//!     * Represent data to be retained on server
//!     * Information may be binary/text
//!     * Encryption usually not required
//!
//! **Workflow**
//! ___
//!
//! Maybe created during user [login](../vault/trait.Vault.html#method.login) by [check_user_valid](../vault/trait.UserAuthentication.html#tymethod.check_user_valid)
//!
//! ## [AuthenticationToken](struct.AuthenticationToken.html)
//!
//! **Purpose**
//! ___
//! * Represents the Authentication token
//! * Usually sort lived
//!
//! ## [RefreshToken](struct.RefreshToken.html)
//! **Purpose**
//! ___
//! * Represents the RefreshToken token
//! * Usually long lived
//!
//! ## [Token](struct.Token.html)
//!
//! **Purpose**
//! ___
//! * Wrapper for JWT pair
//!
//! **Workflow**
//! ___
//! * Created during user [login](../vault/trait.Vault.html#method.login)
//!

use std::ops::Deref;

#[derive(Clone, PartialEq, Debug)]
pub struct AuthenticationToken(String);

#[derive(Clone, PartialEq, Debug)]
pub struct RefreshToken(String);

impl Deref for AuthenticationToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for RefreshToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Wrapper for JWT
/// Represent the short lived token
/// To be used for authentication
impl AuthenticationToken {
    pub fn new<T: AsRef<str>>(token: T) -> Self {
        Self(token.as_ref().to_string())
    }
}

/// Wrapper for JWT
/// Represent the long lived token
/// To be used for refresh
impl RefreshToken {
    pub fn new<T: AsRef<str>>(token: T) -> Self {
        Self(token.as_ref().to_string())
    }
}

/// Wrapper for JWT pair
#[derive(Clone, PartialEq, Debug)]
pub struct Token {
    authentication: AuthenticationToken,
    refresh: RefreshToken,
}

impl Token {
    pub fn new(authentication: AuthenticationToken, refresh: RefreshToken) -> Self {
        Self {
            authentication,
            refresh,
        }
    }
    pub fn authentication_token(&self) -> &AuthenticationToken {
        &self.authentication
    }
    pub fn refresh_token(&self) -> &RefreshToken {
        &self.refresh
    }
}

impl From<String> for AuthenticationToken {
    fn from(token: String) -> Self {
        AuthenticationToken(token)
    }
}

impl From<String> for RefreshToken {
    fn from(token: String) -> Self {
        RefreshToken(token)
    }
}

/// Generate Token from authentication and refresh token
impl From<(String, String)> for Token {
    fn from((authentication, refresh): (String, String)) -> Self {
        let authentication_token = AuthenticationToken::from(authentication);
        let refresh_token = RefreshToken::from(refresh);
        Token::new(authentication_token, refresh_token)
    }
}

/// Represents the session
/// client side
/// server side
#[derive(Clone, PartialEq, Debug)]
pub struct Session {
    pub client: Option<Vec<u8>>,
    pub server: Option<Vec<u8>>,
}

impl Session {
    pub fn new(client: Option<Vec<u8>>, server: Option<Vec<u8>>) -> Self {
        Self {
            client,
            server,
        }
    }
}

