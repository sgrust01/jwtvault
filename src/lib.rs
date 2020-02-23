//! # JWT Vault
//! ## Features
//! * Manages & Orchestrates JWT for user login, logout & renew
//! * Easy start
//! * Async ready
//! * No un-safe code
//! * Runs on stable rust
//! * Library approach (Requires no runtime)
//! * Supports plugable components (Store & Hasher)
//! * Invalidates old refresh upon new refresh token renewal
//! * Invalidates old authentication upon new authentication token renewal
//! * Handles Thundering herd problem upon authentication token expiry
//!
//! ## Prerequisite
//!
//! ```toml
//!  [dependencies]
//!  jwtvault = "*"
//!```
//!
//! ```shell script
//! $ curl https://raw.githubusercontent.com/sgrust01/jwtvault/master/generate_certificates.sh > ./generate_certificates.sh
//!```
//!
//!```shell script
//! $ chmod 700 generate_certificates.sh && ./generate_certificates.sh
//!```
//!
//!
//! ## Quickstart
//!
//!
//! ```rust
//! use jwtvault::prelude::*;
//! use std::collections::HashMap;
//! use std::collections::hash_map::DefaultHasher;
//! use futures::executor::block_on;
//!
//! fn main() {
//!     let mut users = HashMap::new();
//!
//!     // User: John Doe
//!    let user_john = "john_doe";
//!    let password_for_john = "john";
//!
//!    // User: Jane Doe
//!    let user_jane = "jane_doe";
//!    let password_for_jane = "jane";
//!
//!    // load users and their password from database/somewhere
//!    users.insert(user_john.to_string(), password_for_john.to_string());
//!    users.insert(user_jane.to_string(), password_for_jane.to_string());
//!
//!    let loader = CertificateManger::default();
//!
//!    // Initialize vault
//!    let mut vault = DefaultVault::new(loader, users);
//!
//!    // John needs to login now
//!    let token = block_on(vault.login(
//!        user_john.as_bytes(),
//!        password_for_john.as_bytes(),
//!        None,
//!        None,
//!    ));
//!    let token = token.ok().unwrap();
//!    // When John presents authentication token, it can be used to restore John's session info
//!    let server_refresh_token = block_on(resolve_session_from_client_authentication_token(
//!        &mut vault,
//!        user_john.as_bytes(),
//!        token.authentication(),
//!    ));
//!    let server_refresh_token = server_refresh_token.ok().unwrap();
//!
//!    // server_refresh_token (variable) contains server method which captures client private info
//!    // which never leaves the server
//!    let private_info_about_john = server_refresh_token.server().unwrap();
//!    let key = digest::<_, DefaultHasher>(user_john.as_bytes());
//!    let data_on_server_side = private_info_about_john.get(&key).unwrap();
//!
//!    // server_refresh_token (variable) contains client method which captures client public info
//!    // which is also send back to client
//!    assert!(server_refresh_token.client().is_none());
//!
//!    // Check out the data on client and server which are public and private respectively
//!    println!("[Private] John Info: {}",
//!             String::from_utf8_lossy(data_on_server_side.as_slice()).to_string());
//!
//!    // lets renew authentication token
//!    let new_token = block_on(vault.renew(
//!        user_john.as_bytes(),
//!        token.refresh(),
//!        None,
//!    ));
//!    let new_token = new_token.ok().unwrap();
//!
//!    // When John presents new authentication token it can be used to restore session info
//!    let result = block_on(resolve_session_from_client_authentication_token(
//!        &mut vault,
//!        user_john.as_bytes(),
//!        new_token.as_str(),
//!    ));
//!    let _ = result.ok().unwrap();
//!
//!}
//! ```
//!
//!
//! # Workflows
//!
//! * To begin use login with ___***user***___ and ___***password***___
//!
//!     * Upon successful login is provides user will be provided with JWT pair (authentication/refresh)
//!
//!     * Authentication token is then provided to access any resources
//!
//!     * Refresh token is used to renew an authentication token upon expiry
//!
//! * Use resolve_session_from_client_authentication_token with ___***user***___ and ___***authentication_token***___ to restore user session
//!
//! * Use renew with ___***user***___ and ___***refresh_token***___ to generate new authentication token
//!
//! * logout with ___***user***___ and ___***authentication_token***___ will remove all tokens associated with the user
//!
//!

pub mod prelude;
pub mod api;
pub mod utils;
pub mod errors;
pub mod constants;

#[macro_use]
extern crate serde;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
