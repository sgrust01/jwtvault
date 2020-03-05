//! # JWT Vault
//! ## Features
//! * Manages & Orchestrates JWT for user login, logout & renew
//!     * Option 1: DynamicVault (uses dynamic dispatch but requires considerable less boiler-plate code)
//!     * Option 2: DefaultVault (uses static dispatch but requires considerable more boiler-plate code)
//! * Async ready
//! * Easy start
//! * No un-safe code
//! * Runs on stable rust
//! * Uses [Argon](https://en.wikipedia.org/wiki/Argon2) (see [video](https://www.youtube.com/watch?v=Sc3aHMCc4h0&t=339s))
//! * Library approach (Requires no runtime)
//! * Supports plugable components
//! * Invalidates old refresh upon new refresh token renewal
//! * Invalidates old authentication upon new authentication token renewal
//! * Cross feeding not allowed
//! * Handles Thundering herd problem upon authentication token expiry
//! * Works with any web-server, any password hashing, and any backend ([here](https://github.com/sgrust01/jwtvault_examples))
//! * Fully functional
//! [webserver](https://github.com/sgrust01/jwtvault_examples#example-5-webserver)
//! with [actix](https://github.com/actix/actix)
//! and [postgres](https://github.com/sfackler/rust-postgres/tree/master/tokio-postgres)
//!
//!
//! ## Quickstart
//!
//! ### Prerequisite:
//!
//!
//!  ```toml
//!   [dependencies]
//!   jwtvault = "*"
//! ```
//!
//!  ```shell script
//! $ curl https://raw.githubusercontent.com/sgrust01/jwtvault/master/generate_certificates.sh > ./generate_certificates.sh
//! ```
//!
//! ```shell script
//! $ chmod 700 generate_certificates.sh && ./generate_certificates.sh
//! ```
//!
//! #### Option 1: DynamicVault
//!
//! ```rust
//! use std::collections::HashMap;
//! use std::collections::hash_map::DefaultHasher;
//!
//! use jwtvault::prelude::*;
//!
//! fn main() {
//!     let hasher = ArgonPasswordHasher::default();
//!     // User: John Doe
//!     let user_john = "john_doe";
//!     let password_for_john = "john";
//!     // Save value 'hashed_password_for_john' to persistent storage
//!     // This is more relevant during user signup/password reset
//!     let hashed_password_for_john = hasher.hash_user_password(user_john, password_for_john).unwrap();
//!
//!     // User: Jane Doe
//!     let user_jane = "jane_doe";
//!     let password_for_jane = "jane";
//!     // Save 'hashed_password_for_jane' to persistent storage
//!     // This is more relevant during user signup/password reset
//!     let hashed_password_for_jane = hasher.hash_user_password(user_jane, password_for_jane).unwrap();
//!
//!     let mut users = HashMap::new();
//!
//!     // load users and their password from database/somewhere
//!     users.insert(user_john.to_string(), hashed_password_for_john.to_string());
//!     users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());
//!
//!     // Setup app users
//!     let login = LoginInfo::new(users);
//!
//!      // Initialize vault
//!     let mut vault = DynamicVault::default(Box::new(login));
//!
//!     // John needs to login now
//!     let token = block_on(vault.login(
//!         user_john,
//!         password_for_john,
//!         None,
//!         None,
//!     ));
//!     let token = token.ok().unwrap();
//!     // When John presents authentication token, it can be used to restore John's session info
//!     let server_refresh_token = block_on(resolve_session_from_client_authentication_token(
//!         &mut vault,
//!         user_john,
//!         token.authentication(),
//!     ));
//!     let server_refresh_token = server_refresh_token.ok().unwrap();
//!
//!     // server_refresh_token (variable) contains server method which captures client private info
//!     // which never leaves the server
//!     let private_info_about_john = server_refresh_token.server().unwrap();
//!     let key = digest::<_, DefaultHasher>(user_john);
//!     let data_on_server_side = private_info_about_john.get(&key).unwrap();
//!
//!     // server_refresh_token (variable) contains client method which captures client public info
//!     // which is also send back to client
//!     assert!(server_refresh_token.client().is_none());
//!
//!     // Check out the data on client and server which are public and private respectively
//!     println!("[Private] John Info: {}",
//!              String::from_utf8_lossy(data_on_server_side.as_slice()).to_string());
//!
//!     // lets renew authentication token
//!     let new_token = block_on(vault.renew(
//!         user_john,
//!         token.refresh(),
//!         None,
//!     ));
//!     let new_token = new_token.ok().unwrap();
//!
//!     // When John presents new authentication token it can be used to restore session info
//!     let result = block_on(resolve_session_from_client_authentication_token(
//!         &mut vault,
//!         user_john,
//!         new_token.as_str(),
//!     ));
//!     let _ = result.ok().unwrap();
//! }
//! ```
//!
//! #### Option 2: DefaultVault
//!
//! ```rust
//! use jwtvault::prelude::*;
//! use std::collections::HashMap;
//! use std::collections::hash_map::DefaultHasher;
//!
//!
//! fn main() {
//!
//!     let mut users = HashMap::new();
//!
//!     let loader = CertificateManger::default();
//!
//!     // User: John Doe
//!     let user_john = "john_doe";
//!     let password_for_john = "john";
//!
//!     // This should ideally be pre-computed during user sign-up/password reset/change password
//!     let hashed_password_for_john = hash_password_with_argon(
//!         password_for_john,
//!         loader.password_hashing_secret().as_str(),
//!     ).unwrap();
//!
//!     // User: Jane Doe
//!     let user_jane = "jane_doe";
//!     let password_for_jane = "jane";
//!
//!     // This should ideally be pre-computed during user sign-up/password reset/change password
//!     let hashed_password_for_jane = hash_password_with_argon(
//!         password_for_jane,
//!         loader.password_hashing_secret().as_str(),
//!     ).unwrap();
//!
//!     // load users and their (argon hashed) password from database/somewhere
//!     users.insert(user_john.to_string(), hashed_password_for_john);
//!     users.insert(user_jane.to_string(), hashed_password_for_jane);
//!
//!     // Initialize vault
//!     let mut vault = DefaultVault::new(loader, users, false);
//!
//!     // John needs to login now
//!     let token = block_on(vault.login(
//!         user_john,
//!         password_for_john,
//!         None,
//!         None,
//!     ));
//!     let token = token.ok().unwrap();
//!     // When John presents authentication token, it can be used to restore John's session info
//!     let server_refresh_token = block_on(resolve_session_from_client_authentication_token(
//!         &mut vault,
//!         user_john,
//!         token.authentication(),
//!     ));
//!     let server_refresh_token = server_refresh_token.ok().unwrap();
//!
//!     // server_refresh_token (variable) contains server method which captures client private info
//!     // which never leaves the server
//!     let private_info_about_john = server_refresh_token.server().unwrap();
//!     let key = digest::<_, DefaultHasher>(user_john);
//!     let data_on_server_side = private_info_about_john.get(&key).unwrap();
//!
//!     // server_refresh_token (variable) contains client method which captures client public info
//!     // which is also send back to client
//!     assert!(server_refresh_token.client().is_none());
//!
//!     // Check out the data on client and server which are public and private respectively
//!     println!("[Private] John Info: {}",
//!              String::from_utf8_lossy(data_on_server_side.as_slice()).to_string());
//!
//!     // lets renew authentication token
//!     let new_token = block_on(vault.renew(
//!         user_john,
//!         token.refresh(),
//!         None,
//!     ));
//!     let new_token = new_token.ok().unwrap();
//!
//!     // When John presents new authentication token it can be used to restore session info
//!     let result = block_on(resolve_session_from_client_authentication_token(
//!         &mut vault,
//!         user_john,
//!         new_token.as_str(),
//!     ));
//!     let _ = result.ok().unwrap();
//! }
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
