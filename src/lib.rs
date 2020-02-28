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
//!
//!
//!
//!
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
