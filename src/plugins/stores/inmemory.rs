//! # Component Documentation
//! ## [DefaultVault](struct.DefaultVault.html)
//!
//! **Purpose**
//! ___
//!
//! * Used as a component within [Components](../../../api/components/index.html)
//! * Complete implementation for basic use-cases
//!
//! ## [MemoryVault](struct.MemoryVault.html)
//!
//! **_Client implementation required_** <br/><br/>
//!
//! **Purpose**
//! ___
//!
//! * Used as a component within [Components](../../../api/components/index.html)
//! * Client needs to provide an implementation for [UserAuthentication](../../../api/vault/index.html)
//!

use crate::prelude::*;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::hash::Hasher;


use failure::Error;
use crate::plugins::hashers::default::MemoryHasher;

/// # In-Memory Vault
/// Structure
/// * Use DefaultHasher <br/>
/// * Use certificates from Disk <br/>
/// * Use Static users <br/>
///
/// Pending Implementation <br/>
/// * UserAuthentication
///
/// See [DefaultVault](struct.DefaultVault.html) for full implementation
/// Also see example on how to use it
pub struct MemoryVault<H: Hasher + Default> {
    user_passwords: HashMap<String, String>,
    store: HashMap<u64, String>,
    keys: KeyPairs,
    hasher: H,
}

impl<H: Hasher + Default> MemoryVault<H> {
    pub fn new(user_passwords: HashMap<String, String>, hasher: H) -> Self {
        let store = HashMap::new();
        let keys = KeyPairs::default();
        MemoryVault {
            user_passwords,
            store,
            keys,
            hasher,
        }
    }

    pub fn user_passwords(&self) -> &HashMap<String, String> {
        &self.user_passwords
    }

    pub fn hasher(&self) -> &H {
        &self.hasher
    }
}


/// Default Implementation
impl<H: Hasher + Default> KeyStore for MemoryVault<H> {
    fn key_pairs(&self) -> &KeyPairs {
        &self.keys
    }
}

/// Default Implementation
impl<H: Hasher + Default> UserIdentity for MemoryVault<H> {
    fn check_same_user<T: AsRef<[u8]>>(&self, user: T, user_from_token: T) -> Result<(), Error> {
        if user.as_ref() == user_from_token.as_ref() {
            return Ok(());
        };
        let msg = "User mismatch".to_string();
        let reason = format!("Token: {:?} User: {:?}", user_from_token.as_ref(), user.as_ref());
        return Err(InvalidTokenOwner(msg, reason).into());
    }
}

impl<H: Hasher + Default> PersistenceHasher<H> for MemoryVault<H> {
    fn engine(&self) -> H {
        <H as Default>::default()
    }
}

// Un-Implemented
//impl<H: Hasher + Default> UserAuthentication for MemoryVault<H> {
//}

/// Default Implementation
impl<H: Hasher + Default> Persistence for MemoryVault<H> {
    fn store(&mut self, key: u64, value: String) {
        self.store.insert(key, value);
    }
    fn load(&self, key: u64) -> Option<&String> {
        self.store.get(&key)
    }
    fn remove(&mut self, key: u64) -> Option<String> {
        self.store.remove(&key)
    }
}


/// # Default Memory Vault
/// Structure
/// * Use DefaultHasher <br/>
/// * Use certificates from Disk <br/>
/// * Use Static users <br/>
pub struct DefaultVault(MemoryVault<MemoryHasher>);

impl Deref for DefaultVault {
    type Target = MemoryVault<MemoryHasher>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DefaultVault {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Clone for DefaultVault {
    fn clone(&self) -> Self {
        Self::new(self.user_passwords().clone())
    }
}


impl DefaultVault {
    pub fn new(user_passwords: HashMap<String, String>) -> Self {
        let memory_vault = MemoryVault::new(user_passwords, MemoryHasher::default());
        DefaultVault(memory_vault)
    }
}


impl Persistence for DefaultVault {
    fn store(&mut self, key: u64, value: String) {
        self.0.store(key, value)
    }

    fn load(&self, key: u64) -> Option<&String> {
        self.0.load(key)
    }

    fn remove(&mut self, key: u64) -> Option<String> {
        self.0.remove(key)
    }
}

impl PersistenceHasher<MemoryHasher> for DefaultVault {
    fn engine(&self) -> MemoryHasher {
        self.0.engine()
    }
}

/// Default Implementation
impl UserAuthentication for DefaultVault {
    /// Return normally if login succeeds else return an Error
    fn check_user_valid<T: AsRef<[u8]>>(&mut self, user: T, pass: T) -> Result<Option<Session>, Error> {
        let user_id = String::from_utf8(user.as_ref().to_vec())?;
        let password = self.user_passwords.get(&user_id);
        if password.is_none() {
            return Err(MissingPassword(user_id, "No password".to_string()).into());
        };
        let password = password.unwrap().as_bytes();
        if password != pass.as_ref() {
            return Err(InvalidPassword(user_id, "Password does not match".to_string()).into());
        };


        let client = format!("ClientSide: {}", user_id);
        let client_key = digest(&mut self.engine(), client.as_bytes());
        let mut client_sessions = HashMap::new();
        client_sessions.insert(
            client_key,
            client.as_bytes().to_vec(),
        );

        let server = format!("ServerSide: {}", user_id);
        let server_key = digest(&mut self.engine(), server.as_bytes());
        let mut server_sessions = HashMap::new();
        server_sessions.insert(
            server_key,
            server.as_bytes().to_vec(),
        );


        let session = Session::new(
            Some(client_sessions),
            Some(server_sessions),
        );

        Ok(Some(session))
    }
}


impl UserIdentity for DefaultVault {
    fn check_same_user<T: AsRef<[u8]>>(&self, user: T, user_from_token: T) -> Result<(), Error> {
        self.0.check_same_user(user, user_from_token)
    }
}

impl KeyStore for DefaultVault {
    fn key_pairs(&self) -> &KeyPairs {
        self.0.key_pairs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::thread;
    use std::time::Duration;


    fn block_thread(duration: Duration) {
        thread::sleep(duration)
    }

    fn generate_user_passwords() -> HashMap<String, String> {
        let mut user_passwords = HashMap::new();
        let user_john = "John Doe";
        let password_for_john = "john";
        let user_jane = "Jane Doe";
        let password_for_jane = "jane";
        user_passwords.insert(user_john.to_string(), password_for_john.to_string());
        user_passwords.insert(user_jane.to_string(), password_for_jane.to_string());
        user_passwords
    }


    #[test]
    fn test_workflow_feature_user_login() {
        let user_john = "John Doe";
        let password_for_john = "john";
        let _ = "Jane Doe";
        let password_for_jane = "jane";
        let mut vault = DefaultVault::new(generate_user_passwords());

        // login unsuccessful due to incorrect password
        let token = vault.login(user_john, password_for_jane, None, None);
        assert!(token.is_err());

        // Do login
        let token = vault.login(user_john, password_for_john, None, None);
        assert!(token.is_ok());
    }

    #[test]
    fn test_workflow_feature_user_session() {
        let user_john = "John Doe";
        let password_for_john = "john";
        let mut vault = DefaultVault::new(generate_user_passwords());

        // Do login
        let token = vault.login(user_john, password_for_john, None, None).ok().unwrap();
        let token = token.unwrap();

        let client_authentication_token = token.authentication_token();

        // Resolve server claims
        let server = vault.resolve_server_token_from_client_authentication_token(user_john.as_bytes(), client_authentication_token).ok().unwrap();

        // Decode authentication token
        let client = decode_client_token(vault.key_pairs().public_authentication_certificate().as_ref(), client_authentication_token).ok().unwrap();

        // Validate the data on server is same as the data on client
        assert_eq!(server.client().unwrap(), client.buffer().unwrap());
    }

    #[test]
    fn test_workflow_feature_authentication_token_refresh() {
        let user_john = "John Doe";
        let password_for_john = "john";
        let mut vault = DefaultVault::new(generate_user_passwords());

        // Do login
        let token = vault.login(
            user_john, password_for_john, Some(1i64), None,
        ).ok().unwrap();

        let token = token.unwrap();
        let client_authentication_token = token.authentication_token();
        let client_refresh_token = token.refresh_token();

        // Validate existing authentication token is good
        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), client_authentication_token,
        );
        assert!(server.is_ok());

        // Wait for authentication token to expire
        block_thread(Duration::from_secs(2));

        // Validate old authentication token cannot be used
        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), client_authentication_token,
        );
        assert!(server.is_err());

        // renew the token
        let new_client_authentication_token = vault.renew(
            user_john.as_bytes(), client_refresh_token, None,
        ).ok().unwrap();

        // Validate old authentication token cannot be used
        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), client_authentication_token,
        );
        assert!(server.is_err());

        // Validate new authentication token can be used
        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), &new_client_authentication_token,
        );
        assert!(server.is_ok());
    }

    #[test]
    fn test_workflow_feature_user_logout() {
        let user_john = "John Doe";
        let password_for_john = "john";
        let mut vault = DefaultVault::new(generate_user_passwords());

        // Do login
        let token = vault.login(
            user_john, password_for_john, None, None,
        ).ok().unwrap();

        let token = token.unwrap();
        let client_authentication_token = token.authentication_token();
        let client_refresh_token = token.refresh_token();

        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), client_authentication_token,
        );
        assert!(server.is_ok());

        // Do logout
        let _ = vault.logout(user_john.as_bytes(), client_authentication_token);

        // Old authentication token cannot be used to login
        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), client_authentication_token,
        );
        assert!(server.is_err());

        // Old refresh token cannot be used to renew
        let server = vault.renew(
            user_john.as_bytes(), client_refresh_token, None,
        );
        assert!(server.is_err());
    }

    #[test]
    fn test_security_feature_renew_not_possible_prior_to_login() {
        let user_john = "John Doe";
        let password_for_john = "john";
        let mut vault = DefaultVault::new(generate_user_passwords());
        // Do login - To get a token
        let token = vault.login(
            user_john, password_for_john, None, None,
        ).ok().unwrap().unwrap();

        let refresh_token = token.refresh_token();

        // Rew initialise vault to simulate stolen token
        let mut vault = DefaultVault::new(generate_user_passwords());
        let result = vault.renew(user_john.as_ref(), refresh_token, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_security_feature_new_authentication_invalidates_old_authentication() {
        let user_john = "John Doe";
        let password_for_john = "john";
        let mut vault = DefaultVault::new(generate_user_passwords());

        // Do login
        let token = vault.login(
            user_john, password_for_john, None, None,
        ).ok().unwrap();

        let token = token.unwrap();
        let client_authentication_token = token.authentication_token();

        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), client_authentication_token,
        );
        assert!(server.is_ok());

        // Do Re-login
        let new_token = vault.login(
            user_john, password_for_john, None, None,
        ).ok().unwrap();

        let new_token = new_token.unwrap();

        // Use new authentication
        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), new_token.authentication_token(),
        );
        assert!(server.is_ok());

        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), token.authentication_token(),
        );
        assert!(server.is_err());
    }

    #[test]
    fn test_security_feature_new_refresh_invalidates_old_refresh() {
        let user_john = "John Doe";
        let password_for_john = "john";
        let mut vault = DefaultVault::new(generate_user_passwords());

        // Do login
        let token = vault.login(
            user_john, password_for_john, None, None,
        ).ok().unwrap();

        let token = token.unwrap();


        let server = vault.renew(
            user_john.as_bytes(), token.refresh_token(), None,
        );
        assert!(server.is_ok());

        // Do Re-login
        let new_token = vault.login(
            user_john, password_for_john, None, None,
        ).ok().unwrap();

        let new_token = new_token.unwrap();

        // Use old refresh
        // TODO: Check if eager invalidation is required
        // TODO: Distributed login service may require some additional co-ordination
        // TODO: if sticky sessions are not supported/enabled
        let server = vault.renew(
            user_john.as_bytes(), token.refresh_token(), None,
        );
        assert!(server.is_ok());

        // Use new refresh
        let server = vault.renew(
            user_john.as_bytes(), new_token.refresh_token(), None,
        );
        assert!(server.is_ok());

        // Old refresh is invalidated
        let server = vault.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), token.refresh_token(),
        );
        assert!(server.is_err());
    }
}
