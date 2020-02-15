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
use rand::Rng;
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
pub struct MemoryVault<H: Hasher + Default, V: SigningKeys + Clone> {
    user_passwords: HashMap<String, String>,
    store: HashMap<u64, String>,
    keys: V,
    hasher: H,
}

impl<H: Hasher + Default, V: SigningKeys + Clone> MemoryVault<H, V> {
    pub fn new(user_passwords: HashMap<String, String>, hasher: H, keys: V) -> Self {
        let store = HashMap::new();


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
impl<H: Hasher + Default, S: SigningKeys + Clone> KeyStore<S> for MemoryVault<H, S> {
    fn key_pairs(&self) -> &S {
        &self.keys
    }
}

/// Default Implementation
impl<H: Hasher + Default, S: SigningKeys + Clone> UserIdentity for MemoryVault<H, S> {
    fn check_same_user<T: AsRef<[u8]>>(&self, user: T, user_from_token: T) -> Result<(), Error> {
        if user.as_ref() == user_from_token.as_ref() {
            return Ok(());
        };
        let msg = "User mismatch".to_string();
        let reason = format!("Token: {:?} User: {:?}", user_from_token.as_ref(), user.as_ref());
        return Err(InvalidTokenOwner(msg, reason).into());
    }
}

impl<H: Hasher + Default, S: SigningKeys + Clone> PersistenceHasher<H> for MemoryVault<H, S> {
    fn engine(&self) -> H {
        <H as Default>::default()
    }
}

/// Default Implementation
impl<H: Hasher + Default, S: SigningKeys + Clone> UserAuthentication for MemoryVault<H, S> {
    /// Return normally if login succeeds else return an Error
    fn check_user_valid<T: AsRef<[u8]>>(&mut self, user: T, pass: T) -> Result<Option<Session>, Error> {
        let user = String::from_utf8(user.as_ref().to_vec())?;
        let password = self.user_passwords.get(&user);
        if password.is_none() {
            return Err(MissingPassword(user, "No password".to_string()).into());
        };
        let password = password.unwrap().as_bytes();
        if password != pass.as_ref() {
            return Err(InvalidPassword(user, "Password does not match".to_string()).into());
        };

        let mut rng = rand::thread_rng();
        let session = Session::new(
            Some(format!("ClientSide: {}", rng.gen_range(1, 1000)).into_bytes()),
            Some(format!("ServerSide: {}", rng.gen_range(1000, 100000)).into_bytes()),
        );

        Ok(Some(session))
    }
}

/// Default Implementation
impl<H: Hasher + Default, S: SigningKeys + Clone> Persistence for MemoryVault<H, S> {
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
pub struct DefaultVault<S: SigningKeys + Clone>(MemoryVault<MemoryHasher, S>);

impl<S: SigningKeys + Clone> Deref for DefaultVault<S> {
    type Target = MemoryVault<MemoryHasher, S>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S: SigningKeys + Clone> DerefMut for DefaultVault<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

//impl<V: SigningKeys + Clone> Clone for DefaultVault<V> {
//    fn clone(&self) -> Self {
//        Self::new(self.user_passwords().clone())
//    }
//}


impl<S: SigningKeys + Clone> DefaultVault<S> {
    pub fn new(user_passwords: HashMap<String, String>, keys: S) -> Self {
        let memory_vault = MemoryVault::new(user_passwords, MemoryHasher::default(), keys);
        DefaultVault(memory_vault)
    }
}


/// Default Implementation
impl<S: SigningKeys + Clone> UserAuthentication for DefaultVault<S> {
    /// Return normally if login succeeds else return an Error
    fn check_user_valid<T: AsRef<[u8]>>(&mut self, user: T, pass: T) -> Result<Option<Session>, Error> {
        let user = String::from_utf8(user.as_ref().to_vec())?;
        let password = self.user_passwords.get(&user);
        if password.is_none() {
            return Err(MissingPassword(user, "No password".to_string()).into());
        };
        let password = password.unwrap().as_bytes();
        if password != pass.as_ref() {
            return Err(InvalidPassword(user, "Password does not match".to_string()).into());
        };

        let mut rng = rand::thread_rng();
        let session = Session::new(
            Some(format!("{}", rng.gen_range(1, 1000)).into_bytes()),
            Some(format!("{}", rng.gen_range(1000, 100000)).into_bytes()),
        );

        Ok(Some(session))
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

        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut vault = DefaultVault::new(generate_user_passwords(), vault);

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

        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );


        let mut vault = DefaultVault::new(generate_user_passwords(), vault);


        // Do login
        let token = vault.login(user_john, password_for_john, None, None).ok().unwrap();
        let token = token.unwrap();

        let client_authentication_token = token.authentication_token();

        // Resolve server claims
        let server = vault.resolve_server_token_from_client_authentication_token(user_john.as_bytes(), client_authentication_token).ok().unwrap();

        // Decode authentication token
        let client = decode_client_token(vault.key_pairs().public_authentication_certificate(), client_authentication_token).ok().unwrap();

        // Validate the data on server is same as the data on client
        assert_eq!(server.client().unwrap(), client.buffer().unwrap());
    }

    #[test]
    fn test_workflow_feature_authentication_token_refresh() {
        let user_john = "John Doe";
        let password_for_john = "john";

        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );


        let mut vault = DefaultVault::new(generate_user_passwords(), vault);

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

        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );


        let mut vault = DefaultVault::new(generate_user_passwords(), vault);

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
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut vault = DefaultVault::new(generate_user_passwords(), vault);
        // Do login - To get a token
        let token = vault.login(
            user_john, password_for_john, None, None,
        ).ok().unwrap().unwrap();

        let refresh_token = token.refresh_token();

        // Rew initialise vault to simulate stolen token
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut vault = DefaultVault::new(generate_user_passwords(), vault);
        let result = vault.renew(user_john.as_ref(), refresh_token, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_security_feature_new_authentication_invalidates_old_authentication() {
        let user_john = "John Doe";
        let password_for_john = "john";
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut vault = DefaultVault::new(generate_user_passwords(), vault);

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
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut vault = DefaultVault::new(generate_user_passwords(), vault);

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
