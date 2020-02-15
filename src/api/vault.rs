//! # Vault Documentation
//!
//! ## [UserAuthentication](trait.UserAuthentication.html)
//! **_Client implementation required_** <br/><br/>
//!
//! **Purpose** <br/>
//! ___
//!
//! Validate user and password prior to token generation
//!
//! **Expectation from Implementation** <br/>
//! ___
//! * Return normally if comparision succeeds else return an Error
//! * Optionally return [Session](../session/struct.Session.html)
//!
//! **Workflow**
//! ___
//! Called by [login](trait.Vault.html#method.login)
//!
//!
//! ## [UserIdentity](trait.UserIdentity.html)
//! **_Client implementation required_** <br/><br/>
//!
//! **Purpose** <br/>
//! ___
//!
//! User on token is the same user user requesting resource
//!
//! **Expectation from Implementation** <br/>
//! ___
//! Return normally if comparision succeeds else return an Error
//!
//! **Workflow**
//! ___
//! Called by [resolve_server_token_from_client_authentication_token](trait.Vault.html#method.resolve_server_token_from_client_authentication_token)
//!
//!
//! ## [Vault](trait.Vault.html)
//!
//! **Purpose** <br/>
//! ___
//!
//! Orchestrate the overall workflow for JWT
use failure::Error;
use std::hash::Hasher;

use crate::prelude::*;

/// Implementation Required
pub trait UserIdentity {
    /// Implementation Required
    /// Return normally if comparision succeeds else return an Error
    fn check_same_user<T: AsRef<[u8]>>(&self, user: T, user_from_token: T) -> Result<(), Error>;
}

/// Implementation Required
pub trait UserAuthentication {
    /// Return normally if login succeeds else return an Error
    fn check_user_valid<T: AsRef<[u8]>>(&mut self, user: T, pass: T) -> Result<Option<Session>, Error>;
}

/// Will orchestrate the workflow
pub trait Vault<H: Hasher, S: SigningKeys>: KeyStore<S> + UserIdentity + UserAuthentication + Persistence + PersistenceHasher<H> {
    /// Prepares Client Authentication Token
    /// Manages the Client Authentication Buffer
    fn prepare_user_authentication_token(&self, iss: &[u8], reference: u64, iat: i64, nbf: i64, exp: i64, buffer: Option<Vec<u8>>) -> Result<String, Error> {
        let private_certificate = self.key_pairs().private_authentication_certificate();
        let token = encode_client_token(
            private_certificate, iss, buffer, reference, Some(exp), Some(nbf), Some(iat),
        )?;
        Ok(token)
    }

    /// Prepares Client Refresh Token
    fn prepare_client_refresh_token(&self, iss: &[u8], reference: u64, iat: i64, nbf: i64, exp: i64) -> Result<String, Error> {
        let private_certificate = self.key_pairs().private_refresh_certificate();
        let token = encode_client_token(
            private_certificate, iss, None, reference, Some(exp), Some(nbf), Some(iat),
        )?;
        Ok(token)
    }

    /// Prepares Server Refresh Token
    /// Manages the Client Authentication Buffer
    /// Manages the Server Refresh Buffer
    fn prepare_server_refresh_token(&self, iss: &[u8], reference: u64, iat: i64, nbf: i64, exp: i64, client: Option<Vec<u8>>, server: Option<Vec<u8>>) -> Result<String, Error> {
        let private_certificate = self.key_pairs().private_refresh_certificate();
        let token = encode_server_token(
            private_certificate, iss, client, server, reference, Some(exp), Some(nbf), Some(iat),
        )?;
        Ok(token)
    }

    /// Create a digest
    /// Based on following:
    /// User requesting the digest
    /// iat - issued at (time since epoch in seconds)
    /// exp - expiry (time since epoch in seconds)
    fn resolve_refresh_reference<T: AsRef<[u8]>>(&self, payload: T) -> u64 {
        let mut engine = self.engine();
        for i in [0u8, 1u8].iter() {
            engine.write_u8(*i);
        };

        for i in payload.as_ref() {
            engine.write_u8(*i);
        };
        engine.finish()
    }
    fn resolve_authentication_reference<T: AsRef<[u8]>>(&self, payload: T) -> u64 {
        let mut engine = self.engine();
        for i in [1u8, 0u8].iter() {
            engine.write_u8(*i);
        };
        for i in payload.as_ref() {
            engine.write_u8(*i);
        };
        engine.finish()
    }
    fn digest<T: AsRef<[u8]>>(&self, payload: T) -> u64 {
        let mut engine = self.engine();
        for i in payload.as_ref() {
            engine.write_u8(*i);
        };
        engine.finish()
    }
    /// Given valid user identifier and password
    /// Generate the following:
    /// Client Authentication Token (DEFAULT_AUTHENTICATION_MIN_EXPIRY_IN_SECONDS <= Validity < DEFAULT_AUTHENTICATION_MAX_EXPIRY_IN_SECONDS)
    /// Client Refresh Token (DEFAULT_REFRESH_WITH_NO_EXPIRY == Validity)
    fn login<T: AsRef<[u8]>>(&mut self, user: T, pass: T, authentication_token_expiry_in_seconds: Option<i64>, refresh_token_expiry_in_seconds: Option<i64>) -> Result<Option<Token>, Error> {
        // Check:  User login was valid
        let session = self.check_user_valid(user.as_ref(), pass.as_ref())?;

        // Prepare: Client & Server Payload
        let (client, server) = if session.is_some() {
            let session = session.unwrap();
            (session.client, session.server)
        } else {
            (None, None)
        };

        // Prepare: Token params
        let iat = compute_timestamp_in_seconds();
        let exp = compute_refresh_token_expiry(Some(iat), refresh_token_expiry_in_seconds);
        let nbf = iat;

        // Prepare: User reference
        let reference = self.resolve_refresh_reference(user.as_ref());

        // Prepare: Server Refresh Token
        let server_authentication_token = self.prepare_server_refresh_token(user.as_ref(), reference, iat, nbf, exp, client.clone(), server)?;


        // Prepare: Client Refresh Token
        let client_refresh_token = self.prepare_client_refresh_token(user.as_ref(), reference, iat, nbf, exp)?;

        // Prepare: Client Authentication Token
        let exp = compute_authentication_token_expiry(Some(iat), authentication_token_expiry_in_seconds);
        let client_authentication_token = self.prepare_user_authentication_token(
            user.as_ref(), reference, iat, nbf, exp, client,
        )?;

        let digest_reference = self.resolve_authentication_reference(user.as_ref());
        let digest_payload = format!("{}", self.digest(&client_authentication_token));

        self.store(reference, server_authentication_token);
        self.store(digest_reference, digest_payload);

        Ok(Some(Token::from((client_authentication_token, client_refresh_token))))
    }

    /// Resolves the server side data based on Client Authentication Token
    fn resolve_server_token_from_client_authentication_token(&self, user: &[u8], token: &str) -> Result<ServerClaims, Error> {
        let public_certificate = self.key_pairs().public_authentication_certificate();
        let claims = decode_client_token(public_certificate, token)?;
        self.check_same_user(user, claims.sub())?;

        let reference = claims.reference();
        let refresh_token_from_store = self.load(reference);
        if refresh_token_from_store.is_none() {
            let msg = format!("User: {:?} Reference: {}", user, reference);
            let reason = "Missing Server Refresh Token".to_string();
            return Err(MissingServerRefreshToken(msg, reason).into());
        };
        let refresh_token_from_store = refresh_token_from_store.unwrap();

        let digest_reference = self.resolve_authentication_reference(user.as_ref());
        let authentication_token_from_store = self.load(digest_reference);
        if let Some(expected) = authentication_token_from_store {
            let computed = format!("{}", self.digest(&token));
            if expected != &computed {
                let msg = format!("User: {:?} Reference: {}", user, reference);
                let reason = format!(r"Invalid Authentication Token Expected: {} Got: {}", expected, computed);
                return Err(InvalidClientAuthenticationToken(msg, reason).into());
            };
        };


        let public_certificate = self.key_pairs().public_refresh_certificate();
        let claims = decode_server_token(public_certificate, refresh_token_from_store.as_str())?;
        Ok(claims)
    }

    /// Resolves the server side data based on Client Refresh Token
    fn resolve_server_token_from_client_refresh_token(&mut self, user: &[u8], client_refresh_token: &String) -> Result<ServerClaims, Error> {
        let claims = decode_client_token(self.key_pairs().public_refresh_certificate(), client_refresh_token)?;
        self.check_same_user(user, claims.sub())?;
        let reference = claims.reference();
        let token = self.load(reference);
        if token.is_none() {
            let msg = format!("User: {:?} Reference: {}", user, reference);
            let reason = "Missing Server Refresh Token".to_string();
            return Err(MissingServerRefreshToken(msg, reason).into());
        };
        let token = token.unwrap();
        let server_claims = decode_server_token(self.key_pairs().public_refresh_certificate(), token)?;
        if server_claims.iat() != claims.iat() {
            let msg = format!("Client Refresh: {:?} Server Refresh: {}", claims.iat(), server_claims.iat());
            let reason = "iat does not match".to_string();
            self.remove(reference);
            return Err(InvalidServerRefreshToken(msg, reason).into());
        };
        Ok(server_claims)
    }

    /// To be used when user uses refresh token
    fn renew(&mut self, user: &[u8], client_refresh_token: &String, authentication_token_expiry_in_seconds: Option<i64>) -> Result<String, Error> {
        let server_claims = self.resolve_server_token_from_client_refresh_token(user, client_refresh_token)?;

        let iat = compute_timestamp_in_seconds();
        let nbf = iat;
        let exp = compute_authentication_token_expiry(Some(iat), authentication_token_expiry_in_seconds);
        let reference = server_claims.reference();

        let client = match server_claims.client() {
            Some(client) => Some(client.clone()),
            None => None
        };

        let authentication_token = self.prepare_user_authentication_token(
            user, reference, iat, nbf, exp, client,
        )?;

        let digest_reference = self.resolve_authentication_reference(user.as_ref());
        let digest_payload = format!("{}", self.digest(&authentication_token));


        let auth_digest_from_store = self.load(digest_reference);

        if auth_digest_from_store.is_some() {
            self.store(digest_reference, digest_payload);
        } else {
            let msg = "Unable to perform renew since the user is not prior logged in".to_string();
            let reason = format!("Token: {} User: {:?}", client_refresh_token, user.as_ref());
            return Err(InvalidTokenOwner(msg, reason).into());
        };
        Ok(authentication_token)
    }

    /// To be used when user forced logged out
    fn logout(&mut self, user: &[u8], client_authentication_token: &String) -> Result<(), Error> {
        let claims = decode_client_token(self.key_pairs().public_authentication_certificate(), client_authentication_token)?;
        self.check_same_user(user, claims.sub())?;
        let reference = claims.reference();
        let result = self.load(reference);
        if result.is_none() {
            let msg = format!("logout unsuccessful for user: {:#?}", user);
            let reason = "Authentication Token not found".to_string();
            return Err(InvalidClientAuthenticationToken(msg, reason).into());
        };
        self.remove(reference);
        Ok(())
    }

    /// To be used if fraud is detected
    fn revoke(&mut self, client_refresh_token: &String) -> Result<(), Error> {
        let claim = decode_client_token(self.key_pairs().public_refresh_certificate(), client_refresh_token)?;
        self.remove(claim.reference());
        Ok(())
    }
}


impl<H, T, S> Vault<H, S> for T
    where H: Hasher, T: KeyStore<S> + UserIdentity + UserAuthentication + Persistence + PersistenceHasher<H>, S: SigningKeys + Clone
{}


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::utils::token::{decode_client_token, decode_server_token};
    use std::default::Default;
    use std::thread;
    use std::time::Duration;
    use std::collections::hash_map::DefaultHasher;


    fn block_thread(duration: Duration) {
        thread::sleep(duration)
    }


    fn generate_users() -> HashMap<String, String> {
        let mut users = HashMap::new();
        users.insert("John Doe".to_string(), "john".to_string());
        users.insert("Jane Doe".to_string(), "jane".to_string());
        users
    }

    struct VaultManager<S: SigningKeys> {
        pub users: HashMap<String, String>,
        pub bank: HashMap<u64, String>,
        pub key_pairs: S,

    }

    impl<S: SigningKeys> VaultManager<S> {
        pub fn new(users: HashMap<String, String>, key_pairs: S) -> Self {
            let bank = HashMap::new();

            Self {
                users,
                bank,
                key_pairs,

            }
        }
    }

    impl<S: SigningKeys> PersistenceHasher<DefaultHasher> for VaultManager<S> {
        fn engine(&self) -> DefaultHasher {
            DefaultHasher::default()
        }
    }

    impl<S: SigningKeys> Persistence for VaultManager<S> {
        fn store(&mut self, key: u64, value: String) {
            self.bank.insert(key, value);
        }
        fn load(&self, key: u64) -> Option<&String> {
            self.bank.get(&key)
        }
        fn remove(&mut self, key: u64) -> Option<String> {
            self.bank.remove(&key)
        }
    }

    impl<S: SigningKeys> KeyStore<S> for VaultManager<S> {
        fn key_pairs(&self) -> &S {
            &self.key_pairs
        }
    }

    impl<S: SigningKeys> UserAuthentication for VaultManager<S> {
        fn check_user_valid<T: AsRef<[u8]>>(&mut self, user: T, pass: T) -> Result<Option<Session>, Error> {
            let user = String::from_utf8_lossy(user.as_ref()).to_string();
            let pass = String::from_utf8_lossy(pass.as_ref()).to_string();
            let password = self.users.get(&user);

            if password.is_none() {
                return Err(MissingPassword(user, "No password".to_string()).into());
            };
            let password = password.unwrap().as_bytes();
            // TODO: Check for timing attack
            let result = password == pass.as_bytes();
            if !result {
                return Err(InvalidPassword(user, "Invalid password".to_string()).into());
            };

            let client = Some(format!("Client:{}", user).into_bytes());
            let server = Some(format!("Server:{}", user).into_bytes());

            let session = Some(Session::new(
                client,
                server,
            ));

            Ok(session)
        }
    }

    impl<S: SigningKeys> UserIdentity for VaultManager<S> {
        fn check_same_user<T: AsRef<[u8]>>(&self, user: T, user_from_token: T) -> Result<(), Error> {
            if user_from_token.as_ref() != user.as_ref() {
                //TODO: Maybe monitor this
                let msg = "Unable to perform Logout since the user request does not match the token".to_string();
                let reason = format!("Token: {:?} User: {:?}", user_from_token.as_ref(), user.as_ref());
                return Err(InvalidTokenOwner(msg, reason).into());
            };
            Ok(())
        }
    }


    #[test]
    fn test_user_login() {
        let user = "John Doe";
        let password = "john";

        let expected_auth_buffer = format!("Client:{}", user);
        let expected_server_buffer = format!("Server:{}", user);


        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let result = manager.login(user.as_bytes(), password.as_bytes(), None, None).ok().unwrap();

        let token = result.unwrap();

        let refresh_jwt = token.refresh_token();
        let authentication_jwt = token.authentication_token();

        let public_certificate = manager.key_pairs().public_refresh_certificate();
        let refresh_token = decode_client_token(public_certificate, refresh_jwt).ok().unwrap();

        let public_certificate = manager.key_pairs().public_authentication_certificate();
        let authentication_token = decode_client_token(public_certificate, authentication_jwt).ok().unwrap();

        // #################
        // Validate: Tokens
        // #################

        // Validate Authentication Token belong to the user
        assert_eq!(authentication_token.sub().as_slice(), user.as_bytes());
        // Validate Refresh Token belong to the user
        assert_eq!(refresh_token.sub().as_slice(), user.as_bytes());
        // Validate Refresh & Authentication Token same same refresh as Server Refresh Token
        assert_eq!(refresh_token.reference(), authentication_token.reference());

        // ##############################
        // Validate: Authentication Token
        // ##############################
        let iat = authentication_token.iat().clone();
        let exp = authentication_token.exp().clone();
        let nbf = authentication_token.nbf().clone();


        assert!(exp <= (iat + DEFAULT_AUTHENTICATION_MAX_EXPIRY_IN_SECONDS));
        assert!(exp >= (iat + DEFAULT_AUTHENTICATION_MAX_EXPIRY_IN_SECONDS - DEFAULT_AUTHENTICATION_MIN_EXPIRY_IN_SECONDS));

        assert!((exp - iat) <= DEFAULT_AUTHENTICATION_MAX_EXPIRY_IN_SECONDS);
        assert!((exp - iat) >= DEFAULT_AUTHENTICATION_MIN_EXPIRY_IN_SECONDS);

        assert_eq!(nbf, iat);

        let client = String::from_utf8(authentication_token.buffer().unwrap().clone()).unwrap();
        assert_eq!(client, expected_auth_buffer);

        // #######################
        // Validate: Refresh Token
        // #######################

        let iat = refresh_token.iat().clone();
        let exp = refresh_token.exp().clone();
        let nbf = refresh_token.nbf().clone();

        assert_eq!(exp, DEFAULT_REFRESH_WITH_NO_EXPIRY);
        assert_eq!(nbf, iat);

        // Validate nothing was inject in the refresh token
        let buffer = refresh_token.buffer();
        assert!(buffer.is_none());

        // #################################################
        // Validate: Server v/s Client Authentication Token
        // #################################################
        let reference = authentication_token.reference();
        let session = manager.load(reference).unwrap();
        let public_certificate = manager.key_pairs().public_refresh_certificate();
        let session = decode_server_token(public_certificate, session.as_str()).ok().unwrap();

        // Validate Server Refresh mirrors Client Authentication Token
        assert_eq!(session.iat(), authentication_token.iat());
        assert_eq!(session.nbf(), authentication_token.nbf());
        assert_eq!(session.sub(), authentication_token.sub());
        // Validate Server Refresh does not mirror Client Authentication Token expiry
        assert_ne!(session.exp(), authentication_token.exp());
        // Validate client authentication and server refresh token have same references
        assert_eq!(session.reference(), authentication_token.reference());
        // Validate client authentication and expected buffer are same
        assert_eq!(*session.server().unwrap(), expected_server_buffer.clone().into_bytes());
        // Validate client authentication and server client buffer are same
        assert_eq!(*session.client().unwrap(), *authentication_token.buffer().unwrap());

        // #########################################
        // Validate: Server v/s Client Refresh Token
        // #########################################

        let reference = refresh_token.reference();
        let session = manager.load(reference).unwrap();
        let public_certificate = manager.key_pairs().public_refresh_certificate();
        let session = decode_server_token(public_certificate, session.as_str()).ok().unwrap();
        // Validate Server Refresh mirrors Client Refresh Token
        assert_eq!(session.iat(), refresh_token.iat());
        assert_eq!(session.nbf(), refresh_token.nbf());
        assert_eq!(session.sub(), refresh_token.sub());
        assert_eq!(session.exp(), refresh_token.exp());

        // Validate client refresh and server refresh token have same references
        assert_eq!(session.reference(), refresh_token.reference());
        // Validate client authentication and expected buffer are same
        assert_eq!(*session.server().unwrap(), expected_server_buffer.clone().into_bytes());
        // Validate client authentication and server client buffer are same
        assert_eq!(*session.client().unwrap(), *authentication_token.buffer().unwrap());
    }


    #[test]
    fn test_user_access_not_allowed_post_authentication_token_exp_until_renewed() {
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let user_john = "John Doe";
        let password_for_john = "john";

        let authentication_token_expiry_in_seconds = 1i64;
        // Set Client Authentication Token Expiry to one second
        let token_for_john = manager.login(user_john.to_string(), password_for_john.to_string(), Some(authentication_token_expiry_in_seconds), None).ok().unwrap().unwrap();
        // Extract Client Authentication Token
        let auth_token_for_john = token_for_john.authentication_token();
        // Use Client Authentication Token to login
        let server_claims_pre_expiry = manager.resolve_server_token_from_client_authentication_token(user_john.as_bytes(), auth_token_for_john.as_str()).ok().unwrap();
        // Validated Client Claims
        let client_claims = decode_client_token(manager.key_pairs().public_authentication_certificate(), auth_token_for_john.as_str()).ok().unwrap();
        // Validate Client Authentication Token expiry is set to one second
        assert_eq!(client_claims.exp() - client_claims.iat(), authentication_token_expiry_in_seconds);

        block_thread(Duration::from_secs(2u64));

        // Validate Client Authentication Token expired
        let result = manager.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), auth_token_for_john.as_str(),
        );
        assert!(result.is_err());

        // #################
        // renew the token
        // #################

        let renewed_auth_token_for_john = manager.renew(
            user_john.as_bytes(), token_for_john.refresh_token(), Some(authentication_token_expiry_in_seconds),
        ).ok().unwrap();

        // Validate expired Client Authentication Token cannot be used again
        let result = manager.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), auth_token_for_john.as_str(),
        );
        assert!(result.is_err());

        // Use Client Authentication Token to login
        let server_claims_post_expiry = manager.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), renewed_auth_token_for_john.as_str(),
        ).ok().unwrap();

        // Validated Client Claims
        let client_claims = decode_client_token(manager.key_pairs().public_authentication_certificate(), renewed_auth_token_for_john.as_str()).ok().unwrap();
        // Validate Client Authentication Token expiry is set to one second
        assert_eq!(client_claims.exp() - client_claims.iat(), authentication_token_expiry_in_seconds);

        assert_eq!(server_claims_pre_expiry, server_claims_post_expiry);

        block_thread(Duration::from_secs(2u64));

        // Validate Client Authentication Token expired
        let result = manager.resolve_server_token_from_client_authentication_token(user_john.as_bytes(), renewed_auth_token_for_john.as_str());
        assert!(result.is_err());
    }

    #[test]
    fn test_user_logout() {
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let user_john = "John Doe";
        let password_for_john = "john";
        let token_for_john = manager.login(user_john.to_string(), password_for_john.to_string(), None, None).ok().unwrap().unwrap();

        let server_claims = manager.resolve_server_token_from_client_authentication_token(user_john.as_bytes(), token_for_john.authentication_token());
        assert!(server_claims.is_ok());
        let reference = server_claims.ok().unwrap().reference();

        // Validate the server token is available
        let result = manager.load(reference);
        assert!(result.is_some());

        // ############
        // Force logout
        // ############

        let logged_out = manager.logout(user_john.as_bytes(), token_for_john.authentication_token());
        assert!(logged_out.is_ok());

        // Validate the authorization token cannot be used post logout.
        let server_claims = manager.resolve_server_token_from_client_authentication_token(user_john.as_bytes(), token_for_john.authentication_token());
        assert!(server_claims.is_err());

        // Validate the refresh token cannot be used post logout.
        let logged_out = manager.renew(user_john.as_bytes(), token_for_john.refresh_token(), None);
        assert!(logged_out.is_err());

        // Validate the server token is removed
        let result = manager.load(reference);
        assert!(result.is_none());
    }

    #[test]
    fn test_user_revocation() {
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let user_john = "John Doe";
        let password_for_john = "john";
        let token_for_john = manager.login(user_john.to_string(), password_for_john.to_string(), None, None).ok().unwrap().unwrap();

        let server_claims = manager.resolve_server_token_from_client_authentication_token(user_john.as_bytes(), token_for_john.authentication_token());
        assert!(server_claims.is_ok());
        let reference = server_claims.ok().unwrap().reference();

        // Validate the server token is available
        let result = manager.load(reference);
        assert!(result.is_some());

        // ############
        // Revoke Token
        // ############

        let logged_out = manager.revoke(token_for_john.refresh_token());
        assert!(logged_out.is_ok());

        // Validate the authorization token cannot be used post logout.
        let server_claims = manager.resolve_server_token_from_client_authentication_token(user_john.as_bytes(), token_for_john.authentication_token());
        assert!(server_claims.is_err());

        // Validate the refresh token cannot be used post logout.
        let logged_out = manager.renew(user_john.as_bytes(), token_for_john.refresh_token(), None);
        assert!(logged_out.is_err());

        // Validate the server token is removed
        let result = manager.load(reference);
        assert!(result.is_none());
    }

    #[test]
    fn test_user_cross_token_access_not_allowed() {
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let user_john = "John Doe";
        let password_for_john = "john";

        let token_for_john = manager.login(user_john.to_string(), password_for_john.to_string(), None, None).ok().unwrap().unwrap();
        let auth_token_for_john = token_for_john.authentication_token();

        let user_jane = "Jane Doe";
        let password_for_jane = "jane";

        let token_for_jane = manager.login(
            user_jane.to_string(), password_for_jane.to_string(), None, None,
        ).ok().unwrap().unwrap();
        let auth_token_for_jane = token_for_jane.authentication_token();

        //  Validate: Server Token success for a valid Client Authentication Token
        let result = manager.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), auth_token_for_john.as_str(),
        );
        assert!(result.is_ok());

        //  Validate: Server Token success for a valid Client Authentication Token
        let result = manager.resolve_server_token_from_client_authentication_token(
            user_jane.as_bytes(), auth_token_for_jane.as_str(),
        );
        assert!(result.is_ok());

        // ############
        // Cross Access
        // ############

        //  Validate: Server Token failed for a invalid Client Authentication Token (cross access)
        let result = manager.resolve_server_token_from_client_authentication_token(
            user_john.as_bytes(), auth_token_for_jane.as_str(),
        );
        assert!(result.is_err());

        //  Validate: Server Token failed for a invalid Client Authentication Token (cross access)
        let result = manager.resolve_server_token_from_client_authentication_token(
            user_jane.as_bytes(), auth_token_for_john.as_str(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_new_client_refresh_token_invalidates_old_token() {
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let user_john = "John Doe";
        let password_for_john = "john";

        let token_for_john = manager.login(
            user_john.to_string(), password_for_john.to_string(), None, None,
        ).ok().unwrap().unwrap();

        let result = manager.resolve_server_token_from_client_refresh_token(
            user_john.to_string().as_bytes(), token_for_john.refresh_token(),
        );
        assert!(result.is_ok());

        block_thread(Duration::from_secs(2));

        let new_token_for_john = manager.login(
            user_john.to_string(), password_for_john.to_string(), None, None,
        ).ok().unwrap().unwrap();


        let result = manager.resolve_server_token_from_client_refresh_token(
            user_john.to_string().as_bytes(), new_token_for_john.refresh_token(),
        );
        assert!(result.is_ok());


        let result = manager.resolve_server_token_from_client_refresh_token(
            user_john.to_string().as_bytes(), token_for_john.refresh_token(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_same_user_constraint() {
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let user_john = "John Doe";
        let password_for_john = "john";

        let token_for_john = manager.login(
            user_john.to_string(), password_for_john.to_string(), None, None,
        ).ok().unwrap().unwrap();

        let result = manager.check_same_user("Jane Doe".as_bytes(), token_for_john.authentication_token().as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn test_renewal_allowed_for_logged_in_users() {
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let user_john = "John Doe";
        let password_for_john = "john";

        let token_for_john = manager.login(
            user_john.to_string(), password_for_john.to_string(), None, None,
        ).ok().unwrap().unwrap();

        let result = manager.renew(
            user_john.to_string().as_bytes(), token_for_john.refresh_token(), None,
        );
        assert!(result.is_ok());

        let auth_ref = manager.resolve_authentication_reference(user_john.as_bytes());
        manager.remove(auth_ref);

        let result = manager.renew(
            user_john.to_string().as_bytes(), token_for_john.refresh_token(), None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_check_user_valid() {
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let user = "John Doe".as_bytes().to_vec();
        let password = vec![0xffu8];
        let token_for_john = manager.check_user_valid(
            user.as_slice(), password.as_slice(),
        );
        assert!(token_for_john.is_err());

        let user = vec![0xffu8];
        let password = "john".as_bytes().to_vec();
        let token_for_john = manager.check_user_valid(
            user.as_slice(), password.as_slice(),
        );
        assert!(token_for_john.is_err());

        let user = vec![0xffu8];
        let password = vec![0xffu8];
        let token_for_john = manager.check_user_valid(
            user.as_slice(), password.as_slice(),
        );
        assert!(token_for_john.is_err());
    }

    #[test]
    fn test_multiple_logout_not_allowed() {
        let keys = RSAKeys::default();
        let vault = KeyVault::new(
            keys.public_authentication(),
            keys.private_authentication(),
            keys.public_refresh(),
            keys.private_refresh(),
        );

        let mut manager = VaultManager::new(generate_users(), vault);

        let user_john = "John Doe";
        let password_for_john = "john";

        let token_for_john = manager.login(
            user_john.to_string(), password_for_john.to_string(), None, None,
        ).ok().unwrap().unwrap();

        let result = manager.logout(user_john.as_bytes(), token_for_john.authentication_token());
        assert!(result.is_ok());

        let result = manager.logout(user_john.as_bytes(), token_for_john.authentication_token());
        assert!(result.is_err());
    }
}

