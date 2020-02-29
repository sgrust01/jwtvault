use crate::prelude::*;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use argonautica::Hasher;


//pub async fn execute<H, E, F>(user: &[u8], token: &str, engine: &mut E, check_same_user: impl Fn(&[u8], &str) -> F) -> Result<ServerClaims, Error>
//    where F: Future<Output=Result<(), Error>>, H: Default + Hasher, E: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence {


#[derive(Debug, Clone, PartialEq)]
pub struct DefaultVault {
    public_authentication_certificate: PublicKey,
    private_authentication_certificate: PrivateKey,
    public_refresh_certificate: PublicKey,
    private_refresh_certificate: PrivateKey,
    password_hashing_secret: PrivateKey,
    trust_token_bearer: bool,
    store: HashMap<u64, String>,
    users: HashMap<String, String>,
}

impl PersistenceHasher<DefaultHasher> for DefaultVault {}


impl TrustToken for DefaultVault {
    fn trust_token_bearer(&self) -> bool {
        self.trust_token_bearer
    }
}


impl PasswordHasher<Hasher<'static>> for DefaultVault {
    fn hash_user_password<T: AsRef<str>>(&self, user: T, password: T) -> Result<String, Error> {
        let secret_key = self.password_hashing_secret.as_str();
        let result = hash_password_with_argon(password.as_ref(), secret_key.as_ref()).map_err(|e| {
            let msg = format!("Login failed for user: {}", user.as_ref());
            let reason = e.to_string();
            LoginFailed::PasswordHashingFailed(msg, reason).into()
        });

        result
    }
    fn verify_user_password<T: AsRef<str>>(&self, user: T, password: T, hash: T) -> Result<bool, Error> {
        let secret_key = self.password_hashing_secret.as_str();
        let result = verify_user_password_with_argon(
            password.as_ref(), secret_key.as_ref(), hash.as_ref(),
        ).map_err(|e| {
            let reason = e.to_string();
            let msg = format!("Login verification for user: {} Reason: {}", user.as_ref(), reason);
            let reason = e.to_string();
            LoginFailed::PasswordVerificationFailed(msg, reason).into()
        });
        result
    }
}

impl Store for DefaultVault {
    fn public_authentication_certificate(&self) -> &PublicKey {
        &self.public_authentication_certificate
    }

    fn private_authentication_certificate(&self) -> &PrivateKey {
        &self.private_authentication_certificate
    }

    fn public_refresh_certificate(&self) -> &PublicKey {
        &self.public_refresh_certificate
    }

    fn private_refresh_certificate(&self) -> &PrivateKey {
        &self.private_refresh_certificate
    }

    fn password_hashing_secret(&self) -> &PrivateKey {
        &self.password_hashing_secret
    }
}

impl DefaultVault {
    pub fn new<T: Keys>(loader: T, users: HashMap<String, String>, trust_token_bearer: bool) -> Self {
        let public_authentication_certificate = loader.public_authentication_certificate().clone();
        let private_authentication_certificate = loader.private_authentication_certificate().clone();
        let public_refresh_certificate = loader.public_refresh_certificate().clone();
        let private_refresh_certificate = loader.private_refresh_certificate().clone();
        let password_hashing_secret = loader.password_hashing_secret().clone();
        let store = HashMap::new();

        Self {
            public_authentication_certificate,
            private_authentication_certificate,
            public_refresh_certificate,
            private_refresh_certificate,
            password_hashing_secret,
            trust_token_bearer,
            store,
            users,
        }
    }
}


#[async_trait]
impl Persistence for DefaultVault {
    async fn store(&mut self, key: u64, value: String) {
        self.store.insert(key, value);
    }

    async fn load(&self, key: u64) -> Option<&String> {
        self.store.get(&key)
    }

    async fn remove(&mut self, key: u64) -> Option<String> {
        self.store.remove(&key)
    }
}

#[async_trait]
impl UserIdentity for DefaultVault {
    async fn check_same_user(&self, user: &str, user_from_token: &str) -> Result<(), Error> {
        if user != user_from_token {
            let msg = "Login Failed".to_string();
            let reason = "Invalid token".to_string();
            return Err(LoginFailed::InvalidTokenOwner(msg, reason).into());
        }
        Ok(())
    }
}

#[async_trait]
impl UserAuthentication for DefaultVault {
    async fn check_user_valid(&mut self, user: &str, password: &str) -> Result<Option<Session>, Error> {
        let password_from_disk = self.users.get(&user.to_string());

        if password_from_disk.is_none() {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };
        let password_from_disk = password_from_disk.unwrap();
        let result = self.verify_user_password(user, password, password_from_disk)?;
        if !result {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };

        let reference = digest::<_, DefaultHasher>(user.as_bytes());
        let mut server = HashMap::new();
        server.insert(reference, user.clone().as_bytes().to_vec());
        let session = Session::new(None, Some(server));
        Ok(Some(session))
    }
}


#[async_trait]
impl Workflow<DefaultHasher, Hasher<'static>> for DefaultVault {
    async fn login(&mut self, user: &str, pass: &str, authentication_token_expiry_in_seconds: Option<i64>, refresh_token_expiry_in_seconds: Option<i64>) -> Result<Token, Error> {
        continue_login(self, user, pass, authentication_token_expiry_in_seconds, refresh_token_expiry_in_seconds).await
    }

    async fn renew(&mut self, user: &str, client_refresh_token: &String, authentication_token_expiry_in_seconds: Option<i64>) -> Result<String, Error> {
        continue_renew(self, user, client_refresh_token, authentication_token_expiry_in_seconds).await
    }

    async fn logout(&mut self, user: &str, client_authentication_token: &String) -> Result<(), Error> {
        continue_logout(self, user, client_authentication_token).await
    }

    async fn revoke(&mut self, client_refresh_token: &String) -> Result<(), Error> {
        continue_revoke(self, client_refresh_token).await
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::default::Default;


    #[test]
    fn test_trusted_token_bearer_workflow() {
        let certificate = CertificateManger::default();
        // User: John Doe
        let user_john = "john_doe";
        let password_for_john = "john";
        // Save value 'hashed_password_for_john' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_john = hash_password_with_argon(password_for_john, certificate.password_hashing_secret().as_str()).unwrap();

        // User: Jane Doe
        let user_jane = "jane_doe";
        let password_for_jane = "jane";
        // Save 'hashed_password_for_jane' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_jane = hash_password_with_argon(password_for_jane, certificate.password_hashing_secret().as_str()).unwrap();

        let mut users = HashMap::new();

        // load users and their password from database/somewhere
        users.insert(user_john.to_string(), hashed_password_for_john.to_string());
        users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());

        // Initialize vault
        let mut vault = DefaultVault::new(certificate, users, true);

        // Login: John Doe
        let result = block_on(
            vault.login(
                user_john,
                password_for_john,
                None,
                None)
        );

        let token = result.ok().unwrap();

        // Decode client authentication token
        let client_claim = decode_client_token(
            &vault.public_authentication_certificate, token.authentication(),
        ).ok().unwrap();
        assert_eq!(client_claim.sub().as_slice(), user_john.as_bytes());

        // Decode client refresh token
        let client_claim = decode_client_token(
            &vault.public_refresh_certificate, token.refresh(),
        ).ok().unwrap();
        assert_eq!(client_claim.sub().as_slice(), user_john.as_bytes());

        // Decode server token
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, token.authentication(),
            )
        );
        let server_claims = result.ok().unwrap();
        // Validate client sub is same as Server sub
        assert_eq!(client_claim.sub(), server_claims.sub());

        // Renew: John Doe
        let new_auth_token = block_on(
            vault.renew(
                user_john,
                token.refresh(),
                None,
            )
        ).ok().unwrap();

        // Decode client token
        let new_client_claim = decode_client_token(
            &vault.public_authentication_certificate, &new_auth_token,
        ).ok().unwrap();
        assert_eq!(new_client_claim.sub(), server_claims.sub());

        // Decode server token
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &new_auth_token,
            )
        ).ok().unwrap();

        // Validate client sub is same as Server sub
        assert_eq!(result.sub().as_slice(), user_john.as_bytes());

        // Validate old token is invalid
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &token.authentication(),
            )
        );
        assert!(result.is_err());

        // Logout: John Doe
        let result = block_on(
            vault.logout(
                user_john, &new_auth_token,
            )
        );
        assert!(result.is_ok());

        // Validate first authentication token cannot be used
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &token.authentication(),
            )
        );
        assert!(result.is_err());

        // Validate second authentication token cannot be used
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &new_auth_token,
            )
        );
        assert!(result.is_err());

        // Validate renew with old refresh is not allowed
        let result = block_on(
            vault.renew(
                user_john,
                token.refresh(),
                None,
            )
        );
        assert!(result.is_err());

        // Re-login: John Doe
        let token = block_on(
            vault.login(
                user_john,
                password_for_john,
                None,
                None)
        ).ok().unwrap();

        // Validate decode server claims post re-login
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, token.authentication(),
            )
        );
        assert!(result.is_ok());

        // Revoke all token
        let result = block_on(
            vault.revoke(&token.refresh())
        );
        assert!(result.is_ok());

        // Validate renew is not allowed post revoke
        let result = block_on(
            vault.renew(user_john, &token.refresh(), None)
        );
        assert!(result.is_err());

        // Validate renew is not allowed post revoke by feeding incorrect token
        let result = block_on(
            vault.renew(user_john, &token.authentication(), None)
        );
        assert!(result.is_err());

        // Decode session from client authentication token is not allowed
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &token.authentication(),
            )
        );
        assert!(result.is_err());

        // Decode session from client refresh token is not allowed
        let result = block_on(
            resolve_session_from_client_refresh_token(
                &mut vault, user_john, &token.refresh(),
            )
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_untrusted_token_bearer_workflow() {
        let certificate = CertificateManger::default();
        // User: John Doe
        let user_john = "john_doe";
        let password_for_john = "john";
        // Save value 'hashed_password_for_john' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_john = hash_password_with_argon(password_for_john, certificate.password_hashing_secret().as_str()).unwrap();

        // User: Jane Doe
        let user_jane = "jane_doe";
        let password_for_jane = "jane";
        // Save 'hashed_password_for_jane' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_jane = hash_password_with_argon(password_for_jane, certificate.password_hashing_secret().as_str()).unwrap();

        let mut users = HashMap::new();

        // load users and their password from database/somewhere
        users.insert(user_john.to_string(), hashed_password_for_john.to_string());
        users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());

        // Initialize vault
        let mut vault = DefaultVault::new(certificate, users, false);

        // Login: John Doe
        let result = block_on(
            vault.login(
                user_john,
                password_for_john,
                None,
                None)
        );

        let token = result.ok().unwrap();

        // Decode client authentication token
        let client_claim = decode_client_token(
            &vault.public_authentication_certificate, token.authentication(),
        ).ok().unwrap();
        let user_john_from_token = Vec::<u8>::new();
        assert_eq!(client_claim.sub().as_slice(), user_john_from_token.as_slice());

        // Decode client refresh token
        let client_claim = decode_client_token(
            &vault.public_refresh_certificate, token.refresh(),
        ).ok().unwrap();
        let user_john_from_token = Vec::<u8>::new();
        assert_eq!(client_claim.sub().as_slice(), user_john_from_token.as_slice());

        // Decode server token
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, token.authentication(),
            )
        );
        let server_claims = result.ok().unwrap();
        // Validate client sub is same as Server sub
        assert_eq!(user_john.as_bytes(), server_claims.sub().as_slice());


        // Renew: John Doe
        let new_auth_token = block_on(
            vault.renew(
                user_john,
                token.refresh(),
                None,
            )
        ).ok().unwrap();

        // Decode client token
        let new_client_claim = decode_client_token(
            &vault.public_authentication_certificate, &new_auth_token,
        ).ok().unwrap();
        assert_eq!(new_client_claim.sub().as_slice(), user_john_from_token.as_slice());
        assert_eq!(user_john.as_bytes(), server_claims.sub().as_slice());

        // Decode server token
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &new_auth_token,
            )
        ).ok().unwrap();

        // Validate client sub is same as Server sub
        assert_eq!(result.sub().as_slice(), user_john.as_bytes());
        assert_eq!(result.sub().as_slice(), user_john.as_bytes());

        // Validate old token is invalid
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &token.authentication(),
            )
        );
        assert!(result.is_err());

        // Logout: John Doe
        let result = block_on(
            vault.logout(
                user_john, &new_auth_token,
            )
        );
        assert!(result.is_ok());

        // Validate first authentication token cannot be used
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &token.authentication(),
            )
        );
        assert!(result.is_err());

        // Validate second authentication token cannot be used
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &new_auth_token,
            )
        );
        assert!(result.is_err());

        // Validate renew with old refresh is not allowed
        let result = block_on(
            vault.renew(
                user_john,
                token.refresh(),
                None,
            )
        );
        assert!(result.is_err());

        // Re-login: John Doe
        let token = block_on(
            vault.login(
                user_john,
                password_for_john,
                None,
                None)
        ).ok().unwrap();

        // Validate decode server claims post re-login
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, token.authentication(),
            )
        );
        assert!(result.is_ok());

        // Revoke all token
        let result = block_on(
            vault.revoke(&token.refresh())
        );
        assert!(result.is_ok());

        // Validate renew is not allowed post revoke
        let result = block_on(
            vault.renew(user_john, &token.refresh(), None)
        );
        assert!(result.is_err());

        // Validate renew is not allowed post revoke by feeding incorrect token
        let result = block_on(
            vault.renew(user_john, &token.authentication(), None)
        );
        assert!(result.is_err());

        // Decode session from client authentication token is not allowed
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &token.authentication(),
            )
        );
        assert!(result.is_err());

        // Decode session from client refresh token is not allowed
        let result = block_on(
            resolve_session_from_client_refresh_token(
                &mut vault, user_john, &token.refresh(),
            )
        );
        assert!(result.is_err());
    }
}