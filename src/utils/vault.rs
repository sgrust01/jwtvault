use crate::prelude::*;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;


//pub async fn execute<H, E, F>(user: &[u8], token: &str, engine: &mut E, check_same_user: impl Fn(&[u8], &str) -> F) -> Result<ServerClaims, Error>
//    where F: Future<Output=Result<(), Error>>, H: Default + Hasher, E: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence {


pub struct DefaultVault {
    public_authentication_certificate: PublicKey,
    private_authentication_certificate: PrivateKey,
    public_refresh_certificate: PublicKey,
    private_refresh_certificate: PrivateKey,
    password_hasher: ArgonPasswordHasher,
    trust_token_bearer: bool,
    store: HashMap<u64, String>,
    users: HashMap<String, String>,
}


impl DefaultVault {
    pub fn new<T: Keys>(loader: T, users: HashMap<String, String>, trust_token_bearer: bool) -> Self {
        let public_authentication_certificate = loader.public_authentication_certificate().clone();
        let private_authentication_certificate = loader.private_authentication_certificate().clone();
        let public_refresh_certificate = loader.public_refresh_certificate().clone();
        let private_refresh_certificate = loader.private_refresh_certificate().clone();
        let secret_key = loader.password_hashing_secret();

        let password_hasher = ArgonPasswordHasher::new(secret_key.as_str());

        let store = HashMap::new();

        Self {
            public_authentication_certificate,
            private_authentication_certificate,
            public_refresh_certificate,
            private_refresh_certificate,
            password_hasher,
            trust_token_bearer,
            store,
            users,
        }
    }
}

impl PersistenceHasher<DefaultHasher> for DefaultVault {}


impl TrustToken for DefaultVault {
    fn trust_token_bearer(&self) -> bool {
        self.trust_token_bearer
    }
}


impl<'a> PasswordHasher<ArgonHasher<'a>> for DefaultVault {
    fn hash_user_password<T: AsRef<str>>(&self, user: T, password: T) -> Result<String, Error> {
        self.password_hasher.hash_user_password(user, password)
    }
    fn verify_user_password<T: AsRef<str>>(&self, user: T, password: T, hash: T) -> Result<bool, Error> {
        self.password_hasher.verify_user_password(user, password, hash)
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
impl<'a> Workflow<DefaultHasher, ArgonHasher<'a>> for DefaultVault {
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
    fn test_temporary_token_workflow() {
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

        let token = block_on(vault.login(user_john, password_for_john, None, None));
        let token = token.ok().unwrap();
        let user_account_authentication_token = token.authentication();

        let temp_token = block_on(
            continue_generate_temporary_authentication_token(&mut vault, user_john, None)
        );
        block_thread(1);
        // This token is one time non-renewable token
        let temp_token = temp_token.ok().unwrap();
        let authentication_token = temp_token.authentication();

        // Authentication token is only valid for limited period
        let public_authentication_certificate = vault.public_authentication_certificate();
        let result = decode_client_token(public_authentication_certificate, authentication_token);
        assert!(result.is_ok());
        let result = result.ok().unwrap();
        assert_eq!(result.exp() - result.iat(), DEFAULT_TEMPORARY_AUTHENTICATION_EXPIRY_IN_SECONDS);

        let result = block_on(
            resolve_temporary_session_from_client_authentication_token(&mut vault, user_john, authentication_token)
        );
        assert!(result.is_ok());
        let result = result.ok().unwrap();
        assert_eq!(result.exp() - result.iat(), DEFAULT_TEMPORARY_AUTHENTICATION_EXPIRY_IN_SECONDS);

        // Temporary session cannot be retrieved using authentication token from user login
        let result = block_on(
            resolve_temporary_session_from_client_authentication_token(&mut vault, user_john, user_account_authentication_token)
        );
        assert!(result.is_err());


        // Using temporary authentication token to retrieve the real user session is not allowed
        let result = block_on(
            resolve_session_from_client_authentication_token(&mut vault, user_john, authentication_token)
        );
        assert!(result.is_err());


        let public_refresh_certificate = vault.public_refresh_certificate();
        let refresh_token = temp_token.refresh();

        // Refresh token cannot be used to retrieve server session
        let result = decode_client_token(public_refresh_certificate, refresh_token);
        assert!(result.is_err());


        // Refresh token cannot be used to logout
        let result = block_on(continue_logout(&mut vault, user_john, authentication_token));
        assert!(result.is_err());

        // Refresh token cannot be used to revoke
        let result = block_on(continue_revoke(&mut vault, refresh_token));
        assert!(result.is_err());

        // Refresh token cannot be used to renew
        let result = block_on(continue_renew(&mut vault, user_john, refresh_token, None));
        assert!(result.is_err());
    }

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


    #[test]
    fn test_cross_feeding_not_allowed() {
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

        let token_for_john = result.ok().unwrap();

        // Login: Jane Doe
        let result = block_on(
            vault.login(
                user_jane,
                password_for_jane,
                None,
                None)
        );

        let token_for_jane = result.ok().unwrap();

        let result = block_on(
            resolve_session_from_client_refresh_token(
                &mut vault, user_john, token_for_jane.authentication(),
            )
        );
        assert!(result.is_err());

        let result = block_on(
            resolve_session_from_client_refresh_token(
                &mut vault, user_jane, token_for_john.authentication(),
            )
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_new_refresh_invalidates_old_refresh() {
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
        let token_for_john = result.ok().unwrap();

        let johns_refresh_token = token_for_john.refresh();

        let result = block_on(
            resolve_session_from_client_refresh_token(&mut vault, user_john, johns_refresh_token)
        );
        assert!(result.is_ok());

        let result = block_on(
            vault.login(
                user_john,
                password_for_john,
                None,
                None)
        );
        let new_token_for_john = result.ok().unwrap();
        let johns_new_refresh_token = new_token_for_john.refresh();

        let result = block_on(
            resolve_session_from_client_refresh_token(&mut vault, user_john, johns_new_refresh_token)
        );
        assert!(result.is_ok());
        let result = block_on(
            resolve_session_from_client_refresh_token(&mut vault, user_john, johns_refresh_token)
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_new_authentication_invalidates_old_authentication() {
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
        let token_for_john = result.ok().unwrap();

        let johns_authentication_token = token_for_john.authentication();

        let result = block_on(
            resolve_session_from_client_authentication_token(&mut vault, user_john, johns_authentication_token)
        );
        assert!(result.is_ok());

        let result = block_on(
            vault.login(
                user_john,
                password_for_john,
                None,
                None)
        );
        let new_token_for_john = result.ok().unwrap();
        let johns_new_authentication_token = new_token_for_john.authentication();

        let result = block_on(
            resolve_session_from_client_authentication_token(&mut vault, user_john, johns_new_authentication_token)
        );
        assert!(result.is_ok());
        let result = block_on(
            resolve_session_from_client_refresh_token(&mut vault, user_john, johns_authentication_token)
        );
        assert!(result.is_err());
    }
}