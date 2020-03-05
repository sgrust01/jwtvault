use crate::prelude::*;
use std::collections::HashMap;
use std::default::Default;
use std::ops::{Deref, DerefMut};
use std::collections::hash_map::DefaultHasher;
use std::convert::From;

//pub async fn execute<H, E, F>(user: &[u8], token: &str, engine: &mut E, check_same_user: impl Fn(&[u8], &str) -> F) -> Result<ServerClaims, Error>
//    where F: Future<Output=Result<(), Error>>, H: Default + Hasher, E: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence {

/// Uses dynamic dispatch
pub struct DynamicVault {
    trust_token_bearer: bool,
    user_authentication: Box<dyn UserAuthentication + Send + Sync>,
    user_identity: Box<dyn UserIdentity + Send + Sync>,
    certificate_store: CertificateStore,
    password_hasher: ArgonPasswordHasher,
    store: HashMap<u64, String>,
}

struct DefaultIdentity;

#[async_trait]
impl UserIdentity for DefaultIdentity {
    async fn check_same_user(&self, user: &str, user_from_token: &str) -> Result<(), Error> {
        if user != user_from_token {
            let msg = "Login Failed".to_string();
            let reason = "Invalid token".to_string();
            return Err(LoginFailed::InvalidTokenOwner(msg, reason).into());
        }
        Ok(())
    }
}

impl DynamicVault {
    pub fn default(user_authentication: Box<dyn UserAuthentication + Send + Sync>) -> Self {
        let loader = CertificateManger::default();
        let trust_token_bearer = false;
        let user_identity = Box::new(DefaultIdentity);
        Self::new(loader, trust_token_bearer, user_authentication, user_identity)
    }
    pub fn new<T: Keys>(loader: T, trust_token_bearer: bool, user_authentication: Box<dyn UserAuthentication + Send + Sync>, user_identity: Box<dyn UserIdentity + Send + Sync>) -> Self {
        let password_hashing_secret = loader.password_hashing_secret();
        let certificate_store = CertificateStore::from(loader);
        let password_hasher = ArgonPasswordHasher::from(password_hashing_secret.clone());
        let store = HashMap::new();

        Self {
            trust_token_bearer,
            user_authentication,
            user_identity,
            certificate_store,
            password_hasher,
            store,
        }
    }
}

impl PersistenceHasher<DefaultHasher> for DynamicVault {}


impl TrustToken for DynamicVault {
    fn trust_token_bearer(&self) -> bool {
        self.trust_token_bearer
    }
}

impl PasswordHasher<ArgonPasswordHasher> for DynamicVault {
    fn hash_user_password<T: AsRef<str>>(&self, user: T, password: T) -> Result<String, Error> {
        self.password_hasher.hash_user_password(user, password)
    }
    fn verify_user_password<T: AsRef<str>>(&self, user: T, password: T, hash: T) -> Result<bool, Error> {
        self.password_hasher.verify_user_password(user, password, hash)
    }
}

impl Store for DynamicVault {
    fn public_authentication_certificate(&self) -> &PublicKey {
        self.certificate_store.public_authentication_certificate()
    }

    fn private_authentication_certificate(&self) -> &PrivateKey {
        self.certificate_store.private_authentication_certificate()
    }

    fn public_refresh_certificate(&self) -> &PublicKey {
        self.certificate_store.public_refresh_certificate()
    }

    fn private_refresh_certificate(&self) -> &PrivateKey {
        self.certificate_store.private_refresh_certificate()
    }
}


#[async_trait]
impl Persistence for DynamicVault {
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
impl UserIdentity for DynamicVault {
    async fn check_same_user(&self, user: &str, user_from_token: &str) -> Result<(), Error> {
        let _ = self.user_identity.check_same_user(user, user_from_token).await?;
        Ok(())
    }
}

#[async_trait]
impl UserAuthentication for DynamicVault {
    async fn check_user_valid(&mut self, user: &str, password: &str) -> Result<Option<Session>, Error> {
        let session = self.user_authentication.check_user_valid(user, password).await?;
        Ok(session)
    }
}


#[async_trait]
impl Workflow<DefaultHasher, ArgonPasswordHasher> for DynamicVault {
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

pub struct LoginInfo {
    users: HashMap<String, String>,
    hasher: ArgonPasswordHasher,
}

impl Deref for LoginInfo {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.users
    }
}

impl DerefMut for LoginInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.users
    }
}

impl LoginInfo {
    pub fn new(users: HashMap<String, String>) -> Self {
        let hasher = ArgonPasswordHasher::default();
        Self {
            users,
            hasher,
        }
    }
}


#[async_trait]
impl UserAuthentication for LoginInfo {
    async fn check_user_valid(&mut self, user: &str, password: &str) -> Result<Option<Session>, Error> {
        let password_from_disk = self.get(&user.to_string());

        if password_from_disk.is_none() {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };
        let password_from_disk = password_from_disk.unwrap();
        let result = self.hasher.verify_user_password(user, password, password_from_disk)?;
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


#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_trusted_token_bearer_workflow() {
        let loader = CertificateManger::default();
        let user_identity = Box::new(DefaultIdentity);
        let hasher = ArgonPasswordHasher::default();

        // User: John Doe
        let user_john = "john_doe";
        let password_for_john = "john";
        // Save value 'hashed_password_for_john' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_john = hasher.hash_user_password(user_john, password_for_john).unwrap();

        // User: Jane Doe
        let user_jane = "jane_doe";
        let password_for_jane = "jane";
        // Save 'hashed_password_for_jane' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_jane = hasher.hash_user_password(user_jane, password_for_jane).unwrap();

        let mut users = HashMap::new();

        // load users and their password from database/somewhere
        users.insert(user_john.to_string(), hashed_password_for_john.to_string());
        users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());

        // Setup app users
        let login = LoginInfo::new(users);

        // Initialize vault
        let mut vault = DynamicVault::new(loader, true, Box::new(login), user_identity);

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
            &vault.public_authentication_certificate(), token.authentication(),
        ).ok().unwrap();
        assert_eq!(client_claim.sub().as_slice(), user_john.as_bytes());

        // Decode client refresh token
        let client_claim = decode_client_token(
            &vault.public_refresh_certificate(), token.refresh(),
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
            &vault.public_authentication_certificate(), &new_auth_token,
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
        let hasher = ArgonPasswordHasher::default();
        // User: John Doe
        let user_john = "john_doe";
        let password_for_john = "john";
        // Save value 'hashed_password_for_john' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_john = hasher.hash_user_password(user_john, password_for_john).unwrap();

        // User: Jane Doe
        let user_jane = "jane_doe";
        let password_for_jane = "jane";
        // Save 'hashed_password_for_jane' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_jane = hasher.hash_user_password(user_jane, password_for_jane).unwrap();

        let mut users = HashMap::new();

        // load users and their password from database/somewhere
        users.insert(user_john.to_string(), hashed_password_for_john.to_string());
        users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());

        // Setup app users
        let login = LoginInfo::new(users);

        // Initialize vault
        let mut vault = DynamicVault::default(Box::new(login));

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
            &vault.public_authentication_certificate(), token.authentication(),
        ).ok().unwrap();
        let user_john_from_token = Vec::<u8>::new();
        assert_eq!(client_claim.sub().as_slice(), user_john_from_token.as_slice());

        // Decode client refresh token
        let client_claim = decode_client_token(
            &vault.public_refresh_certificate(), token.refresh(),
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
            &vault.public_authentication_certificate(), &new_auth_token,
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
        let hasher = ArgonPasswordHasher::default();
        // User: John Doe
        let user_john = "john_doe";
        let password_for_john = "john";
        // Save value 'hashed_password_for_john' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_john = hasher.hash_user_password(user_john, password_for_john).unwrap();

        // User: Jane Doe
        let user_jane = "jane_doe";
        let password_for_jane = "jane";
        // Save 'hashed_password_for_jane' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_jane = hasher.hash_user_password(user_jane, password_for_jane).unwrap();

        let mut users = HashMap::new();

        // load users and their password from database/somewhere
        users.insert(user_john.to_string(), hashed_password_for_john.to_string());
        users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());

        // Setup app users
        let login = LoginInfo::new(users);

        // Initialize vault
        let mut vault = DynamicVault::default(Box::new(login));


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
        let hasher = ArgonPasswordHasher::default();
        // User: John Doe
        let user_john = "john_doe";
        let password_for_john = "john";
        // Save value 'hashed_password_for_john' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_john = hasher.hash_user_password(user_john, password_for_john).unwrap();

        // User: Jane Doe
        let user_jane = "jane_doe";
        let password_for_jane = "jane";
        // Save 'hashed_password_for_jane' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_jane = hasher.hash_user_password(user_jane, password_for_jane).unwrap();

        let mut users = HashMap::new();

        // load users and their password from database/somewhere
        users.insert(user_john.to_string(), hashed_password_for_john.to_string());
        users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());

        // Setup app users
        let login = LoginInfo::new(users);

        // Initialize vault
        let mut vault = DynamicVault::default(Box::new(login));

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
        let hasher = ArgonPasswordHasher::default();
        // User: John Doe
        let user_john = "john_doe";
        let password_for_john = "john";
        // Save value 'hashed_password_for_john' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_john = hasher.hash_user_password(user_john, password_for_john).unwrap();

        // User: Jane Doe
        let user_jane = "jane_doe";
        let password_for_jane = "jane";
        // Save 'hashed_password_for_jane' to persistent storage
        // This is more relevant during user signup/password reset
        let hashed_password_for_jane = hasher.hash_user_password(user_jane, password_for_jane).unwrap();

        let mut users = HashMap::new();

        // load users and their password from database/somewhere
        users.insert(user_john.to_string(), hashed_password_for_john.to_string());
        users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());

        // Setup app users
        let login = LoginInfo::new(users);

        // Initialize vault
        let mut vault = DynamicVault::default(Box::new(login));

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