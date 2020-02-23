use crate::prelude::*;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;


//pub async fn execute<H, E, F>(user: &[u8], token: &str, engine: &mut E, check_same_user: impl Fn(&[u8], &str) -> F) -> Result<ServerClaims, Error>
//    where F: Future<Output=Result<(), Error>>, H: Default + Hasher, E: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence {


#[derive(Debug, Clone, PartialEq)]
pub struct DefaultVault {
    public_authentication_certificate: PublicKey,
    private_authentication_certificate: PrivateKey,
    public_refresh_certificate: PublicKey,
    private_refresh_certificate: PrivateKey,
    store: HashMap<u64, String>,
    users: HashMap<String, String>,
}

impl PersistenceHasher<DefaultHasher> for DefaultVault {}

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

impl DefaultVault {
    pub fn new<T: Keys>(loader: T, users: HashMap<String, String>) -> Self {
        let public_authentication_certificate = loader.public_authentication_certificate().clone();
        let private_authentication_certificate = loader.private_authentication_certificate().clone();
        let public_refresh_certificate = loader.public_refresh_certificate().clone();
        let private_refresh_certificate = loader.private_refresh_certificate().clone();
        let store = HashMap::new();

        Self {
            public_authentication_certificate,
            private_authentication_certificate,
            public_refresh_certificate,
            private_refresh_certificate,
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
        if password != password_from_disk.as_str() {
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
impl Workflow for DefaultVault {
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
    fn test_user_workflow() {
        let certificate = CertificateManger::default();
        // User: John Doe
        let user_john = "john_doe";
        let password_for_john = "john";

        // User: Jane Doe
        let user_jane = "jane_doe";
        let password_for_jane = "jane";
        let mut users = HashMap::new();

        // load users and their password from database/somewhere
        users.insert(user_john.to_string(), password_for_john.to_string());
        users.insert(user_jane.to_string(), password_for_jane.to_string());

        // Initialize vault
        let mut vault = DefaultVault::new(certificate, users);

        let result = block_on(
            vault.login(
                user_john,
                password_for_john,
                None,
                None)
        );
        let token = result.ok().unwrap();
        let client_claim = decode_client_token(
            &vault.public_authentication_certificate, token.authentication(),
        ).ok().unwrap();
        assert_eq!(client_claim.sub().as_slice(), user_john.as_bytes());
        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, token.authentication(),
            )
        );
        let server_claims = result.ok().unwrap();
        assert_eq!(client_claim.sub(), server_claims.sub());

        let new_auth_token = block_on(
            vault.renew(
                user_john,
                token.refresh(),
                None,
            )
        ).ok().unwrap();
        let new_client_claim = decode_client_token(
            &vault.public_authentication_certificate, &new_auth_token,
        ).ok().unwrap();
        assert_eq!(new_client_claim.sub(), server_claims.sub());

        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &new_auth_token,
            )
        ).ok().unwrap();

        assert_eq!(result.sub().as_slice(), user_john.as_bytes());

        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &token.authentication(),
            )
        );
        assert!(result.is_err());

        let result = block_on(
            vault.logout(
                user_john, &new_auth_token,
            )
        );
        assert!(result.is_ok());

        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &token.authentication(),
            )
        );
        assert!(result.is_err());

        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &new_auth_token,
            )
        );
        assert!(result.is_err());

        let token = block_on(
            vault.login(
                user_john,
                password_for_john,
                None,
                None)
        ).ok().unwrap();

        let result = block_on(
            vault.revoke(&token.refresh())
        );
        assert!(result.is_ok());

        let result = block_on(
            vault.renew(user_john, &token.refresh(), None)
        );
        assert!(result.is_err());

        let result = block_on(
            vault.renew(user_john, &token.authentication(), None)
        );
        assert!(result.is_err());

        let result = block_on(
            resolve_session_from_client_authentication_token(
                &mut vault, user_john, &token.authentication(),
            )
        );
        assert!(result.is_err());

        let result = block_on(
            resolve_session_from_client_refresh_token(
                &mut vault, user_john, &token.refresh(),
            )
        );
        assert!(result.is_err());
    }
}