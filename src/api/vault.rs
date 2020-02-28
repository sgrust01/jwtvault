use crate::prelude::*;
use std::hash::Hasher;


/// Return normally if comparision succeeds else return an Error
#[async_trait]
pub trait UserIdentity {
    /// Implementation Required
    async fn check_same_user(&self, user: &str, user_from_token: &str) -> Result<(), Error>;
}


/// Return normally if login succeeds else return an Error
#[async_trait]
pub trait UserAuthentication {
    /// Implementation Required
    async fn check_user_valid(&mut self, user: &str, password: &str) -> Result<Option<Session>, Error>;
}

pub trait PasswordHasher<H: Default> {
    /// Implementation Required
    fn trust_token(&self) -> bool;
    fn hash_user_password<T: AsRef<str>>(&self, user: T,  password: T) -> Result<String, Error>;
    fn verify_user_password<T: AsRef<str>>(&self, user: T,  password: T,  hash: T) -> Result<bool, Error>;

}

/// Workflow for library user
/// [DefaultVault](../../utils/vault/struct.DefaultVault.html)
#[async_trait]
pub trait Workflow {
    async fn login(&mut self, user: &str, pass: &str, authentication_token_expiry_in_seconds: Option<i64>, refresh_token_expiry_in_seconds: Option<i64>) -> Result<Token, Error>;
    async fn renew(&mut self, user: &str, client_refresh_token: &String, authentication_token_expiry_in_seconds: Option<i64>) -> Result<String, Error>;
    async fn logout(&mut self, user: &str, client_authentication_token: &String) -> Result<(), Error>;
    async fn revoke(&mut self, client_refresh_token: &String) -> Result<(), Error>;
}


pub async fn resolve_session_from_client_authentication_token<H, V>(vault: &mut V, user: &str, token: &str) -> Result<ServerClaims, Error>
    where H: Default + Hasher, V: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence {
    let client_claims = decode_client_token(vault.public_authentication_certificate(), token)?;
    let user_from_token = String::from_utf8_lossy(client_claims.sub().as_slice()).to_string();
    let _ = vault.check_same_user(user, user_from_token.as_str()).await?;
    let public_certificate = vault.public_authentication_certificate();
    let claims = decode_client_token(public_certificate, token)?;

    let reference = claims.reference();
    let refresh_token_from_store = vault.load(reference).await;
    if refresh_token_from_store.is_none() {
        let msg = format!("User: {:?} Reference: {}", user, reference);
        let reason = "Missing Server Refresh Token".to_string();
        return Err(TokenErrors::MissingServerRefreshToken(msg, reason).into());
    };
    let refresh_token_from_store = refresh_token_from_store.unwrap();

    let digest_reference = resolve_authentication_reference::<_, H>(user.as_bytes());
    let authentication_token_from_store = vault.load(digest_reference).await;
    if let Some(expected) = authentication_token_from_store {
        let computed = format!("{}", digest::<_, H>(&token.as_bytes()));
        if expected != &computed {
            let msg = format!("User: {:?} Reference: {}", user, reference);
            let reason = format!(r"Invalid Authentication Token Expected: {} Got: {}", expected, computed);
            return Err(TokenErrors::InvalidClientAuthenticationToken(msg, reason).into());
        };
    };


    let public_certificate = &vault.public_refresh_certificate();
    let claims = decode_server_token(public_certificate, refresh_token_from_store.as_str())?;
    Ok(claims)
}

pub async fn resolve_session_from_client_refresh_token<H, V>(vault: &mut V, user: &str, client_refresh_token: &str) -> Result<ServerClaims, Error>
    where H: Default + Hasher, V: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence {
    let claims = decode_client_token(vault.public_refresh_certificate(), client_refresh_token)?;
    let user_from_token = String::from_utf8_lossy(claims.sub()).to_string();
    vault.check_same_user(user, user_from_token.as_str()).await?;
    let reference = claims.reference();
    let token = vault.load(reference).await;
    if token.is_none() {
        let msg = format!("User: {:?} Reference: {}", user, reference);
        let reason = "Missing Server Refresh Token".to_string();
        return Err(TokenErrors::MissingServerRefreshToken(msg, reason).into());
    };
    let token = token.unwrap();
    let server_claims = decode_server_token(vault.public_refresh_certificate(), token)?;
    if server_claims.iat() != claims.iat() {
        let msg = format!("Client Refresh: {:?} Server Refresh: {}", claims.iat(), server_claims.iat());
        let reason = "iat does not match".to_string();
        vault.remove(reference).await;
        return Err(TokenErrors::InvalidServerRefreshToken(msg, reason).into());
    };
    Ok(server_claims)
}

pub async fn continue_login<H, V>(vault: &mut V, user: &str, pass: &str, refresh_token_expiry_in_seconds: Option<i64>, authentication_token_expiry_in_seconds: Option<i64>) -> Result<Token, Error>
    where H: Default + Hasher, V: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence  {
    let session = vault.check_user_valid(user, pass).await?;
    let (client, server) = match session {
        Some(s) => (s.client, s.server),
        None => (None, None)
    };

    // Prepare: Token params
    let iat = compute_timestamp_in_seconds();
    let exp = compute_refresh_token_expiry(Some(iat), refresh_token_expiry_in_seconds);
    let nbf = iat;

    // Prepare: User reference
    let reference = resolve_refresh_reference::<_, H>(user.as_bytes());


    // Prepare: Server Token
    let server_token = prepare_server_token(
        vault.private_refresh_certificate(), user, reference, iat, nbf, exp, client.clone(), server,
    )?;

    // Prepare: Client Refresh Token
    let client_refresh_token = prepare_client_refresh_token(
        vault.private_refresh_certificate(), user, reference, iat, nbf, exp,
    )?;

    // Prepare: Client Authentication Token
    let exp = compute_authentication_token_expiry(Some(iat), authentication_token_expiry_in_seconds);
    let client_authentication_token = prepare_user_authentication_token(
        vault.private_authentication_certificate(), user, reference, iat, nbf, exp, client.clone(),
    )?;

    let digest_reference = resolve_authentication_reference::<_, H>(user.as_bytes());
    let digest_payload = format!("{}", digest::<_, H>(&client_authentication_token.as_bytes()));

    // This is used to invalided old authentication token
    vault.store(digest_reference, digest_payload).await;

    // This is used to track the server session
    vault.store(reference, server_token).await;


    let token = Token::new(client_authentication_token, client_refresh_token);

    Ok(token)
}

pub async fn continue_renew<H, V>(vault: &mut V, user: &str, client_refresh_token: &String, authentication_token_expiry_in_seconds: Option<i64>) -> Result<String, Error>
    where H: Default + Hasher, V: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence {
    let server_claims = resolve_session_from_client_refresh_token(vault, user, client_refresh_token).await?;

    let iat = compute_timestamp_in_seconds();
    let nbf = iat;
    let exp = compute_authentication_token_expiry(Some(iat), authentication_token_expiry_in_seconds);
    let reference = server_claims.reference();

    let client = match server_claims.client() {
        Some(client) => Some(client.clone()),
        None => None
    };

    let authentication_token = prepare_user_authentication_token(
        vault.private_authentication_certificate(), user, reference, iat, nbf, exp, client,
    )?;

    let digest_reference = resolve_authentication_reference::<_, H>(user.as_bytes());
    let digest_payload = format!("{}", digest::<_, H>(&authentication_token.as_bytes()));


    let auth_digest_from_store = vault.load(digest_reference).await;

    if auth_digest_from_store.is_some() {
        vault.store(digest_reference, digest_payload).await;
    } else {
        let msg = "Unable to perform renew since the user is not prior logged in".to_string();
        let reason = format!("Token: {} User: {:?}", client_refresh_token, user.as_bytes());
        return Err(LoginFailed::InvalidTokenOwner(msg, reason).into());
    };
    Ok(authentication_token)
}

pub async fn continue_logout<H, V>(vault: &mut V, user: &str, client_authentication_token: &String) -> Result<(), Error>
    where H: Default + Hasher, V: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence {
    let claims = decode_client_token(
        vault.public_authentication_certificate(), client_authentication_token,
    )?;
    let user_from_token = String::from_utf8_lossy(claims.sub()).to_string();
    vault.check_same_user(user, user_from_token.as_str()).await?;
    let reference = claims.reference();
    let result = vault.load(reference).await;
    if result.is_none() {
        let msg = format!("logout unsuccessful for user: {:#?}", user);
        let reason = "Authentication Token not found".to_string();
        return Err(TokenErrors::InvalidClientAuthenticationToken(msg, reason).into());
    };
    vault.remove(reference).await;
    Ok(())
}

pub async fn continue_revoke<H, V>(vault: &mut V, client_refresh_token: &String) -> Result<(), Error>
    where H: Default + Hasher, V: Store + UserIdentity + UserAuthentication + PersistenceHasher<H> + Persistence {
    let claim = decode_client_token(vault.public_refresh_certificate(), client_refresh_token)?;
    vault.remove(claim.reference()).await;
    Ok(())
}