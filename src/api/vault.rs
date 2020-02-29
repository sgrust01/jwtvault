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

pub trait TrustToken {
    /// Implementation Required
    fn trust_token_bearer(&self) -> bool;
}


pub trait PasswordHasher<H: Default> {
    /// Implementation Required
    fn hash_user_password<T: AsRef<str>>(&self, user: T, password: T) -> Result<String, Error>;
    fn verify_user_password<T: AsRef<str>>(&self, user: T, password: T, hash: T) -> Result<bool, Error>;
}

/// Workflow for library user
/// [DefaultVault](../../utils/vault/struct.DefaultVault.html)
#[async_trait]
pub trait Workflow<H, D>: Store + PersistenceHasher<H> + Persistence + UserIdentity + UserAuthentication + TrustToken + PasswordHasher<D>
    where H: Hasher + Default, D: Default {
    async fn login(&mut self, user: &str, pass: &str, authentication_token_expiry_in_seconds: Option<i64>, refresh_token_expiry_in_seconds: Option<i64>) -> Result<Token, Error>;
    async fn renew(&mut self, user: &str, client_refresh_token: &String, authentication_token_expiry_in_seconds: Option<i64>) -> Result<String, Error>;
    async fn logout(&mut self, user: &str, client_authentication_token: &String) -> Result<(), Error>;
    async fn revoke(&mut self, client_refresh_token: &String) -> Result<(), Error>;
}


pub async fn resolve_session_from_client_authentication_token<W, H, D>(vault: &mut W, user: &str, token: &str) -> Result<ServerClaims, Error>
    where H: Hasher + Default, D: Default, W: Workflow<H, D> {
    // Decode client authentication token
    let public_certificate = vault.public_authentication_certificate();
    let claims = decode_client_token(public_certificate, token)?;

    // Get server side token
    let reference = claims.reference();
    let refresh_token_from_store = vault.load(reference).await;
    if refresh_token_from_store.is_none() {
        let msg = format!("User: {:?} Reference: {}", user, reference);
        let reason = "Missing Server Refresh Token".to_string();
        return Err(TokenErrors::MissingServerRefreshToken(msg, reason).into());
    };

    // Decode server side token
    let public_certificate = vault.public_refresh_certificate();
    let refresh_token_from_store = refresh_token_from_store.unwrap();
    let claims = decode_server_token(public_certificate, refresh_token_from_store.as_str())?;

    // Restore server side token
    let user_from_token = String::from_utf8_lossy(claims.sub()).to_string();

    // Call hook
    let _ = vault.check_same_user(user, user_from_token.as_str()).await?;

    // Given the user on server side check if the authentication token was valid
    let user_digest = resolve_authentication_reference::<_, H>(user_from_token.as_bytes());
    let token_digest_from_store = vault.load(user_digest).await;
    if token_digest_from_store.is_none() {
        let msg = format!("User: {:?} has no session information", user_from_token);
        let reason = format!("User: {:?} has no data in vault", user_from_token);
        return Err(TokenErrors::MissingServerRefreshToken(msg, reason).into());
    };
    let token_digest_from_store = token_digest_from_store.unwrap();
    let user_token = digest::<_, H>(&token.as_bytes());
    let user_token = format!("{}", user_token);
    if token_digest_from_store.as_str() != user_token {
        let msg = format!("User: {} client authentication token is not valid", user_from_token);
        let reason = format!("Requested: {} Available: {}", user_token, token_digest_from_store);
        return Err(TokenErrors::InvalidClientAuthenticationToken(msg, reason).into());
    }

    Ok(claims)
}

pub async fn resolve_session_from_client_refresh_token<W, H, D>(vault: &mut W, user: &str, client_refresh_token: &str) -> Result<ServerClaims, Error>
    where H: Hasher + Default, D: Default, W: Workflow<H, D> {
    let claims = decode_client_token(vault.public_refresh_certificate(), client_refresh_token)?;
    let reference = claims.reference();

    // load the server side token via the reference on the client side
    let refresh_token_from_store = vault.load(reference).await;
    if refresh_token_from_store.is_none() {
        let msg = format!("User: {:?} Reference: {}", user, reference);
        let reason = "Missing Server Refresh Token".to_string();
        return Err(TokenErrors::MissingServerRefreshToken(msg, reason).into());
    };
    let refresh_token_from_store = refresh_token_from_store.unwrap();

    // Decode server side token
    let public_certificate = vault.public_refresh_certificate();
    let server_claims = decode_server_token(public_certificate, refresh_token_from_store.as_str())?;

    // Restore user from server side token
    let user_from_token = String::from_utf8_lossy(server_claims.sub()).to_string();

    // Validate iat on client on server are same. If not, destroy the server claim and return error
    if server_claims.iat() != claims.iat() {
        let msg = format!("Client Refresh: {:?} Server Refresh: {}", claims.iat(), server_claims.iat());
        let reason = "iat does not match".to_string();
        vault.remove(reference).await;
        return Err(TokenErrors::InvalidServerRefreshToken(msg, reason).into());
    };

    // Call hook
    let _ = vault.check_same_user(user, user_from_token.as_str()).await?;

    Ok(server_claims)
}

pub async fn continue_login<W, H, D>(vault: &mut W, user: &str, pass: &str, refresh_token_expiry_in_seconds: Option<i64>, authentication_token_expiry_in_seconds: Option<i64>) -> Result<Token, Error>
    where H: Hasher + Default, D: Default, W: Workflow<H, D> {
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
    let client_refresh_token = if vault.trust_token_bearer() {
        prepare_client_refresh_token(
            vault.private_refresh_certificate(), user, reference, iat, nbf, exp,
        )
    } else {
        let u = Vec::<u8>::new();
        prepare_client_refresh_token(
            vault.private_refresh_certificate(), u.as_slice(), reference, iat, nbf, exp,
        )
    }?;

    // Prepare: Client Authentication Token
    let exp = compute_authentication_token_expiry(Some(iat), authentication_token_expiry_in_seconds);
    let client_authentication_token = if vault.trust_token_bearer() {
        prepare_user_authentication_token(
            vault.private_authentication_certificate(), user, reference, iat, nbf, exp, client.clone(),
        )
    } else {
        let u = Vec::<u8>::new();
        prepare_user_authentication_token(
            vault.private_authentication_certificate(), u.as_slice(), reference, iat, nbf, exp, client.clone(),
        )
    }?;


    let digest_reference = resolve_authentication_reference::<_, H>(user.as_bytes());
    let digest_payload = format!("{}", digest::<_, H>(&client_authentication_token.as_bytes()));

    // This is used to invalided old authentication token
    vault.store(digest_reference, digest_payload).await;

    // This is used to track the server session
    vault.store(reference, server_token).await;


    let token = Token::new(client_authentication_token, client_refresh_token);

    Ok(token)
}

pub async fn continue_renew<W, H, D>(vault: &mut W, user: &str, client_refresh_token: &String, authentication_token_expiry_in_seconds: Option<i64>) -> Result<String, Error>
    where H: Hasher + Default, D: Default, W: Workflow<H, D> {
    let server_claims = resolve_session_from_client_refresh_token(vault, user, client_refresh_token).await?;

    let iat = compute_timestamp_in_seconds();
    let nbf = iat;
    let exp = compute_authentication_token_expiry(Some(iat), authentication_token_expiry_in_seconds);
    let reference = server_claims.reference();

    let client = match server_claims.client() {
        Some(client) => Some(client.clone()),
        None => None
    };

    let authentication_token = if vault.trust_token_bearer() {
        prepare_user_authentication_token(
            vault.private_authentication_certificate(), user, reference, iat, nbf, exp, client.clone(),
        )
    } else {
        let u = Vec::<u8>::new();
        prepare_user_authentication_token(
            vault.private_authentication_certificate(), u.as_slice(), reference, iat, nbf, exp, client.clone(),
        )
    }?;


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

pub async fn continue_logout<W, H, D>(vault: &mut W, user: &str, client_authentication_token: &String) -> Result<(), Error>
    where H: Hasher + Default, D: Default, W: Workflow<H, D> {
    let claims = resolve_session_from_client_authentication_token::<>(vault, user, client_authentication_token).await?;
    let reference = claims.reference();
    let result = vault.load(reference).await;
    if result.is_none() {
        let msg = format!("logout unsuccessful for user: {:#?}", user);
        let reason = "Authentication Token not found".to_string();
        return Err(TokenErrors::InvalidClientAuthenticationToken(msg, reason).into());
    };

    let _ = vault.remove(reference).await;
    let key = digest::<_, H>(user.as_bytes());
    let _ = vault.remove(key).await;

    Ok(())
}

pub async fn continue_revoke<W, H, D>(vault: &mut W, client_refresh_token: &String) -> Result<(), Error>
    where H: Hasher + Default, D: Default, W: Workflow<H, D> {
    let claim = decode_client_token(vault.public_refresh_certificate(), client_refresh_token)?;
    vault.remove(claim.reference()).await;
    Ok(())
}