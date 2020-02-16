use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, DecodingKey, EncodingKey};

use failure::Error;

use crate::utils::helpers::compute_timestamp_in_seconds;
use crate::errors::TokenErrors::{TokenEncodingFailed, TokenDecodingFailed};
use std::collections::HashMap;


#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ClientClaims {
    sub: Vec<u8>,
    _buf: Option<HashMap<u64, Vec<u8>>>,
    _ref: u64,
    exp: i64,
    nbf: i64,
    iat: i64,

}

impl ClientClaims {
    pub fn new(sub: Vec<u8>, _buf: Option<HashMap<u64, Vec<u8>>>, _ref: u64, exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> Self {
        let iat = match iat {
            Some(iat) => iat,
            None => {
                compute_timestamp_in_seconds()
            }
        };

        let exp = match exp {
            Some(exp) => exp,
            None => {
                iat + 86400 // in seconds 24 * 60 * 60
            }
        };
        let nbf = match nbf {
            Some(nbf) => nbf,
            None => iat
        };

        Self { sub, _buf, _ref, exp, nbf, iat }
    }
    pub fn sub(&self) -> &Vec<u8> {
        &self.sub
    }
    pub fn iat(&self) -> &i64 {
        &self.iat
    }
    pub fn nbf(&self) -> &i64 {
        &self.nbf
    }
    pub fn exp(&self) -> &i64 {
        &self.exp
    }
    pub fn buffer(&self) -> Option<&HashMap<u64, Vec<u8>>> {
        self._buf.as_ref()
    }
    pub fn reference(&self) -> u64 {
        self._ref
    }
}

pub fn encode_client_token(private_certificate: &[u8], user_id: &[u8], _buf: Option<HashMap<u64, Vec<u8>>>, _ref: u64, exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> Result<String, Error> {
    let header = Header::new(Algorithm::RS256);
    let claims = ClientClaims::new(user_id.to_vec(), _buf, _ref, exp, nbf, iat);
    let key = EncodingKey::from_rsa_pem(private_certificate);
    if key.is_err() {
        let msg = key.err().unwrap().to_string();
        return Err(TokenEncodingFailed("Unable to encode token".to_string(), msg).into());
    };
    let key = key.unwrap();
    let token = encode(&header, &claims, &key);
    if token.is_err() {
        let msg = token.err().unwrap().to_string();
        return Err(TokenEncodingFailed("Unable to decode token".to_string(), msg).into());
    };
    let token = token.ok().unwrap();
    Ok(token)
}

pub fn decode_client_token(public_certificate: &[u8], token: &str) -> Result<ClientClaims, Error> {
    let validation = Validation::new(Algorithm::RS256);
    let key = DecodingKey::from_rsa_pem(public_certificate);
    if key.is_err() {
        let msg = key.err().unwrap().to_string();
        return Err(TokenDecodingFailed("Unable to encode token".to_string(), msg).into());
    };
    let key = key.unwrap();

    let result = decode::<ClientClaims>(token, &key, &validation);
    if result.is_err() {
        let msg = result.err().unwrap().to_string();
        return Err(TokenDecodingFailed("Unable to decode token".to_string(), msg).into());
    };
    let claims = result.ok().unwrap();
    let claims = claims.claims;
    Ok(claims)
}

// ======

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServerClaims {
    sub: Vec<u8>,
    _client: Option<HashMap<u64, Vec<u8>>>,
    _server: Option<HashMap<u64, Vec<u8>>>,
    _ref: u64,
    exp: i64,
    nbf: i64,
    iat: i64,

}

impl ServerClaims {
    pub fn new(sub: Vec<u8>, _client: Option<HashMap<u64, Vec<u8>>>, _server: Option<HashMap<u64, Vec<u8>>>, _ref: u64, exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> Self {
        let iat = match iat {
            Some(iat) => iat,
            None => {
                compute_timestamp_in_seconds()
            }
        };

        let exp = match exp {
            Some(exp) => exp,
            None => {
                iat + 86400 // in seconds 24 * 60 * 60
            }
        };
        let nbf = match nbf {
            Some(nbf) => nbf,
            None => iat
        };

        Self { sub, _client, _server, _ref, exp, nbf, iat }
    }
    pub fn sub(&self) -> &Vec<u8> {
        &self.sub
    }
    pub fn iat(&self) -> &i64 {
        &self.iat
    }
    pub fn nbf(&self) -> &i64 {
        &self.nbf
    }
    pub fn exp(&self) -> &i64 {
        &self.exp
    }
    pub fn client(&self) -> Option<&HashMap<u64, Vec<u8>>> {
        self._client.as_ref()
    }
    pub fn server(&self) -> Option<&HashMap<u64, Vec<u8>>> {
        self._server.as_ref()
    }
    pub fn reference(&self) -> u64 {
        self._ref
    }
}

pub fn encode_server_token(private_certificate: &[u8], user_id: &[u8], _client: Option<HashMap<u64, Vec<u8>>>, _server: Option<HashMap<u64, Vec<u8>>>, _ref: u64, exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> Result<String, Error> {
    let header = Header::new(Algorithm::RS256);
    let claims = ServerClaims::new(user_id.to_vec(), _client, _server, _ref, exp, nbf, iat);
    let key = EncodingKey::from_rsa_pem(private_certificate);
    if key.is_err() {
        let msg = key.err().unwrap().to_string();
        return Err(TokenEncodingFailed("Unable to encode token".to_string(), msg).into());
    };
    let key = key.unwrap();
    let token = encode(&header, &claims, &key);
    if token.is_err() {
        let msg = token.err().unwrap().to_string();
        return Err(TokenEncodingFailed("Unable to encode token".to_string(), msg).into());
    };
    let token = token.ok().unwrap();
    Ok(token)
}

pub fn decode_server_token(public_certificate: &[u8], token: &str) -> Result<ServerClaims, Error> {
    let validation = Validation::new(Algorithm::RS256);
    let key = DecodingKey::from_rsa_pem(public_certificate);
    if key.is_err() {
        let msg = key.err().unwrap().to_string();
        return Err(TokenDecodingFailed("Unable to encode token".to_string(), msg).into());
    };
    let key = key.unwrap();
    let result = decode::<ServerClaims>(token, &key, &validation);
    if result.is_err() {
        let msg = result.err().unwrap().to_string();
        return Err(TokenDecodingFailed("Unable to decode token".to_string(), msg).into());
    };
    let claims = result.ok().unwrap();
    let claims = claims.claims;
    Ok(claims)
}


//=====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::helpers::digest;
    use std::collections::hash_map::DefaultHasher;

    #[test]
    fn validate_token_validity() {
        let sub: Vec<u8> = "user".to_string().into_bytes();
        let _buf = "buffer".to_string().into_bytes();
        let mut buffer = HashMap::new();
        buffer.insert(
            digest(&mut DefaultHasher::default(), "buffer".as_bytes()),
            _buf
        );

        let _ref: u64 = 1u64;
        let claims = ClientClaims::new(sub, Some(buffer), _ref, None, None, None);
        assert_eq!(claims.exp - claims.iat, 86400);
        assert_eq!(claims.nbf, claims.iat);
    }

    #[test]
    fn validate_token_default_validity() {
        let iat = compute_timestamp_in_seconds();
        let sub: Vec<u8> = "user".to_string().into_bytes();
        let _buf = "buffer".to_string().into_bytes();

        let mut buffer = HashMap::new();
        buffer.insert(
            digest(&mut DefaultHasher::default(), "buffer".as_bytes()),
            _buf);



        let _ref: u64 = 1u64;
        let exp = iat + 86400;
        let nbf = iat;
        let iat = Some(iat);
        let claims = ClientClaims::new(sub, Some(buffer), _ref, None, None, iat);
        assert_eq!(claims.iat, iat.unwrap());
        assert_eq!(claims.exp, exp);
        assert_eq!(claims.nbf, nbf);
    }

    #[test]
    fn invalidate_encode_client_token() {
        let private_certificate = "no certificates".as_bytes().to_vec();
        let user_id = "userid".as_bytes().to_vec();
        let _ref = 1u64;
        let result = encode_client_token(private_certificate.as_slice(), user_id.as_slice(), None, _ref, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_server_token_validity() {
        let sub = "user".as_bytes().to_vec();
        let mut client_session = HashMap::new();
        let mut server_session = HashMap::new();
        let _client = "client".as_bytes().to_vec();
        let _server = "server".as_bytes().to_vec();
        client_session.insert(
            digest(&mut DefaultHasher::default(), "client".as_bytes()),
            _client
        );
        server_session.insert(
            digest(&mut DefaultHasher::default(), "server".as_bytes()),
            _server
        );
        let _ref = 1u64;

        let claims = ServerClaims::new(
            sub.clone(), Some(client_session.clone()), Some(server_session.clone()),
            _ref, None, None, None,
        );
        assert_eq!(claims.exp - claims.iat, 86400);
        assert_eq!(claims.nbf, claims.iat);
    }

    #[test]
    fn invalidate_encode_server_token() {
        let private_certificate = "no certificates".as_bytes().to_vec();
        let user_id = "userid".as_bytes().to_vec();
        let _ref = 1u64;
        let result = encode_server_token(private_certificate.as_slice(), user_id.as_slice(), None, None, _ref, None, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn invalidate_decode_server_token() {
        let private_certificate = "no certificates".as_bytes().to_vec();
        let token = "no token";
        let result = decode_server_token(private_certificate.as_slice(), token);
        assert!(result.is_err());
    }
}