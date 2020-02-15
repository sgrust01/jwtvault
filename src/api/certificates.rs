//! # Certificates Documentation
//! ## [CertificateLoader](trait.CertificateLoader.html)
//!
use failure::Error;

use jsonwebtoken::{EncodingKey, DecodingKey};
use std::ops::Deref;

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey<'a>(DecodingKey<'a>);

impl<'a> PublicKey<'a> {
    pub fn new(payload: &'a str) -> Self {
        Self(DecodingKey::from_rsa_pem(payload.as_bytes()).unwrap())
    }
}

impl<'a> Deref for PublicKey<'a> {
    type Target = DecodingKey<'a>;

    /// Dereferences the value.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey(EncodingKey);

impl Deref for PrivateKey {
    type Target = EncodingKey;

    /// Dereferences the value.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PrivateKey {
    pub fn new(payload: &str) -> Self {
        Self(EncodingKey::from_rsa_pem(payload.as_bytes()).unwrap())
    }
}


pub trait SigningKeys {
    fn public_authentication_certificate(&self) -> &PublicKey;
    fn private_authentication_certificate(&self) -> &PrivateKey;
    fn public_refresh_certificate(&self) -> &PublicKey;
    fn private_refresh_certificate(&self) -> &PrivateKey;
}

pub trait CertificateLoader<T> {
    fn load_public_certificate(&self, input: T) -> Result<Vec<u8>, Error>;
    fn load_private_certificate(&self, input: T) -> Result<Vec<u8>, Error>;
}
