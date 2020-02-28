use std::ops::Deref;

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey(String);

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey(String);

pub trait Store {
    fn public_authentication_certificate(&self) -> &PublicKey;
    fn private_authentication_certificate(&self) -> &PrivateKey;
    fn public_refresh_certificate(&self) -> &PublicKey;
    fn private_refresh_certificate(&self) -> &PrivateKey;
    fn password_hashing_secret(&self) -> &PrivateKey;
}

pub trait Keys {
    fn public_authentication_certificate(&self) -> PublicKey;
    fn private_authentication_certificate(&self) -> PrivateKey;
    fn public_refresh_certificate(&self) -> PublicKey;
    fn private_refresh_certificate(&self) -> PrivateKey;
    fn password_hashing_secret(&self) -> PrivateKey;
}

impl Deref for PrivateKey {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PublicKey {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for PublicKey {
    fn from(data: String) -> Self {
        PublicKey(data)
    }
}

impl From<String> for PrivateKey {
    fn from(data: String) -> Self {
        PrivateKey(data)
    }
}

impl Into<String> for PublicKey {
    fn into(self) -> String {
        self.0
    }
}

impl Into<String> for PrivateKey {
    fn into(self) -> String {
        self.0
    }
}