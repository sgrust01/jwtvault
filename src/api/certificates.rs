//! # Certificates Documentation
//! ## [CertificateLoader](trait.CertificateLoader.html)
//!
use failure::Error;

pub trait CertificateLoader<T> {
    fn load_public_certificate(&self, input: T) -> Result<Vec<u8>, Error>;
    fn load_private_certificate(&self, input: T) -> Result<Vec<u8>, Error>;
}

/// To be used for generating Token (JWT)
#[derive(Clone, PartialEq, Debug)]
pub struct KeyPairs
{
    authentication: AuthenticationKeyPair,
    refresh: RefreshKeyPair,
}

/// To be used for generating Authentication Token (JWT)
#[derive(Clone, PartialEq, Debug)]
pub struct AuthenticationKeyPair {
    public_certificate: Vec<u8>,
    private_certificate: Vec<u8>,
}

/// To be used for generating Refresh Token (JWT)
#[derive(Clone, PartialEq, Debug)]
pub struct RefreshKeyPair {
    public_certificate: Vec<u8>,
    private_certificate: Vec<u8>,
}

impl AuthenticationKeyPair {
    pub fn new(public_certificate: Vec<u8>, private_certificate: Vec<u8>) -> Self {
        Self {
            public_certificate,
            private_certificate,
        }
    }
    pub fn public_certificate(&self) -> &[u8] {
        self.public_certificate.as_slice()
    }
    pub fn private_certificate(&self) -> &[u8] {
        self.private_certificate.as_slice()
    }
}

impl RefreshKeyPair {
    pub fn new(public_certificate: Vec<u8>, private_certificate: Vec<u8>) -> Self {
        Self {
            public_certificate,
            private_certificate,
        }
    }
    pub fn public_certificate(&self) -> &[u8] {
        self.public_certificate.as_slice()
    }
    pub fn private_certificate(&self) -> &[u8] {
        self.private_certificate.as_slice()
    }
}


impl KeyPairs {
    pub fn new(authentication: AuthenticationKeyPair, refresh: RefreshKeyPair) -> Self {
        Self {
            authentication,
            refresh,
        }
    }

    pub fn authentication_key_pair(&self) -> &AuthenticationKeyPair {
        &self.authentication
    }

    pub fn refresh_key_pair(&self) -> &RefreshKeyPair {
        &self.refresh
    }

    pub fn public_authentication_certificate(&self) -> &[u8] {
        self.authentication_key_pair().public_certificate()
    }

    pub fn private_authentication_certificate(&self) -> &[u8] {
        self.authentication_key_pair().private_certificate()
    }

    pub fn public_refresh_certificate(&self) -> &[u8] {
        self.refresh_key_pair().public_certificate()
    }

    pub fn private_refresh_certificate(&self) -> &[u8] {
        self.refresh_key_pair().private_certificate()
    }
}
