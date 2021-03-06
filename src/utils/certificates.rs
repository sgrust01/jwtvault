use crate::constants::DEFAULT_PASSWORD_HASHING_SECRET_PATH;
use crate::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateManger {
    public_authentication_certificate_path: String,
    private_authentication_certificate_path: String,
    public_refresh_certificate_path: String,
    private_refresh_certificate_path: String,
    password_hashing_secret_path: String,

    public_authentication_certificate: String,
    private_authentication_certificate: String,
    public_refresh_certificate: String,
    private_refresh_certificate: String,
    password_hashing_secret: String,
}

impl CertificateManger {
    pub fn new(public_authentication_certificate_path: String, private_authentication_certificate_path: String, public_refresh_certificate_path: String, private_refresh_certificate_path: String, password_hashing_secret_path: String) -> Self {
        let public_authentication_certificate = load_file_from_disk(public_authentication_certificate_path.as_str()).ok().unwrap();
        let private_authentication_certificate = load_file_from_disk(private_authentication_certificate_path.as_str()).ok().unwrap();
        let public_refresh_certificate = load_file_from_disk(public_refresh_certificate_path.as_str()).ok().unwrap();
        let private_refresh_certificate = load_file_from_disk(private_refresh_certificate_path.as_str()).ok().unwrap();
        let password_hashing_secret = load_file_from_disk(password_hashing_secret_path.as_str()).ok().unwrap();

        let public_authentication_certificate = String::from_utf8(public_authentication_certificate).unwrap();
        let private_authentication_certificate = String::from_utf8(private_authentication_certificate).unwrap();
        let public_refresh_certificate = String::from_utf8(public_refresh_certificate).unwrap();
        let private_refresh_certificate = String::from_utf8(private_refresh_certificate).unwrap();
        let password_hashing_secret = String::from_utf8(password_hashing_secret).unwrap();


        Self {
            public_authentication_certificate_path,
            private_authentication_certificate_path,
            public_refresh_certificate_path,
            private_refresh_certificate_path,
            password_hashing_secret_path,

            public_authentication_certificate,
            private_authentication_certificate,
            public_refresh_certificate,
            private_refresh_certificate,
            password_hashing_secret,
        }
    }
}

impl Default for CertificateManger {
    fn default() -> Self {
        Self::new(
            DEFAULT_PUBLIC_AUTHENTICATION_TOKEN_PATH.to_string(),
            DEFAULT_PRIVATE_AUTHENTICATION_TOKEN_PATH.to_string(),
            DEFAULT_PUBLIC_REFRESH_TOKEN_PATH.to_string(),
            DEFAULT_PRIVATE_REFRESH_TOKEN_PATH.to_string(),
            DEFAULT_PASSWORD_HASHING_SECRET_PATH.to_string(),
        )
    }
}

impl Keys for CertificateManger {
    fn public_authentication_certificate(&self) -> PublicKey {
        PublicKey::from(self.public_authentication_certificate.clone())
    }
    fn private_authentication_certificate(&self) -> PrivateKey {
        PrivateKey::from(self.private_authentication_certificate.clone())
    }
    fn public_refresh_certificate(&self) -> PublicKey {
        PublicKey::from(self.public_refresh_certificate.clone())
    }
    fn private_refresh_certificate(&self) -> PrivateKey {
        PrivateKey::from(self.private_refresh_certificate.clone())
    }
    fn password_hashing_secret(&self) -> PrivateKey {
        PrivateKey::from(self.password_hashing_secret.clone())
    }
}
#[derive(Clone)]
pub struct KeyPair {
    public_certificate: PublicKey,
    private_certificate: PrivateKey,
}

impl KeyPair {
    pub fn new(public_certificate: PublicKey, private_certificate: PrivateKey) -> Self {
        Self {
            public_certificate,
            private_certificate,
        }
    }
    pub fn public_certificate(&self) -> &PublicKey {
        &self.public_certificate
    }
    pub fn private_certificate(&self) -> &PrivateKey {
        &self.private_certificate
    }
}

#[derive(Clone)]
pub struct CertificateStore {
    authentication: KeyPair,
    refresh: KeyPair,
}

impl CertificateStore {
    pub fn new(authentication: KeyPair, refresh: KeyPair) -> Self {
        Self {
            authentication,
            refresh,
        }
    }
    pub fn authentication(&self) -> &KeyPair {
        &self.authentication
    }
    pub fn refresh(&self) -> &KeyPair {
        &self.refresh
    }
}


impl Store for CertificateStore {
    fn public_authentication_certificate(&self) -> &PublicKey {
        self.authentication().public_certificate()
    }
    fn private_authentication_certificate(&self) -> &PrivateKey {
        self.authentication().private_certificate()
    }
    fn public_refresh_certificate(&self) -> &PublicKey {
        self.refresh().public_certificate()
    }
    fn private_refresh_certificate(&self) -> &PrivateKey {
        self.refresh().private_certificate()
    }
}

impl<T: Keys> From<T> for CertificateStore {
    fn from(loader: T) -> Self {
        let authentication = KeyPair::new(
            loader.public_authentication_certificate().clone(),
            loader.private_authentication_certificate().clone(),
        );
        let refresh = KeyPair::new(
            loader.public_refresh_certificate().clone(),
            loader.private_refresh_certificate().clone(),
        );
        CertificateStore::new(authentication, refresh)
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        let manger = CertificateManger::default();
        CertificateStore::from(manger)
    }
}

