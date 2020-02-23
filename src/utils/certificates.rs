use crate::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateManger {
    public_authentication_certificate_path: String,
    private_authentication_certificate_path: String,
    public_refresh_certificate_path: String,
    private_refresh_certificate_path: String,

    public_authentication_certificate: String,
    private_authentication_certificate: String,
    public_refresh_certificate: String,
    private_refresh_certificate: String,
}

impl CertificateManger {
    pub fn new(public_authentication_certificate_path: String, private_authentication_certificate_path: String, public_refresh_certificate_path: String, private_refresh_certificate_path: String) -> Self {
        let public_authentication_certificate = load_file_from_disk(public_authentication_certificate_path.as_str()).ok().unwrap();
        let private_authentication_certificate = load_file_from_disk(private_authentication_certificate_path.as_str()).ok().unwrap();
        let public_refresh_certificate = load_file_from_disk(public_refresh_certificate_path.as_str()).ok().unwrap();
        let private_refresh_certificate = load_file_from_disk(private_refresh_certificate_path.as_str()).ok().unwrap();

        let public_authentication_certificate = String::from_utf8(public_authentication_certificate).unwrap();
        let private_authentication_certificate = String::from_utf8(private_authentication_certificate).unwrap();
        let public_refresh_certificate = String::from_utf8(public_refresh_certificate).unwrap();
        let private_refresh_certificate = String::from_utf8(private_refresh_certificate).unwrap();


        Self {
            public_authentication_certificate_path,
            private_authentication_certificate_path,
            public_refresh_certificate_path,
            private_refresh_certificate_path,

            public_authentication_certificate,
            private_authentication_certificate,
            public_refresh_certificate,
            private_refresh_certificate,
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
}
