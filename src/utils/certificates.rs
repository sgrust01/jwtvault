use std::fs::File;
use std::io::Read;

use failure::Error;
use crate::prelude::*;


#[derive(Debug, Clone, PartialEq)]
pub struct KeyVault<'a> {
    public_authentication_key: PublicKey<'a>,
    private_authentication_key: PrivateKey,
    public_refresh_key: PublicKey<'a>,
    private_refresh_key: PrivateKey,
}


impl<'a> SigningKeys for KeyVault<'a> {
    fn public_authentication_certificate(&self) -> &PublicKey {
        &self.public_authentication_key
    }
    fn private_authentication_certificate(&self) -> &PrivateKey {
        &self.private_authentication_key
    }
    fn public_refresh_certificate(&self) -> &PublicKey {
        &self.public_refresh_key
    }
    fn private_refresh_certificate(&self) -> &PrivateKey {
        &self.private_refresh_key
    }
}

#[derive(Debug, Clone)]
pub struct KeyPaths {
    public_authentication_path: String,
    private_authentication_path: String,
    public_refresh_path: String,
    private_refresh_path: String,
}

impl KeyPaths {
    fn public_authentication_path(&self) -> &str {
        self.public_authentication_path.as_str()
    }
    fn private_authentication_path(&self) -> &str {
        self.private_authentication_path.as_str()
    }
    fn public_refresh_path(&self) -> &str {
        self.public_refresh_path.as_str()
    }
    fn private_refresh_path(&self) -> &str {
        self.private_refresh_path.as_str()
    }
}

#[derive(Debug, Clone)]
pub struct Keys {
    public_authentication: Vec<u8>,
    private_authentication: Vec<u8>,
    public_refresh: Vec<u8>,
    private_refresh: Vec<u8>,
}


#[derive(Debug, Clone)]
pub struct RSAKeys {
    public_authentication: String,
    private_authentication: String,
    public_refresh: String,
    private_refresh: String,
}

impl From<Keys> for RSAKeys {
    fn from(keys: Keys) -> Self {
        let public_authentication = String::from_utf8_lossy(keys.public_authentication()).to_string();
        let private_authentication = String::from_utf8_lossy(keys.private_authentication()).to_string();
        let public_refresh = String::from_utf8_lossy(keys.public_refresh()).to_string();
        let private_refresh = String::from_utf8_lossy(keys.private_refresh()).to_string();
        Self {
            public_authentication,
            private_authentication,
            public_refresh,
            private_refresh,
        }
    }
}


impl Keys {
    pub fn public_authentication(&self) -> &[u8] {
        self.public_authentication.as_slice()
    }
    pub fn private_authentication(&self) -> &[u8] {
        self.private_authentication.as_slice()
    }
    pub fn public_refresh(&self) -> &[u8] {
        self.public_refresh.as_slice()
    }
    pub fn private_refresh(&self) -> &[u8] {
        self.private_refresh.as_slice()
    }
}

impl Keys {
    pub fn new(public_authentication: Vec<u8>, private_authentication: Vec<u8>, public_refresh: Vec<u8>, private_refresh: Vec<u8>) -> Self {
        Self {
            public_authentication,
            private_authentication,
            public_refresh,
            private_refresh,
        }
    }
}


impl Default for KeyPaths {
    fn default() -> Self {
        let public_authentication_path = DEFAULT_PUBLIC_AUTHENTICATION_TOKEN_PATH.to_string();
        let private_authentication_path = DEFAULT_PRIVATE_AUTHENTICATION_TOKEN_PATH.to_string();
        let public_refresh_path = DEFAULT_PUBLIC_REFRESH_TOKEN_PATH.to_string();
        let private_refresh_path = DEFAULT_PRIVATE_REFRESH_TOKEN_PATH.to_string();
        Self::new(
            public_authentication_path,
            private_authentication_path,
            public_refresh_path,
            private_refresh_path,
        )
    }
}


impl Default for Keys {
    fn default() -> Self {
        let paths = KeyPaths::default();
        let disk = FromDisk;
        let public_authentication = disk.load_public_certificate(paths.public_authentication_path()).ok().unwrap();
        let private_authentication = disk.load_private_certificate(paths.private_authentication_path()).ok().unwrap();
        let public_refresh = disk.load_public_certificate(paths.public_refresh_path()).ok().unwrap();
        let private_refresh = disk.load_private_certificate(paths.private_refresh_path()).ok().unwrap();
        Self::new(
            public_authentication,
            private_authentication,
            public_refresh,
            private_refresh,
        )
    }
}


impl Default for RSAKeys {
    fn default() -> Self {
        RSAKeys::from(Keys::default())
    }
}

impl RSAKeys {
    pub fn public_authentication(&self) -> &str {
        self.public_authentication.as_str()
    }
    pub fn private_authentication(&self) -> &str {
        self.private_authentication.as_str()
    }
    pub fn public_refresh(&self) -> &str {
        self.public_refresh.as_str()
    }
    pub fn private_refresh(&self) -> &str {
        self.private_refresh.as_str()
    }
}


impl KeyPaths {
    pub fn new(public_authentication_path: String, private_authentication_path: String, public_refresh_path: String, private_refresh_path: String) -> Self {
        Self {
            public_authentication_path,
            private_authentication_path,
            public_refresh_path,
            private_refresh_path,

        }
    }
}

impl<'a> KeyVault<'a> {
    pub fn new(public_authentication_payload: &'a str, private_authentication_payload: &'a str, public_refresh_payload: &'a str, private_refresh_payload: &'a str) -> Self {
        let public_authentication_key = PublicKey::new(public_authentication_payload);
        let private_authentication_key = PrivateKey::new(private_authentication_payload);
        let public_refresh_key = PublicKey::new(public_refresh_payload);
        let private_refresh_key = PrivateKey::new(private_refresh_payload);
        Self {
            public_authentication_key,
            private_authentication_key,
            public_refresh_key,
            private_refresh_key,
        }
    }
}


#[derive(Clone, PartialEq, Debug)]
pub struct FromDisk;

impl CertificateLoader<&str> for FromDisk {
    fn load_public_certificate(&self, public_certificate_path: &str) -> Result<Vec<u8>, Error>
    {
        let file: Result<File, Error> = File::open(public_certificate_path).map_err(|e| {
            BadFile(format!("Public certificate {} bad/missing", public_certificate_path), e.to_string()).into()
        });
        let mut file = file?;

        let mut data = Vec::new();
        let result: Result<usize, Error> = file.read_to_end(&mut data).map_err(|e| {
            BadFile(format!("Unable to read public certificate {}", public_certificate_path), e.to_string()).into()
        });
        result?;
        Ok(data)
    }
    fn load_private_certificate(&self, private_certificate_path: &str) -> Result<Vec<u8>, Error>
    {
        let file: Result<File, Error> = File::open(private_certificate_path).map_err(|e| {
            BadFile(format!("Private certificate {} bad/missing", private_certificate_path), e.to_string()).into()
        });
        let mut file = file?;
        let mut data = Vec::new();
        let result: Result<usize, Error> = file.read_to_end(&mut data).map_err(|e| {
            BadFile(format!("Unable to read file {}", private_certificate_path), e.to_string()).into()
        });
        result?;
        Ok(data)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::fs;
    use jsonwebtoken::{EncodingKey, DecodingKey};
    use std::ops::Deref;

    fn tail(path: &str) -> String {
        let elems: Vec<_> = path.split("/").collect();
        let z: &str = elems.get(1).unwrap();
        z.to_string()
    }

    #[test]
    fn missing_certificates() {
        let disk = FromDisk;
        let result = disk.load_private_certificate("nofile");
        assert!(result.is_err());
        let result = disk.load_public_certificate("nofile");
        assert!(result.is_err());
    }


    #[test]
    fn validate_try_from_on_disk() {
        let store = "teststore";
        let _ = if cfg!(target_os = "linux") {
            Command::new("sh")
                .arg("generate_certificates.sh")
                .arg(store)
                .output()
                .expect("failed to execute process");
        };
//        else {
//            Command::new("cmd")
//                .args(&["./generate_certificates.sh", store])
//                .output()
//                .expect("failed to execute process")
//        };
//        let loader = FromDisk;

        let public_authentication_certificate_path = format!("{}/{}", store, tail(DEFAULT_PUBLIC_AUTHENTICATION_TOKEN_PATH));
        let private_authentication_certificate_path = format!("{}/{}", store, tail(DEFAULT_PRIVATE_AUTHENTICATION_TOKEN_PATH));
        let public_refresh_certificate_path = format!("{}/{}", store, tail(DEFAULT_PUBLIC_REFRESH_TOKEN_PATH));
        let private_refresh_certificate_path = format!("{}/{}", store, tail(DEFAULT_PRIVATE_REFRESH_TOKEN_PATH));

        let path = KeyPaths::new(
            public_authentication_certificate_path,
            private_authentication_certificate_path,
            public_refresh_certificate_path,
            private_refresh_certificate_path,
        );

        let disk = FromDisk;
        let public_authentication = disk.load_public_certificate(path.public_authentication_path()).ok().unwrap();
        let private_authentication = disk.load_private_certificate(path.private_authentication_path()).ok().unwrap();
        let public_refresh = disk.load_public_certificate(path.public_refresh_path()).ok().unwrap();
        let private_refresh = disk.load_private_certificate(path.private_refresh_path()).ok().unwrap();

        let keys = Keys::new(
            public_authentication.clone(),
            private_authentication.clone(),
            public_refresh.clone(),
            private_refresh.clone());

        let keys = RSAKeys::from(keys);

        assert_eq!(keys.public_authentication().as_bytes(), public_authentication.as_slice());
        assert_eq!(keys.private_authentication().as_bytes(), private_authentication.as_slice());
        assert_eq!(keys.public_refresh().as_bytes(), public_refresh.as_slice());
        assert_eq!(keys.private_refresh().as_bytes(), private_refresh.as_slice());

        fs::remove_dir_all(store).unwrap();
    }

    #[test]
    fn validate_default_key_vault() {
        let keys = Keys::default();
        let disk = FromDisk;


        let public_authentication_payload = String::from_utf8_lossy(keys.public_authentication()).to_string();
        let private_authentication_payload = String::from_utf8_lossy(keys.private_authentication()).to_string();
        let public_refresh_payload = String::from_utf8_lossy(keys.public_refresh()).to_string();
        let private_refresh_payload = String::from_utf8_lossy(keys.private_refresh()).to_string();


        let vault = KeyVault::new(
            public_authentication_payload.as_str(),
            private_authentication_payload.as_str(),
            public_refresh_payload.as_str(),
            private_refresh_payload.as_str(),
        );


        let public_authentication_payload = disk.load_public_certificate(DEFAULT_PUBLIC_AUTHENTICATION_TOKEN_PATH).ok().unwrap();
        let public_authentication_payload = String::from_utf8_lossy(public_authentication_payload.as_slice()).to_string();
        let expected = DecodingKey::from_rsa_pem(public_authentication_payload.as_bytes()).unwrap();

        let computed = vault.public_authentication_certificate();
        assert_eq!(&expected, computed.deref());

        let private_authentication_payload = disk.load_private_certificate(DEFAULT_PRIVATE_AUTHENTICATION_TOKEN_PATH).ok().unwrap();
        let private_authentication_payload = String::from_utf8_lossy(private_authentication_payload.as_slice()).to_string();
        let expected = EncodingKey::from_rsa_pem(private_authentication_payload.as_bytes()).unwrap();

        let computed = vault.private_authentication_certificate();
        assert_eq!(&expected, computed.deref());


        let public_refresh_payload = disk.load_public_certificate(DEFAULT_PUBLIC_REFRESH_TOKEN_PATH).ok().unwrap();
        let public_refresh_payload = String::from_utf8_lossy(public_refresh_payload.as_slice()).to_string();
        let expected = DecodingKey::from_rsa_pem(public_refresh_payload.as_bytes()).unwrap();

        let computed = vault.public_refresh_certificate();
        assert_eq!(&expected, computed.deref());


        let private_refresh_payload = disk.load_private_certificate(DEFAULT_PRIVATE_REFRESH_TOKEN_PATH).ok().unwrap();
        let private_refresh_payload = String::from_utf8_lossy(private_refresh_payload.as_slice()).to_string();
        let expected = EncodingKey::from_rsa_pem(private_refresh_payload.as_bytes()).unwrap();

        let computed = vault.private_refresh_certificate();
        assert_eq!(&expected, computed.deref());
    }
}