use std::fs::File;
use std::io::Read;
use std::convert::TryFrom;

use failure::Error;
use crate::prelude::*;


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


impl TryFrom<(FromDisk, &str, &str, &str, &str)> for KeyPairs {
    type Error = Error;

    fn try_from((loader, public_authentication_certificate_path, private_authentication_certificate_path, public_refresh_certificate_path, private_refresh_certificate_path): (FromDisk, &str, &str, &str, &str)) -> Result<Self, Self::Error> {
        let public_certificate = loader.load_public_certificate(
            public_authentication_certificate_path
        )?;
        let private_certificate = loader.load_private_certificate(
            private_authentication_certificate_path
        )?;
        let authentication = AuthenticationKeyPair::new(public_certificate, private_certificate);

        let public_certificate = loader.load_public_certificate(
            public_refresh_certificate_path
        )?;
        let private_certificate = loader.load_private_certificate(
            private_refresh_certificate_path
        )?;
        let refresh = RefreshKeyPair::new(public_certificate, private_certificate);

        Ok(KeyPairs::new(authentication, refresh))
    }
}

/// This will panic is the default keys are not present
/// Run ./generate.sh under store
impl Default for KeyPairs {
    fn default() -> Self {
        let disk = FromDisk;

        let public_certificate_path = DEFAULT_PUBLIC_AUTHENTICATION_TOKEN_PATH;
        let private_certificate_path = DEFAULT_PRIVATE_AUTHENTICATION_TOKEN_PATH;

        let public_certificate = disk.load_public_certificate(public_certificate_path).ok().unwrap();
        let private_certificate = disk.load_private_certificate(private_certificate_path).ok().unwrap();

        let authentication = AuthenticationKeyPair::new(public_certificate, private_certificate);

        let public_certificate_path = DEFAULT_PUBLIC_REFRESH_TOKEN_PATH;
        let private_certificate_path = DEFAULT_PRIVATE_REFRESH_TOKEN_PATH;

        let public_certificate = disk.load_public_certificate(public_certificate_path).ok().unwrap();
        let private_certificate = disk.load_private_certificate(private_certificate_path).ok().unwrap();

        let refresh = RefreshKeyPair::new(public_certificate, private_certificate);

        Self::new(authentication, refresh)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::convert::TryFrom;
    use std::fs;

    fn tail(path: &str) -> String {
        let elems: Vec<_> = path.split("/").collect();
        let z: &str = elems.get(1).unwrap();
        z.to_string()
    }

    #[test]
    fn validate_round_trip() {
        let keys = KeyPairs::default();
        let user = "user";
        let _ref = 1u64;
        let token = encode_client_token(
            keys.private_authentication_certificate(),
            user.as_bytes(),
            None,
            _ref,
            None,
            None,
            None
        );
        let token = token.ok().unwrap();
        let computed = decode_client_token(
            keys.public_authentication_certificate(),
            token.as_ref()
        );
        let computed = computed.ok().unwrap();
        assert_eq!(computed.reference(), _ref);
        assert_eq!(computed.sub().as_slice(), user.as_bytes());
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
        let loader = FromDisk;

        let public_authentication_certificate_path = format!("{}/{}", store, tail(DEFAULT_PUBLIC_AUTHENTICATION_TOKEN_PATH));
        let private_authentication_certificate_path = format!("{}/{}", store, tail(DEFAULT_PRIVATE_AUTHENTICATION_TOKEN_PATH));
        let public_refresh_certificate_path = format!("{}/{}", store, tail(DEFAULT_PUBLIC_REFRESH_TOKEN_PATH));
        let private_refresh_certificate_path = format!("{}/{}", store, tail(DEFAULT_PRIVATE_REFRESH_TOKEN_PATH));

        let key: Result<KeyPairs, Error> = TryFrom::try_from(
            (
                loader,
                public_authentication_certificate_path.as_str(),
                private_authentication_certificate_path.as_str(),
                public_refresh_certificate_path.as_str(),
                private_refresh_certificate_path.as_str())
        );
        assert!(key.is_ok());
        fs::remove_dir_all(store).unwrap();
    }
}