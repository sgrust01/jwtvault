use std::fs::File;
use failure::Error;
use std::io::Read;
use rand::Rng;
use chrono::Utc;
use std::hash::Hasher;
use crate::prelude::*;

pub fn load_file_from_disk(path: &str) -> Result<Vec<u8>, Error>
{
    let file: Result<File, Error> = File::open(path).map_err(|e| {
        CertificateError::BadFile(format!("Path: {} bad/missing", path), e.to_string()).into()
    });
    let mut file = file?;

    let mut data = Vec::new();
    let result: Result<usize, Error> = file.read_to_end(&mut data).map_err(|e| {
        CertificateError::FileReadError(format!("Unable to read path {}", path), e.to_string()).into()
    });
    result?;
    Ok(data)
}



/// Compute time since epoch in seconds
pub fn compute_timestamp_in_seconds() -> i64 {
    let now = Utc::now();
    now.timestamp()
}

/// Compute the expiry of the refresh token
/// Default: 15 minutes
pub fn compute_authentication_token_expiry(since_epoch_in_seconds: Option<i64>, expiry_in_seconds: Option<i64>) -> i64 {
    let since_epoch_in_seconds = match since_epoch_in_seconds {
        Some(n) => n,
        None => Utc::now().timestamp()
    };


    match expiry_in_seconds {
        Some(n) => since_epoch_in_seconds + n,
        None => {
            //Handle: Thundering herd problem
            let mut rng = rand::thread_rng();
            since_epoch_in_seconds + rng.gen_range(DEFAULT_AUTHENTICATION_MIN_EXPIRY_IN_SECONDS, DEFAULT_AUTHENTICATION_MAX_EXPIRY_IN_SECONDS)
        }
    }
}

/// Compute the expiry of the refresh token
/// Default: Never expire
pub fn compute_refresh_token_expiry(since_epoch_in_seconds: Option<i64>, expiry_in_seconds: Option<i64>) -> i64 {
    let since_epoch_in_seconds = match since_epoch_in_seconds {
        Some(n) => n,
        None => Utc::now().timestamp()
    };

    match expiry_in_seconds {
        Some(n) => since_epoch_in_seconds + n,
        None => DEFAULT_REFRESH_WITH_NO_EXPIRY
    }
}

pub fn digest<H: Hasher, T: AsRef<[u8]>>(hasher: &mut H, payload: T) -> u64 {
    for i in payload.as_ref() {
        hasher.write_u8(*i);
    };
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    #[test]
    fn validate_compute_authentication_token_expiry() {
        let iat = compute_timestamp_in_seconds();
        let exp = compute_authentication_token_expiry(None, None);
        assert!(exp > iat);
    }

    #[test]
    fn validate_compute_refresh_token_expiry() {
        let iat = compute_timestamp_in_seconds();
        let exp = compute_refresh_token_expiry(None, None);
        assert!(exp > iat);
    }

    #[test]
    fn validate_digest() {
        let mut hasher = DefaultHasher::default();
        let data = "data";
        let run1 = digest(&mut hasher, data.as_bytes());
        let mut hasher = DefaultHasher::default();
        let data = "data";
        let run2 = digest(&mut hasher, data.as_bytes());
        assert_eq!(run1, run2);

        let mut hasher = DefaultHasher::default();
        let data = "data";
        let run3 = digest(&mut hasher, data.as_bytes());
        assert_eq!(run1, run3);

        let mut hasher = DefaultHasher::default();
        let data = "data";
        let run4 = digest(&mut hasher, data.as_bytes());
        assert_eq!(run1, run4);
    }
}