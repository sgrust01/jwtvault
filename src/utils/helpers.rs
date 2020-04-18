use std::fs::File;
use std::io::Read;
use std::{thread::sleep, time::Duration, time::Instant};
use std::hash::Hasher;

use rand::Rng;
use chrono::Utc;

use futures::Future;
use futures::executor::LocalPool;

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


/// Compute the expiry of the temporary refresh token
/// Default: 10 minutes
pub fn compute_temporary_authentication_token_expiry(since_epoch_in_seconds: Option<i64>, expiry_in_seconds: Option<i64>) -> i64 {
    let since_epoch_in_seconds = match since_epoch_in_seconds {
        Some(n) => n,
        None => Utc::now().timestamp()
    };

    match expiry_in_seconds {
        Some(n) => since_epoch_in_seconds + n,
        None => DEFAULT_TEMPORARY_AUTHENTICATION_EXPIRY_IN_SECONDS
    }
}

pub fn digest<H: Hasher, T: AsRef<[u8]>>(hasher: &mut H, payload: T) -> u64 {
    for i in payload.as_ref() {
        hasher.write_u8(*i);
    };
    hasher.finish()
}

pub fn block_thread(sleep_in_seconds: u64) -> u64 {
    let duration = Duration::from_secs(sleep_in_seconds);
    let now = Instant::now();
    sleep(duration);
    let result = Instant::now() - now;
    result.as_secs()
}


pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut pool = LocalPool::new();
    pool.run_until(f)
}

pub fn hash_password_with_argon<T: AsRef<str>>(password: T, secret_key: T) -> Result<String, ArgonError> {
    let mut hasher = ArgonHasher::default();
    let secret_key = secret_key.as_ref();
    hasher.with_password(password.as_ref())
        .with_secret_key(secret_key)
        .hash()
}

pub fn verify_user_password_with_argon<T: AsRef<str>>(password: T, secret_key: T, hash: T) -> Result<bool, ArgonError> {
    let mut verifier = ArgonVerifier::default();
    let secret_key = secret_key.as_ref();
    verifier.with_hash(hash.as_ref())
        .with_password(password.as_ref())
        .with_secret_key(secret_key)
        .verify()
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

    #[test]
    fn validate_argon_workflow_for_correct_workflow() {
        let certificate = CertificateManger::default();

        let secret_key = certificate.password_hashing_secret();
        let plain_password = "password";

        let hash = hash_password_with_argon(plain_password, &secret_key).unwrap();

        let result = verify_user_password_with_argon(plain_password, &secret_key, &hash).unwrap();
        assert!(result);
    }

    #[test]
    fn validate_argon_workflow_with_incorrect_password() {
        let secret_key = "some_super_secret";

        let plain_password = "password";
        let hash = hash_password_with_argon(plain_password, &secret_key).unwrap();

        let result = verify_user_password_with_argon(plain_password, &secret_key, &hash).unwrap();
        assert!(result);

        let plain_password = "wrong_password";
        let result = verify_user_password_with_argon(plain_password, &secret_key, &hash).unwrap();

        assert!(!result);
    }

    #[test]
    fn validate_argon_workflow_with_incorrect_secret() {
        let secret_key = "some_super_secret";

        let plain_password = "password";
        let hash = hash_password_with_argon(plain_password, &secret_key).unwrap();

        let result = verify_user_password_with_argon(plain_password, &secret_key, &hash).unwrap();
        assert!(result);

        let secret_key = "some_other_super_secret";
        let result = verify_user_password_with_argon(plain_password, &secret_key, &hash).unwrap();

        assert!(!result);
    }

    #[test]
    fn validate_argon_workflow_with_incorrect_hash() {
        let secret_key = "some_super_secret";

        let plain_password = "password";
        let hash = hash_password_with_argon(plain_password, &secret_key).unwrap();

        let result = verify_user_password_with_argon(plain_password, &secret_key, &hash).unwrap();
        assert!(result);

        let some_other_hash = hash_password_with_argon("some_other_password", &secret_key).unwrap();

        let result = verify_user_password_with_argon(plain_password, &secret_key, &some_other_hash).unwrap();

        assert!(!result);
    }

    #[test]
    fn validate_block_thread() {
        let sleep = 1;
        let result = block_thread(sleep);
        assert!(result >= sleep);
    }
}