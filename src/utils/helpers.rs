/// Module
use rand::Rng;
use chrono::Utc;

use crate::prelude::*;

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


#[cfg(test)]
mod tests {
    use super::*;

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

}