pub use failure::Error;
pub use futures::executor::block_on;
pub use async_trait::async_trait;

pub use crate::api::certificates::{Store, Keys, PublicKey, PrivateKey};
pub use crate::api::session::{Session, Token};
pub use crate::api::persistence::{Persistence, PersistenceHasher};
pub use crate::api::vault::{UserIdentity, UserAuthentication, Workflow, resolve_session_from_client_authentication_token, resolve_session_from_client_refresh_token, continue_login, continue_renew, continue_logout, continue_revoke};

pub use crate::errors::{CertificateError, TokenErrors, LoginFailed};

pub use crate::utils::certificates::CertificateManger;
pub use crate::utils::vault::DefaultVault;
pub use crate::utils::helpers::{load_file_from_disk, compute_timestamp_in_seconds, compute_refresh_token_expiry, compute_authentication_token_expiry};
pub use crate::utils::token::{ClientClaims, ServerClaims, encode_client_token, decode_client_token, prepare_client_refresh_token, prepare_server_token, prepare_user_authentication_token, encode_server_token, decode_server_token};
pub use crate::utils::digestors::{resolve_refresh_reference, resolve_authentication_reference, digest};

pub use crate::constants::{DEFAULT_AUTHENTICATION_MAX_EXPIRY_IN_SECONDS,
                           DEFAULT_AUTHENTICATION_MIN_EXPIRY_IN_SECONDS,
                           DEFAULT_REFRESH_WITH_NO_EXPIRY,
                           DEFAULT_PUBLIC_AUTHENTICATION_TOKEN_PATH,
                           DEFAULT_PRIVATE_AUTHENTICATION_TOKEN_PATH,
                           DEFAULT_PUBLIC_REFRESH_TOKEN_PATH,
                           DEFAULT_PRIVATE_REFRESH_TOKEN_PATH};