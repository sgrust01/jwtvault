//! # Components Documentation
//! ## [PersistenceHasher](trait.PersistenceHasher.html)
//! **Client implementation required** <br/><br/>
//! Specify the hashing algorithm to use <br/>
//!
//! Example with MemoryHasher
//! ```
//! use jwtvault::prelude::*;
//!
//! struct MyStruct(MemoryHasher);
//!
//! impl PersistenceHasher<MemoryHasher> for MyStruct {
//!     fn engine(&self) -> MemoryHasher {
//!         MemoryHasher::default()
//!     }
//! }
//!
//! ```
//!
//!
//! ## Example with [SeaHash](https://github.com/redox-os/tfs/tree/master/seahash)
//! First, depend on `seahash` in `Cargo.toml`:<br/><br/>
//! `use jwtvault::prelude::*;`<br/>
//! `use seahash::SeaHasher;`<br/>
//!
//! `struct MyStruct(SeaHasher);`<br/><br/>
//! `impl PersistenceHasher<SeaHasher> for MyStruct {`<br/>
//!     `fn engine(&mut self) -> &mut SeaHasher {`<br/>
//!         `&mut self.0`<br/>
//!     `}`<br/>
//!`}`<br/>
//!
//! ## Examples with [xxHash](https://github.com/shepmaster/twox-hash)
//! First, depend on `twox-hash` in `Cargo.toml`:<br/><br/>
//!
//! `use jwtvault::prelude::*;`<br/>
//! `use twox_hash::XxHash64;`<br/>
//!
//! `struct MyStruct(XxHash64);`<br/><br/>
//! `impl PersistenceHasher<XxHash64> for MyStruct {` <br/>
//! `    fn engine(&mut self) ->  &mut XxHash64 {` <br/>
//! `       &mut self.0`<br/>
//! `    }`<br/>
//!`}`<br/>
//!
//! ## [Persistence](trait.Persistence.html)
//! **Client implementation required** <br/><br/>
//! Used to save, retrieve and remove server side stored data <br/>
//! May or may-not be persistent across restarts <br/>
//! ## Example with In-Memory
//! **In-Memory: Not Presistant across restart**
//! ```
//! use jwtvault::prelude::*;
//! use std::collections::HashMap;
//!
//! struct MyStruct(HashMap<u64, String>);
//!
//! impl Persistence for MyStruct {
//!    fn store(&mut self, key: u64, value: String) {
//!        self.0.insert(key, value);
//!    }
//!    fn load(&self, key: u64) -> Option<&String> {
//!        self.0.get(&key)
//!    }
//!    fn remove(&mut self, key: u64) -> Option<String> {
//!        self.0.remove(&key)
//!    }
//!}
//! ```
//! ## Example with [RocksDB](https://github.com/rust-rocksdb/rust-rocksdb)
//! **Embedded DB: Presistant across restart, but not against crashes**
//!
//!
//! **$ echo "Coming Soon..."**
//!
//! ## Example with [Postgres](https://github.com/sfackler/rust-postgres)
//! **Central DB: Presistant across restart & crashes but requires DB lookuop**
//!
//! **$ echo "Coming Soon..."**
//!
//! ## [KeyStore](trait.KeyStore.html)
//!
//! **Client implementation required** <br/><br/>
//! Certificates maybe loaded from disk or any other source<br/>
//!
//! -------------------- <br/>
//! Two pairs: <br/>
//! -------------------- <br/>
//! * Authentication Key Pair (Public and Private) <br/>
//! * Refresh Key Pair (Public and Private) <br/>
//!
//! ## Example
//! **From Disk**
//!
//! Run script at the root of the crate<br/>
//!
//! `$./generate_certificates.sh` <br/>
//!
//!
//! ```
//! use jwtvault::prelude::*;
//!
//! struct MyStruct(KeyPairs);
//! impl MyStruct {
//!     pub fn new() -> Self{
//!         Self(KeyPairs::default())
//!     }
//! }
//! impl KeyStore for MyStruct {
//!     fn key_pairs(&self) -> &KeyPairs {
//!         &self.0
//!     }
//! }
//! ```


use std::hash::Hasher;

use crate::prelude::*;

/// ## Hasher Contract for hashing data for storage
/// **Client implementation required** <br/><br/>
/// Specify the hashing algorithm to use <br/>
/// ============= <br/>
/// Few Examples: <br/>
/// ============= <br/>
/// (With no preference and/or order)<br/>
/// * [SeaHash](https://github.com/redox-os/tfs/tree/master/seahash) <br/>
/// * [xxHash](https://github.com/shepmaster/twox-hash) <br/>
pub trait PersistenceHasher<T: Hasher> {
    /// Specify the engine to use<br>
    /// Examples <br/>
    /// `fn engine(&self) {
    ///     SeaHasher::new()
    /// }`
    fn engine(&self) -> T;
}

/// ## Persistence Contract for JWT
/// **Client implementation required** <br/>
/// Used to save, retrieve and remove server side stored data <br/>
/// May or may-not be persistent across restarts <br/>
/// ======== <br/>
/// Example: <br/>
/// ======== <br/>
/// * In memory: HashMap - See examples <br/>
/// * Embedded: RocksDB <br/>
/// * Centralized: Postgres <br/>
pub trait Persistence {
    /// Store the value against the key derived from [PersistenceHasher](trait.PersistenceHasher.html)
    fn store(&mut self, key: u64, value: String);
    /// Loads the value against the key derived from [PersistenceHasher](trait.PersistenceHasher.html)
    fn load(&self, key: u64) -> Option<&String>;
    /// Remove the value against the key derived from [PersistenceHasher](trait.PersistenceHasher.html)
    fn remove(&mut self, key: u64) -> Option<String>;
}

/// ## Store for the certificates
/// **Client implementation required** <br/>
/// The Certificates maybe loaded from on disk or any other source<br/><br/>
/// -------------------- <br/>
/// Two pairs: <br/>
/// -------------------- <br/>
/// * Authentication Key Pair (Public and Private) <br/>
/// * Refresh Key Pair (Public and Private) <br/>

pub trait KeyStore {
    /// Key Pairs
    fn key_pairs(&self) -> &KeyPairs;
}
