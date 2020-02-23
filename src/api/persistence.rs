use crate::prelude::*;
use std::hash::Hasher;
use std::default::Default;


pub trait PersistenceHasher<H: Hasher + Default> {
    fn engine(&self) -> H {
        H::default()
    }
}

#[async_trait]
pub trait Persistence {
    async fn store(&mut self, key: u64, value: String);
    async fn load(&self, key: u64) -> Option<&String>;
    async fn remove(&mut self, key: u64) -> Option<String>;
}

