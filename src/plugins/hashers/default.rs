//! # Component Documentation
//! ## [MemoryHasher](struct.MemoryHasher.html)
//! **Purpose**
//! ___
//! * Uses **DefaultHasher**
//! * Used as a component within [Components](../../../api/components/index.html)

use std::collections::hash_map::DefaultHasher;
use std::ops::{Deref, DerefMut};
use std::hash::Hasher;


pub struct MemoryHasher(DefaultHasher);


impl Hasher for MemoryHasher {
    fn finish(&self) -> u64 {
        self.0.finish()
    }
    fn write(&mut self, bytes: &[u8]) {
        self.0.write(bytes)
    }
}

impl Deref for MemoryHasher {
    type Target = DefaultHasher;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MemoryHasher {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}


impl Default for MemoryHasher {
    fn default() -> Self {
        MemoryHasher(DefaultHasher::default())
    }
}
