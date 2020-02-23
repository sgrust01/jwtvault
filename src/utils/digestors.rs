use std::hash::Hasher;

pub fn resolve_refresh_reference<T: AsRef<[u8]>, E: Hasher + Default>(payload: T) -> u64 {
    let mut engine = E::default();
    for i in [0u8, 1u8].iter() {
        engine.write_u8(*i);
    };

    for i in payload.as_ref() {
        engine.write_u8(*i);
    };
    engine.finish()
}

pub fn resolve_authentication_reference<T: AsRef<[u8]>, E: Hasher + Default>(payload: T) -> u64 {
    let mut engine = E::default();
    for i in [1u8, 0u8].iter() {
        engine.write_u8(*i);
    };
    for i in payload.as_ref() {
        engine.write_u8(*i);
    };
    engine.finish()
}

pub fn digest<T: AsRef<[u8]>, E: Hasher + Default>(payload: T) -> u64 {
    let mut engine = E::default();
    for i in payload.as_ref() {
        engine.write_u8(*i);
    };
    engine.finish()
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    #[test]
    fn test_resolve_refresh_reference() {
        let run1 = resolve_refresh_reference::<_, DefaultHasher>("data");
        let run2 = resolve_refresh_reference::<_, DefaultHasher>("data");
        let run3 = resolve_refresh_reference::<_, DefaultHasher>("data");
        assert_eq!(run1, run2);
        assert_eq!(run1, run3);
    }

    #[test]
    fn test_resolve_authentication_reference() {
        let run1 = resolve_authentication_reference::<_, DefaultHasher>("data");
        let run2 = resolve_authentication_reference::<_, DefaultHasher>("data");
        let run3 = resolve_authentication_reference::<_, DefaultHasher>("data");
        assert_eq!(run1, run2);
        assert_eq!(run1, run3);
    }

    #[test]
    fn test_digest() {
        let run1 = digest::<_, DefaultHasher>("data");
        let run2 = digest::<_, DefaultHasher>("data");
        let run3 = digest::<_, DefaultHasher>("data");
        assert_eq!(run1, run2);
        assert_eq!(run1, run3);
    }
}