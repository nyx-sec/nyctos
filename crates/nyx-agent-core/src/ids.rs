//! Small helpers for minting persisted-record identifiers.

use rand::RngCore;

/// Eight hex characters (4 bytes) of cryptographic randomness, suitable
/// as a per-insert disambiguator on otherwise-deterministic record ids
/// (payload / spec / chain / candidate). Two replays of the same task
/// landing in the same millisecond now collide with probability ~2^-32
/// instead of certainty.
pub fn short_token() -> String {
    let mut buf = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::short_token;

    #[test]
    fn short_token_is_eight_hex_chars() {
        let t = short_token();
        assert_eq!(t.len(), 8);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_token_is_not_constant() {
        let a = short_token();
        let b = short_token();
        assert_ne!(a, b, "two short_token calls should differ with overwhelming probability");
    }
}
