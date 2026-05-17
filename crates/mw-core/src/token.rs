//! Client-token generation + mysql_native_password verification.
//!
//! Tokens are 32 random bytes printed as 43 base64url-ish chars
//! (alphabet [A-Za-z0-9_-]). High-entropy by construction, so we store
//! SHA1(SHA1(token)) — exactly what mysql_native_password needs server-side —
//! and skip a key-stretching KDF that would buy nothing.

use rand::{rngs::OsRng, RngCore};
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::secret::SecretStr;

const TOKEN_RAND_BYTES: usize = 32;
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// Generate a fresh client token. ~192 bits of entropy.
pub fn generate_token() -> SecretStr {
    let mut raw = [0u8; TOKEN_RAND_BYTES];
    OsRng.fill_bytes(&mut raw);
    let mut s = String::with_capacity(TOKEN_RAND_BYTES * 4 / 3 + 1);
    // Base64-url-ish without padding. Process 3 input bytes -> 4 chars; trailing handled.
    let mut i = 0;
    while i + 3 <= raw.len() {
        let n = ((raw[i] as u32) << 16) | ((raw[i + 1] as u32) << 8) | raw[i + 2] as u32;
        s.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        s.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        s.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        s.push(ALPHABET[(n & 0x3F) as usize] as char);
        i += 3;
    }
    match raw.len() - i {
        0 => {}
        1 => {
            let n = (raw[i] as u32) << 16;
            s.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            s.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        }
        2 => {
            let n = ((raw[i] as u32) << 16) | ((raw[i + 1] as u32) << 8);
            s.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            s.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            s.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        }
        _ => unreachable!(),
    }
    SecretStr::new(s)
}

/// SHA1(SHA1(password)). Server-side verification material for
/// mysql_native_password.
pub fn double_sha1(password: &[u8]) -> [u8; 20] {
    let h1 = Sha1::digest(password);
    let h2 = Sha1::digest(h1);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h2);
    out
}

/// Verify a `mysql_native_password` client response.
///
/// Protocol: client_response = SHA1(password) XOR SHA1(scramble || SHA1(SHA1(password)))
/// Server has the right side and the scramble; reconstruct SHA1(password) from the XOR,
/// then re-hash and compare against the stored double-SHA1.
pub fn verify_native_response(
    scramble: &[u8; 20],
    client_response: &[u8],
    stored_double_sha1: &[u8; 20],
) -> bool {
    if client_response.len() != 20 {
        return false;
    }
    let mut hasher = Sha1::new();
    hasher.update(scramble);
    hasher.update(stored_double_sha1);
    let inner = hasher.finalize(); // SHA1(scramble || SHA1(SHA1(pw)))

    let mut recovered_sha1_pw = [0u8; 20];
    for i in 0..20 {
        recovered_sha1_pw[i] = client_response[i] ^ inner[i];
    }
    // recovered_sha1_pw is SHA1(token); replayable against a native-password
    // server, so don't leave it on the stack after use.
    let recomputed = Sha1::digest(recovered_sha1_pw);
    recovered_sha1_pw.zeroize();
    recomputed.as_slice().ct_eq(stored_double_sha1).into()
}

/// SHA-256(token). Server-side verification material for the Postgres
/// cleartext-password path: the proxy stores this and compares it against
/// SHA-256 of the password the client sends in a `PasswordMessage`, so it
/// never holds the token itself (mirrors [`double_sha1`] for native_password).
pub fn sha256(token: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(token);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

/// Verify a Postgres cleartext `PasswordMessage`. Constant-time.
pub fn verify_pg_cleartext(presented: &[u8], stored_sha256: &[u8; 32]) -> bool {
    sha256(presented).ct_eq(stored_sha256).into()
}

/// Compute the response a client would send. Useful for tests.
pub fn native_response(password: &[u8], scramble: &[u8; 20]) -> [u8; 20] {
    let sha1_pw = Sha1::digest(password);
    let sha1_sha1_pw = Sha1::digest(sha1_pw);
    let mut hasher = Sha1::new();
    hasher.update(scramble);
    hasher.update(sha1_sha1_pw);
    let inner = hasher.finalize();
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = sha1_pw[i] ^ inner[i];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_has_expected_shape() {
        let t = generate_token();
        let s = t.expose();
        assert!(s.len() >= 40 && s.len() <= 48);
        for c in s.chars() {
            assert!(c.is_ascii_alphanumeric() || c == '_' || c == '-', "char {c:?}");
        }
    }

    #[test]
    fn generated_tokens_are_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn native_response_round_trip() {
        let pw = b"hunter2-secure-token-9f7a1d";
        let scramble = [0xA5u8; 20];
        let stored = double_sha1(pw);
        let resp = native_response(pw, &scramble);
        assert!(verify_native_response(&scramble, &resp, &stored));
    }

    #[test]
    fn wrong_token_rejected() {
        let scramble = [0x33u8; 20];
        let stored = double_sha1(b"correct-token");
        let resp = native_response(b"wrong-token", &scramble);
        assert!(!verify_native_response(&scramble, &resp, &stored));
    }

    #[test]
    fn wrong_scramble_rejected() {
        let pw = b"tk";
        let stored = double_sha1(pw);
        let resp = native_response(pw, &[0x11u8; 20]);
        assert!(!verify_native_response(&[0x22u8; 20], &resp, &stored));
    }

    #[test]
    fn pg_cleartext_round_trip() {
        let tok = b"some-high-entropy-token-abc123";
        let stored = sha256(tok);
        assert!(verify_pg_cleartext(tok, &stored));
        assert!(!verify_pg_cleartext(b"wrong-token", &stored));
        assert!(!verify_pg_cleartext(b"", &stored));
    }

    #[test]
    fn malformed_response_rejected() {
        let stored = double_sha1(b"tk");
        assert!(!verify_native_response(&[0u8; 20], &[], &stored));
        assert!(!verify_native_response(&[0u8; 20], &[0u8; 19], &stored));
        assert!(!verify_native_response(&[0u8; 20], &[0u8; 21], &stored));
    }
}
