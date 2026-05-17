//! Minimal redacted-secret newtypes. Local to this crate so we can pick our
//! serde shape and Debug behaviour without depending on `secrecy`'s marker
//! traits.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned secret string. Serializes as a plain string (so AEAD-sealed config
/// is the only thing that ever touches disk in cleartext). Debug prints a
/// fixed redacted marker.
///
/// `Clone` is intentional (the config is cloned in a few places) but is a
/// footgun: each clone is an independent heap allocation that only scrubs on
/// its own `Drop`. Every clone widens the window where plaintext sits in
/// memory. Prefer borrowing `expose()`; clone only when an owned copy must
/// outlive the source, and let it drop as soon as possible.
#[derive(Clone, Default)]
pub struct SecretStr(String);

impl SecretStr {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn expose(&self) -> &str { &self.0 }
}

impl std::fmt::Debug for SecretStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretStr(<redacted>)")
    }
}

impl Drop for SecretStr {
    fn drop(&mut self) { self.0.zeroize(); }
}

impl Serialize for SecretStr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretStr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(SecretStr(String::deserialize(d)?))
    }
}

impl From<String> for SecretStr { fn from(s: String) -> Self { Self(s) } }
impl From<&str> for SecretStr { fn from(s: &str) -> Self { Self(s.to_string()) } }

/// Owned secret byte sequence (e.g. SSH key PEM). Serializes as bytes.
#[derive(Clone, Default, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(b: impl Into<Vec<u8>>) -> Self { Self(b.into()) }
    pub fn expose(&self) -> &[u8] { &self.0 }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<redacted, {} bytes>)", self.0.len())
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // ciborium emits bytes as a CBOR byte string; serde_bytes-style helper:
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("byte sequence")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(b) = seq.next_element::<u8>()? { out.push(b); }
                Ok(out)
            }
        }
        Ok(SecretBytes(d.deserialize_byte_buf(V)?))
    }
}
