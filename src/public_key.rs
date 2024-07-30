use crate::{InternalError, SecretKey};

use arrayref::array_ref;
use ed25519_dalek::SigningKey;
use failure::Error;
use std::convert::{TryFrom, TryInto};

/// [`VerifyingKey`](struct.VerifyingKey.html) length in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 64;

/// Concatenation of X25519 public key (first 32 bytes) and Ed25519 public key (last 32 bytes).
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// Ed25519 public key (last 32 bytes)
    pub ed: ed25519_dalek::VerifyingKey,
    /// X25519 public key (first 32 bytes)
    pub dh: x25519_dalek::PublicKey,
}

/// Derive public key from secret key.
impl From<&SecretKey> for VerifyingKey {
    fn from(secret_key: &SecretKey) -> Self {
        // Create a SigningKey (SecretKey) from the bytes
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key.ed);

        Self {
            ed: signing_key.verifying_key(),
            dh: x25519_dalek::PublicKey::from(&secret_key.dh),
        }
    }
}

/// Construct a public key from a slice of bytes, fails if `len(bytes) != 64`.
impl TryFrom<&[u8]> for VerifyingKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            Err(InternalError::BytesLengthError.into())
        } else {
            Ok(Self {
                ed: ed25519_dalek::VerifyingKey::from_bytes(&bytes[32..].try_into()?)?,
                dh: x25519_dalek::PublicKey::from(*array_ref!(bytes, 0, 32)),
            })
        }
    }
}

/// Convert this public key into a byte array.
impl Into<[u8; PUBLIC_KEY_LENGTH]> for &VerifyingKey {
    fn into(self) -> [u8; PUBLIC_KEY_LENGTH] {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH];

        buf[..32].copy_from_slice(self.dh.as_bytes());
        buf[32..].copy_from_slice(self.ed.as_bytes());
        buf
    }
}
