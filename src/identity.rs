use crate::{Address, InternalError, SecretKey, VerifyingKey};

use ed25519_dalek::SigningKey;
use failure::*;

use std::convert::{TryFrom, TryInto};
use std::fs;
use std::path::Path;

/// Combination of [`Address`](struct.Address.html), [`VerifyingKey`](struct.VerifyingKey) and optionally
/// [`SecretKey`](struct.SecretKey.html).
pub struct Identity {
    pub address: Address,
    pub public_key: VerifyingKey,
    pub secret_key: Option<SecretKey>,
}

impl Identity {
    /// Read ZeroTier identity from given location.
    pub fn read<P: AsRef<Path>>(path: P) -> Fallible<Self> {
        Identity::try_from(&fs::read_to_string(path)?[..])
    }

    /// Read ZeroTier identity from default location.
    pub fn read_default() -> Fallible<Self> {
        Identity::read("/var/lib/zerotier-one/identity.secret")
    }
}

impl TryFrom<SecretKey> for Identity {
    type Error = Error;

    fn try_from(secret_key: SecretKey) -> Fallible<Self> {
        let public_key = VerifyingKey::from(&secret_key);

        Ok(Self {
            address: Address::try_from(&public_key)?,
            public_key: VerifyingKey::from(&secret_key),
            secret_key: Some(secret_key),
        })
    }
}

/// TODO: use IO reader instead
impl TryFrom<&str> for Identity {
    type Error = Error;

    fn try_from(identity: &str) -> Fallible<Self> {
        let split_identity: Vec<&str> = identity.split(':').collect();
        let (address1, public_key1, maybe_secret_key1) = match &split_identity[..] {
            [address, "0", public_key] => (address, public_key, None),
            [address, "0", public_key, secret_key] => (address, public_key, Some(secret_key)),
            _ => return Err(InternalError::MalformedIdentity.into()),
        };
        let address = Address::try_from(hex::decode(address1)?.as_slice())?;
        let public_key = VerifyingKey::try_from(hex::decode(public_key1)?.as_slice())?;
        let secret_key = match maybe_secret_key1 {
            Some(secret_key) => Some(SecretKey::try_from(hex::decode(secret_key)?.as_slice())?),
            None => None,
        };
        Ok(Identity {
            address,
            public_key,
            secret_key,
        })
    }
}

impl TryInto<SigningKey> for Identity {
    type Error = Error;

    fn try_into(self) -> Fallible<SigningKey> {
        Ok(SigningKey::from_bytes(&self.secret_key.unwrap().ed))
    }
}

#[cfg(test)]
pub mod tests {
    use ed25519_dalek::{Signer, Verifier};

    use super::*;

    #[test]
    fn test_identity() -> Fallible<()> {
        // nix-shell -p zerotierone --run 'zerotier-idtool generate'
        let identity_str = "538c34e03c:0:070288330a72d2aa3cb7935dfe6028d9fb83bdb42240aaa05e33529121babd183ff775351742a47487454195c08c0e83c520e7466fcdde3396a0c4cd40557737:f20542ab6955fe140fb3a5be9557666b9c89a3e2b73432de46d827d11736773aca15c3e03b89a1d09436ae45bc02f84b8d5a0a2f6c0d42b3856c2b22f5ab2b27";
        let identity = Identity::try_from(identity_str)?;

        // assert_eq!(identity.address, Address::try_from(&identity.public_key)?);

        let secret_key = identity.secret_key.unwrap();
        let public_key = identity.public_key.clone();

        assert_eq!(identity.public_key.ed, public_key.ed);
        assert_eq!(identity.public_key.dh.as_bytes(), public_key.dh.as_bytes());

        let keypair = ed25519_dalek::SigningKey::from_bytes(&secret_key.ed);

        let message = b"7VbLpreCRY738Sw4OGecCw";
        let signature = keypair.sign(message);

        identity.public_key.ed.verify(message, &signature)?;

        Ok(())
    }
}
