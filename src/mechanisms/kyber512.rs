use core::convert::TryInto;

use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

use pqcrypto_kyber::kyber512::PublicKey as Kyber512PublicKey;
use pqcrypto_kyber::kyber512::{
    decapsulate, encapsulate, keypair, public_key_bytes, secret_key_bytes,
};
use pqcrypto_traits::kem::*;

pub const KYBER512_PUBLICKEYBYTES: usize = public_key_bytes();
pub const KYBER512_SECRETKEYBYTES: usize = secret_key_bytes();

fn load_public_key(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<[u8; KYBER512_PUBLICKEYBYTES], Error> {
    let public_bytes: [u8; KYBER512_PUBLICKEYBYTES] = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::Kyber512), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    Ok(public_bytes)
}

fn load_secret_key(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<[u8; KYBER512_SECRETKEYBYTES], Error> {
    let private_bytes: [u8; KYBER512_SECRETKEYBYTES] = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::Kyber512), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    Ok(private_bytes)
}

#[cfg(feature = "kyber512")]
impl GenerateKeyPair for super::Kyber512 {
    // #[inline(never)]
    fn generate_keypair(
        keystore: &mut impl Keystore,
        request: &request::GenerateKeyPair,
    ) -> Result<reply::GenerateKeyPair, Error> {
        // generate keypair
        let (public_key, private_key) = keypair();

        // store keys
        let public_key_id = keystore.store_key(
            request.pk_attributes.persistence,
            key::Secrecy::Public,
            key::Info::from(key::Kind::Kyber512).with_local_flag(),
            &public_key.as_bytes(),
        )?;

        // store keys
        let private_key_id = keystore.store_key(
            request.sk_attributes.persistence,
            key::Secrecy::Secret,
            key::Info::from(key::Kind::Kyber512).with_local_flag(),
            &private_key.as_bytes(),
        )?;

        // return handle
        Ok(reply::GenerateKeyPair {
            public_key: public_key_id,
            private_key: private_key_id,
        })
    }
}

#[cfg(feature = "kyber512")]
impl Encap for super::Kyber512 {
    // #[inline(never)]
    fn encap(
        keystore: &mut impl Keystore,
        request: &request::Encap,
    ) -> Result<reply::Encap, Error> {
        let public_bytes = load_public_key(keystore, &request.public_key)?;
        let public_key = PublicKey::from_bytes(&public_bytes).unwrap();

        let (shared_secret, ciphertext) = encapsulate(&public_key);

        let flags = if request.attributes.serializable {
            key::Flags::SERIALIZABLE
        } else {
            key::Flags::empty()
        };
        let info = key::Info {
            kind: key::Kind::Shared(shared_secret.as_bytes().len()),
            flags,
        };

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            info,
            &shared_secret.as_bytes(),
        )?;

        let ciphertext = Bytes::from_slice(ciphertext.as_bytes()).unwrap();
        // return handle
        Ok(reply::Encap {
            shared_secret: key_id,
            ciphertext,
        })
    }
}

#[cfg(feature = "kyber512")]
impl Decap for super::Kyber512 {
    // #[inline(never)]
    fn decap(
        keystore: &mut impl Keystore,
        request: &request::Decap,
    ) -> Result<reply::Decap, Error> {
        let private_bytes = load_secret_key(keystore, &request.private_key)?;
        let private_key = SecretKey::from_bytes(&private_bytes).unwrap();

        let ciphertext = Ciphertext::from_bytes(&request.ciphertext.as_slice()).unwrap();

        let shared_secret = decapsulate(&ciphertext, &private_key);

        let flags = if request.attributes.serializable {
            key::Flags::SERIALIZABLE
        } else {
            key::Flags::empty()
        };
        let info = key::Info {
            kind: key::Kind::Shared(shared_secret.as_bytes().len()),
            flags,
        };

        let key_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Secret,
            info,
            &shared_secret.as_bytes(),
        )?;

        // return handle
        Ok(reply::Decap {
            shared_secret: key_id,
        })
    }
}

#[cfg(feature = "kyber512")]
impl Exists for super::Kyber512 {
    // #[inline(never)]
    fn exists(
        keystore: &mut impl Keystore,
        request: &request::Exists,
    ) -> Result<reply::Exists, Error> {
        let key_id = request.key;
        let exists = keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::Kyber512), &key_id);
        Ok(reply::Exists { exists })
    }
}

#[cfg(feature = "kyber512")]
impl SerializeKey for super::Kyber512 {
    // #[inline(never)]
    fn serialize_key(
        keystore: &mut impl Keystore,
        request: &request::SerializeKey,
    ) -> Result<reply::SerializeKey, Error> {
        let key_id = request.key;
        let public_key = load_public_key(keystore, &key_id)?;

        let mut serialized_key = SerializedKey::new();
        match request.format {
            KeySerialization::Raw => {
                serialized_key
                    .extend_from_slice(&public_key.as_slice())
                    .map_err(|_| Error::InternalError)?;
            }

            _ => {
                return Err(Error::InternalError);
            }
        }

        Ok(reply::SerializeKey { serialized_key })
    }
}

#[cfg(feature = "kyber512")]
impl DeserializeKey for super::Kyber512 {
    // #[inline(never)]
    fn deserialize_key(
        keystore: &mut impl Keystore,
        request: &request::DeserializeKey,
    ) -> Result<reply::DeserializeKey, Error> {
        // - mechanism: Mechanism
        // - serialized_key: Message
        // - attributes: StorageAttributes

        if request.format != KeySerialization::Raw {
            return Err(Error::InternalError);
        }

        if request.serialized_key.len() != KYBER512_PUBLICKEYBYTES {
            return Err(Error::InvalidSerializedKey);
        }

        let public_key: Kyber512PublicKey =
            PublicKey::from_bytes(&request.serialized_key.as_slice()).unwrap();

        // Since we use Raw so the serialized_key is converted directly.
        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::Kyber512,
            &public_key.as_bytes(),
        )?;

        Ok(reply::DeserializeKey { key: public_id })
    }
}

#[cfg(not(feature = "kyber512"))]
impl GenerateKeyPair for super::Kyber512 {}
#[cfg(not(feature = "kyber512"))]
impl Encap for super::Kyber512 {}
#[cfg(not(feature = "kyber512"))]
impl Decap for super::Kyber512 {}
#[cfg(not(feature = "kyber512"))]
impl Exists for super::Kyber512 {}
#[cfg(not(feature = "kyber512"))]
impl SerializeKey for super::Kyber512 {}
#[cfg(not(feature = "kyber512"))]
impl DeserializeKey for super::Kyber512 {}
