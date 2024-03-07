use core::convert::TryInto;

use crate::api::*;
use crate::error::Error;
use crate::service::*;
use crate::types::*;

use pqcrypto_dilithium::dilithium2::{
    detached_sign, keypair, public_key_bytes, secret_key_bytes, signature_bytes,
    verify_detached_signature,
};
use pqcrypto_dilithium::dilithium2::{
    DetachedSignature as Dilithium2DetachSignature, PublicKey as Dilithium2PublicKey,
};
use pqcrypto_traits::sign::*;

pub const DILITHIUM2_PUBLICKEYBYTES: usize = public_key_bytes();
pub const DILITHIUM2_SECRETKEYBYTES: usize = secret_key_bytes();
pub const DILITHIUM2_SIGNATUREBYTES: usize = signature_bytes();

#[inline(never)]
fn load_public_key(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<[u8; DILITHIUM2_PUBLICKEYBYTES], Error> {
    let public_bytes: [u8; DILITHIUM2_PUBLICKEYBYTES] = keystore
        .load_key(key::Secrecy::Public, Some(key::Kind::Dilithium2), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    Ok(public_bytes)
}

fn load_secret_key(
    keystore: &mut impl Keystore,
    key_id: &KeyId,
) -> Result<[u8; DILITHIUM2_SECRETKEYBYTES], Error> {
    let private_bytes: [u8; DILITHIUM2_SECRETKEYBYTES] = keystore
        .load_key(key::Secrecy::Secret, Some(key::Kind::Dilithium2), key_id)?
        .material
        .as_slice()
        .try_into()
        .map_err(|_| Error::InternalError)?;

    Ok(private_bytes)
}

#[cfg(feature = "dilithium2")]
impl DeserializeKey for super::Dilithium2 {
    #[inline(never)]
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

        let serialized_key: [u8; DILITHIUM2_PUBLICKEYBYTES] = request.serialized_key
            [..DILITHIUM2_PUBLICKEYBYTES]
            .try_into()
            .unwrap();
        let public_key: Dilithium2PublicKey = Dilithium2PublicKey::from_bytes(&serialized_key)
            .map_err(|_| Error::InvalidSerializedKey)?;

        let public_id = keystore.store_key(
            request.attributes.persistence,
            key::Secrecy::Public,
            key::Kind::Dilithium2,
            public_key.as_bytes(),
        )?;

        Ok(reply::DeserializeKey { key: public_id })
    }
}

#[cfg(feature = "dilithium2")]
impl GenerateKeyPair for super::Dilithium2 {
    #[inline(never)]
    fn generate_keypair(
        keystore: &mut impl Keystore,
        request: &request::GenerateKeyPair,
    ) -> Result<reply::GenerateKeyPair, Error> {
        let (public_key, private_key) = keypair();

        // store keys
        let private_key_id = keystore.store_key(
            request.sk_attributes.persistence,
            key::Secrecy::Secret,
            key::Info::from(key::Kind::Dilithium2).with_local_flag(),
            &private_key.as_bytes(),
        )?;

        let public_key_id = keystore.store_key(
            request.pk_attributes.persistence,
            key::Secrecy::Public,
            key::Info::from(key::Kind::Dilithium2).with_local_flag(),
            &public_key.as_bytes(),
        )?;

        // return handle
        Ok(reply::GenerateKeyPair {
            private_key: private_key_id,
            public_key: public_key_id,
        })
    }
}

#[cfg(feature = "dilithium2")]
impl SerializeKey for super::Dilithium2 {
    #[inline(never)]
    fn serialize_key(
        keystore: &mut impl Keystore,
        request: &request::SerializeKey,
    ) -> Result<reply::SerializeKey, Error> {
        let key_id = request.key;
        let public_key = load_public_key(keystore, &key_id)?;

        let serialized_key = match request.format {
            KeySerialization::Raw => {
                let mut serialized_key = SerializedKey::new();
                serialized_key
                    .extend_from_slice(&public_key)
                    .map_err(|_| Error::InternalError)?;

                serialized_key
            }

            _ => {
                return Err(Error::InternalError);
            }
        };

        Ok(reply::SerializeKey { serialized_key })
    }
}

#[cfg(feature = "dilithium2")]
impl Exists for super::Dilithium2 {
    #[inline(never)]
    fn exists(
        keystore: &mut impl Keystore,
        request: &request::Exists,
    ) -> Result<reply::Exists, Error> {
        let key_id = request.key;

        let exists =
            keystore.exists_key(key::Secrecy::Secret, Some(key::Kind::Dilithium2), &key_id);
        Ok(reply::Exists { exists })
    }
}

#[cfg(feature = "dilithium2")]
impl Sign for super::Dilithium2 {
    #[inline(never)]
    fn sign(keystore: &mut impl Keystore, request: &request::Sign) -> Result<reply::Sign, Error> {
        let key_id = request.key;

        let msg = request.message.as_slice();

        let secret_bytes = load_secret_key(keystore, &key_id)?;
        let secret_key = SecretKey::from_bytes(&secret_bytes).unwrap();

        let native_signature = detached_sign(msg, &secret_key);
        let our_signature = Signature::from_slice(native_signature.as_bytes()).unwrap();

        // return signature
        Ok(reply::Sign {
            signature: our_signature,
        })
    }
}

#[cfg(feature = "dilithium2")]
impl Verify for super::Dilithium2 {
    #[inline(never)]
    fn verify(
        keystore: &mut impl Keystore,
        request: &request::Verify,
    ) -> Result<reply::Verify, Error> {
        if let SignatureSerialization::Raw = request.format {
        } else {
            return Err(Error::InvalidSerializationFormat);
        }

        if request.signature.len() != DILITHIUM2_SIGNATUREBYTES {
            return Err(Error::WrongSignatureLength);
        }

        let key_id = request.key;
        let public_bytes = load_public_key(keystore, &key_id)?;
        let public_key = PublicKey::from_bytes(&public_bytes).unwrap();

        let msg = request.message.as_slice();

        let signature_bytes = &request.signature[..DILITHIUM2_SIGNATUREBYTES];

        let signature: Dilithium2DetachSignature =
            DetachedSignature::from_bytes(signature_bytes).unwrap();

        let is_valid = verify_detached_signature(&signature, msg, &public_key).is_ok();

        Ok(reply::Verify { valid: is_valid })
    }
}

#[cfg(not(feature = "dilithium2"))]
impl Exists for super::Dilithium2 {}
#[cfg(not(feature = "dilithium2"))]
impl GenerateKeyPair for super::Dilithium2 {}
#[cfg(not(feature = "dilithium2"))]
impl SerializeKey for super::Dilithium2 {}
#[cfg(not(feature = "dilithium2"))]
impl DeserializeKey for super::Dilithium2 {}
#[cfg(not(feature = "dilithium2"))]
impl Sign for super::Dilithium2 {}
#[cfg(not(feature = "dilithium2"))]
impl Verify for super::Dilithium2 {}
