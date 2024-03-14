#![cfg(feature = "virt")]

use std::assert_eq;

use trussed::client::mechanisms::{Dilithium2, Dilithium3};
use trussed::api::reply::{GenerateKeyPair, Sign, Verify};
use trussed::syscall;

mod client;

use trussed::types::Location::*;

const MESSAGE: &[u8] = b"Sign this message";

#[test]
fn dilithium2() {
    client::get(|client| {
        let keypair: GenerateKeyPair = syscall!(client.generate_dilithium2_keypair(Internal, Volatile));
        let (sk, pk) = (keypair.private_key, keypair.public_key);

        let sign: Sign = syscall!(client.sign_dilithium2(sk, MESSAGE));
        let signature: &[u8] = &sign.signature.as_slice();

        let verify: Verify = syscall!(client.verify_dilithium2(pk, MESSAGE, signature));

        assert_eq!(verify.valid, true);
    })
}

#[test]
fn dilithium3() {
    client::get(|client| {
        let keypair: GenerateKeyPair = syscall!(client.generate_dilithium3_keypair(Internal, Volatile));
        let (sk, pk) = (keypair.private_key, keypair.public_key);

        let sign: Sign = syscall!(client.sign_dilithium3(sk, MESSAGE));
        let signature: &[u8] = &sign.signature.as_slice();

        let verify: Verify = syscall!(client.verify_dilithium3(pk, MESSAGE, signature));

        assert_eq!(verify.valid, true);
    })
}
