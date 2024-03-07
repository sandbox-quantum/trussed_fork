#![cfg(feature = "virt")]

use std::{assert_eq, println};

use trussed::client::mechanisms::{Dilithium2, Dilithium3};
use trussed::client::CryptoClient;
use trussed::types::{KeySerialization, Mechanism, StorageAttributes};
use trussed::{syscall, try_syscall};

mod client;

use trussed::types::Location::*;

const MESSAGE: &[u8] = "Sign this message";

#[test]
fn dilithium2() {
    client::get(|client| {
        let (sk, pk) = syscall!(client.generate_dilithium2_keypair(Internal, Volatile));

        let signature = syscall!(client.sign_dilithium2(sk, MESSAGE)).signature;

        let is_valid = syscall!(client.verify_dilithium2(pk, MESSAGE, signature)).valid;

        assert_eq!(is_valid, true);
    })
}

#[test]
fn dilithium3() {
    client::get(|client| {
        let (sk, pk) = syscall!(client.generate_dilithium3_keypair(Internal, Volatile));

        let signature = syscall!(client.sign_dilithium3(sk, MESSAGE)).signature;

        let is_valid = syscall!(client.verify_dilithium3(pk, MESSAGE, signature)).valid;

        assert_eq!(is_valid, true);
    })
}
