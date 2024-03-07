#![cfg(feature = "virt")]

use std::println;

use trussed::client::mechanisms::{Kyber1024, Kyber512, Kyber768};
use trussed::client::CryptoClient;
use trussed::types::{KeySerialization, Mechanism, StorageAttributes};
use trussed::{syscall, try_syscall};

mod client;

use trussed::types::Location::*;

#[test]
fn kyber512() {
    client::get(|client| {
        let (sk, pk) = syscall!(client.generate_kyber512_keypair(Internal, Volatile));

        let (ciphertext, secret1) = syscall!(client.encap_kyber512(pk, Volatile));

        let secret2 = syscall!(client.decap_kyber512(sk, ciphertext, Volatile));

        // Trussed® won't give out secrets, but lets us use them
        let derivative1 = syscall!(client.sign_hmacsha256(secret1, &[])).signature;
        let derivative2 = syscall!(client.sign_hmacsha256(secret2, &[])).signature;
        assert_neq!(derivative1, derivative2);
        println!("{:?}", derivative1);
        println!("{:?}", derivative2);

        assert!(try_syscall!(client.serialize_key(
            Mechanism::SharedSecret,
            secret1,
            KeySerialization::Raw
        ))
        .is_err());
        let _ =
            syscall!(client.serialize_key(Mechanism::SharedSecret, secret2, KeySerialization::Raw));
    })
}

#[test]
fn kyber768() {
    client::get(|client| {
        let (sk, pk) = syscall!(client.generate_kyber768_keypair(Internal, Volatile));

        let (ciphertext, secret1) = syscall!(client.encap_kyber768(pk, Volatile));

        let secret2 = syscall!(client.decap_kyber768(sk, ciphertext, Volatile));

        // Trussed® won't give out secrets, but lets us use them
        let derivative1 = syscall!(client.sign_hmacsha256(secret1, &[])).signature;
        let derivative2 = syscall!(client.sign_hmacsha256(secret2, &[])).signature;
        assert_neq!(derivative1, derivative2);
        println!("{:?}", derivative1);
        println!("{:?}", derivative2);

        assert!(try_syscall!(client.serialize_key(
            Mechanism::SharedSecret,
            secret1,
            KeySerialization::Raw
        ))
        .is_err());
        let _ =
            syscall!(client.serialize_key(Mechanism::SharedSecret, secret2, KeySerialization::Raw));
    })
}

#[test]
fn kyber1024() {
    client::get(|client| {
        let (sk, pk) = syscall!(client.generate_kyber1024_keypair(Internal, Volatile));

        let (ciphertext, secret1) = syscall!(client.encap_kyber1024(pk, Volatile));

        let secret2 = syscall!(client.decap_kyber1024(sk, ciphertext, Volatile));

        // Trussed® won't give out secrets, but lets us use them
        let derivative1 = syscall!(client.sign_hmacsha256(secret1, &[])).signature;
        let derivative2 = syscall!(client.sign_hmacsha256(secret2, &[])).signature;
        assert_neq!(derivative1, derivative2);
        println!("{:?}", derivative1);
        println!("{:?}", derivative2);

        assert!(try_syscall!(client.serialize_key(
            Mechanism::SharedSecret,
            secret1,
            KeySerialization::Raw
        ))
        .is_err());
        let _ =
            syscall!(client.serialize_key(Mechanism::SharedSecret, secret2, KeySerialization::Raw));
    })
}
