use anyhow::Result;
use generic_array::typenum::U32;

// TODO AES-GCM-SIV or XChaCha20-Poly1305 (XChaCha20-Poly1305-ietf, chacha20poly1305_ietf, chacha20poly1305) might be better than AES-GCM
// TODO Add 128bit fixed string to the message and verify it, see https://libsodium.gitbook.io/doc/secret-key_cryptography/aead#robustness

mod aes_gcm;
mod libsodium;

#[cfg(test)]
mod cipher_tests;

use super::{EncryptionKey, Cipher};

const NONCE_SIZE: usize = 12;
const AUTH_TAG_SIZE: usize = 16;

/// An implementation of the AES-256-GCM cipher. This does runtime CPU feature detection.
/// If the CPU supports a hardware accelerated implementation, that one will be used, oherwise we fall back
/// to a slow software implementation.
enum Aes256GcmImpl {
    HardwareAccelerated(libsodium::Aes256Gcm),
    SoftwareImplementation(aes_gcm::Aes256Gcm),
}

pub struct Aes256Gcm(Aes256GcmImpl);

impl Cipher for Aes256Gcm {
    type KeySize = U32;

    fn new(encryption_key: EncryptionKey<Self::KeySize>) -> Self {
        let hardware_acceleration_available = libsodium::Aes256Gcm::is_available();
        if hardware_acceleration_available {
            Self(Aes256GcmImpl::HardwareAccelerated(libsodium::Aes256Gcm::new(encryption_key)))
        } else {
            Self(Aes256GcmImpl::SoftwareImplementation(aes_gcm::Aes256Gcm::new(encryption_key)))
        }
    }

    fn ciphertext_size(plaintext_size: usize) -> usize {
        plaintext_size + NONCE_SIZE + AUTH_TAG_SIZE
    }

    fn plaintext_size(ciphertext_size: usize) -> usize {
        assert!(
            ciphertext_size >= NONCE_SIZE + AUTH_TAG_SIZE,
            "Invalid ciphertext size"
        );
        ciphertext_size - NONCE_SIZE - AUTH_TAG_SIZE
    }
    
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match &self.0 {
            Aes256GcmImpl::HardwareAccelerated(i) => i.encrypt(plaintext),
            Aes256GcmImpl::SoftwareImplementation(i) => i.encrypt(plaintext),
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match &self.0 {
            Aes256GcmImpl::HardwareAccelerated(i)=> i.decrypt(ciphertext),
            Aes256GcmImpl::SoftwareImplementation(i) => i.decrypt(ciphertext),
        }
    }
}
