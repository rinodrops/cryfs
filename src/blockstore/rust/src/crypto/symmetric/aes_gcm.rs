use aes_gcm::aead::generic_array::typenum::Unsigned;
use aes_gcm::aead::{generic_array::ArrayLength, Aead, Key, NewAead, Nonce};
use aes_gcm::Aes256Gcm as _Aes256Gcm;
use anyhow::{anyhow, bail, Result, Context};
use rand::{thread_rng, RngCore};
use std::marker::PhantomData;

use super::{Cipher, EncryptionKey};

// TODO The aes_gcm crate requires building with RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
//      otherwise it won't use those instruction sets. Evaluate if there's a better crate or if we can somehow automate this in the build.
// TODO Ring might be a better crate for this as they automatically recognize CPU capabilities. Or maybe libsodium-sys.

// TODO AES-GCM-SIV or XChaCha20-Poly1305 (XChaCha20-Poly1305-ietf, chacha20poly1305_ietf, chacha20poly1305) might be better than AES-GCM


pub struct AESGCM<C: NewAead + Aead> {
    cipher: C,
}

impl<C: NewAead + Aead> Cipher for AESGCM<C> {
    type KeySize = C::KeySize;

    fn new(encryption_key: EncryptionKey<Self::KeySize>) -> Result<Self> {
        let cipher = C::new(encryption_key.as_bytes());
        Ok(Self {cipher})
    }

    fn ciphertext_size(plaintext_size: usize) -> usize {
        plaintext_size + C::NonceSize::USIZE + C::TagSize::USIZE
    }

    fn plaintext_size(ciphertext_size: usize) -> usize {
        assert!(
            ciphertext_size >= C::NonceSize::USIZE + C::TagSize::USIZE,
            "Invalid ciphertext size"
        );
        ciphertext_size - C::NonceSize::USIZE - C::TagSize::USIZE
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext_size = Self::ciphertext_size(plaintext.len());
        let nonce = random_nonce();
        let cipherdata = self.cipher.encrypt(&nonce, plaintext).context("Encrypting data failed")?;
        let mut ciphertext = Vec::with_capacity(ciphertext_size);
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend(cipherdata); // TODO Is there a way to encrypt it without copying here? Or does it even matter?
        assert_eq!(ciphertext_size, ciphertext.len());
        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = &ciphertext[..C::NonceSize::USIZE];
        let cipherdata = &ciphertext[C::NonceSize::USIZE..];
        let plaintext = self.cipher.decrypt(nonce.into(), cipherdata).context("Decrypting data failed")?;
        assert_eq!(Self::plaintext_size(ciphertext.len()), plaintext.len());
        Ok(plaintext)
    }
}

fn random_nonce<Size: ArrayLength<u8>>() -> Nonce<Size> {
    let mut nonce = Nonce::<Size>::default();
    let mut rng = thread_rng();
    rng.fill_bytes(&mut nonce);
    nonce
}

pub type Aes256Gcm = AESGCM<_Aes256Gcm>;

// Test cases are in cipher_tests.rs
