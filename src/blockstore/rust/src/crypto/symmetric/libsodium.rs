use sodiumoxide::crypto::aead::aes256gcm::{Key, Nonce, Aes256Gcm as _Aes256Gcm};
use anyhow::{Result, bail, anyhow, Context};
use std::sync::Once;
use generic_array::{typenum::U32, GenericArray, ArrayLength};

use super::{EncryptionKey, Cipher};

// TODO libsodium doesn't implement non-hw-accelerated AES.
// We probably should have a fallback (maybe to the aes_gcm crate?) or use a library like the 'ring' crate
// that does auto detection and provides both hw-accelerated and non-hw-accelerated versions.
// But 'ring' in particular has the disadvantage that it doesn't mlock keys (afaik). Needs further evaluation.

// TODO Add 128bit fixed string to the message and verify it, see https://libsodium.gitbook.io/doc/secret-key_cryptography/aead#robustness

const NONCE_SIZE: usize = 12;
const AUTH_TAG_SIZE: usize = 16;

static INIT_LIBSODIUM: Once = Once::new();

pub struct Aes256Gcm {
    cipher: _Aes256Gcm,
    encryption_key: EncryptionKey<U32>,
}

impl Cipher for Aes256Gcm {
    type EncryptionKey = EncryptionKey<U32>;

    fn new(encryption_key: Self::EncryptionKey) -> Result<Self> {
        INIT_LIBSODIUM.call_once(|| {
            sodiumoxide::init().expect("Failed to initialize libsodium");
        });

        let cipher = _Aes256Gcm::new().map_err(|()| anyhow!("Hardware doesn't support the instructions needed for this implementation"))?;
        Ok(Self {
            cipher,
            encryption_key,
        })
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
        let ciphertext_size = Self::ciphertext_size(plaintext.len());
        let nonce = self.cipher.gen_initial_nonce();
        let cipherdata = self.cipher.seal(plaintext, None, &nonce, &convert_key(&self.encryption_key));
        let mut ciphertext = Vec::with_capacity(ciphertext_size);
        ciphertext.extend_from_slice(nonce.as_ref());
        ciphertext.extend(cipherdata); // TODO Is there a way to encrypt it without copying here? Or does it even matter?
        assert_eq!(ciphertext_size, ciphertext.len());
        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = &ciphertext[..NONCE_SIZE];
        let cipherdata = &ciphertext[NONCE_SIZE..];
        let nonce = Nonce::from_slice(nonce).expect("Wrong nonce size");
        let plaintext = self.cipher.open(cipherdata, None, &nonce, &convert_key(&self.encryption_key))
            .map_err(|()| anyhow!("Decrypting data failed"))?;
        assert_eq!(Self::plaintext_size(ciphertext.len()), plaintext.len());
        Ok(plaintext)
    }
}

fn convert_key(key: &EncryptionKey<U32>) -> Key {
    // Panic on error is ok because key size is hard coded and not dependent on input here
    Key::from_slice(key.as_bytes()).expect("Invalid key size")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_cipher;

    test_cipher!(libsodium_aes256gcm, Aes256Gcm);
}
