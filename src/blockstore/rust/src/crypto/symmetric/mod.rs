use anyhow::Result;

pub trait Cipher {
    type EncryptionKey;
    fn new(key: Self::EncryptionKey) -> Self;

    fn ciphertext_size(plaintext_size: usize) -> usize;
    fn plaintext_size(ciphertext_size: usize) -> usize;

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub mod aes_gcm;
mod key;

pub use key::EncryptionKey;
