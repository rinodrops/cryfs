use anyhow::Result;
use generic_array::ArrayLength;

pub trait Cipher : Sized {
    type KeySize : ArrayLength<u8>;

    fn new(key: EncryptionKey<Self::KeySize>) -> Result<Self>;

    fn ciphertext_size(plaintext_size: usize) -> usize;
    fn plaintext_size(ciphertext_size: usize) -> usize;

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub mod aes_gcm;
pub mod libsodium;
mod key;

#[cfg(test)]
mod cipher_tests;

pub use key::EncryptionKey;

