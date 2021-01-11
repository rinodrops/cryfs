use anyhow::Result;

pub trait EncryptionKey {
    const KeySize: usize;

    fn from_bytes(key_data: &[u8]) -> Self;
}

pub trait Cipher {
    type EncryptionKey;
    fn ciphertext_size(plaintext_size: usize) -> usize;
    fn plaintext_size(ciphertext_size: usize) -> usize;

    fn encrypt(data: &[u8], key: &Self::EncryptionKey) -> Result<Vec<u8>>;
    fn decrypt(data: &[u8], key: &Self::EncryptionKey) -> Result<Vec<u8>>;
}

pub mod aes_gcm;
