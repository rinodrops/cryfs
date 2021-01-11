use aes_gcm::aead::generic_array::typenum::Unsigned;
use aes_gcm::aead::{generic_array::ArrayLength, Aead, Key, NewAead, Nonce};
use aes_gcm::Aes256Gcm as _Aes256Gcm;
use anyhow::{anyhow, bail, Result};
use rand::{thread_rng, RngCore};
use std::marker::PhantomData;

use super::{Cipher, EncryptionKey};

// TODO The aes_gcm crate requires building with RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"
//      otherwise it won't use those instruction sets. Evaluate if there's a better crate or if we can somehow automate this in the build.

pub struct AesKey<C: NewAead>(Key<C>);

impl<C: NewAead> EncryptionKey for AesKey<C> {
    const KeySize: usize = C::KeySize::USIZE;

    fn from_bytes(key_data: &[u8]) -> Self {
        assert_eq!(Self::KeySize, key_data.len(), "Invalid key size");
        AesKey(Key::<C>::clone_from_slice(key_data))
    }
}

pub struct AESGCM<C: NewAead + Aead> {
    _phantom: PhantomData<C>,
}

impl<C: NewAead + Aead> Cipher for AESGCM<C> {
    type EncryptionKey = AesKey<C>;

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

    fn encrypt(plaintext: &[u8], key: &Self::EncryptionKey) -> Result<Vec<u8>> {
        let cipher = C::new(&key.0);
        let ciphertext_size = Self::ciphertext_size(plaintext.len());
        let nonce = random_nonce();
        let cipherdata = cipher.encrypt(&nonce, plaintext)?;
        let mut ciphertext = Vec::with_capacity(ciphertext_size);
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend(cipherdata); // TODO Is there a way to encrypt it without copying here? Or does it even matter?
        assert_eq!(ciphertext_size, ciphertext.len());
        Ok(ciphertext)
    }

    fn decrypt(ciphertext: &[u8], key: &Self::EncryptionKey) -> Result<Vec<u8>> {
        let cipher = C::new(&key.0);
        let nonce = &ciphertext[..C::NonceSize::USIZE];
        let cipherdata = &ciphertext[C::NonceSize::USIZE..];
        let plaintext = cipher.decrypt(nonce.into(), cipherdata)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key1() -> <Aes256Gcm as Cipher>::EncryptionKey {
        AesKey::from_bytes(
            &hex::decode("9726ca3703940a918802953d8db5996c5fb25008a20c92cb95aa4b8fe92702d9")
                .unwrap(),
        )
    }

    #[test]
    fn given_emptydata_when_encrypted_then_canbedecrypted() {
        let plaintext = vec![];
        let ciphertext = Aes256Gcm::encrypt(&plaintext, &key1()).unwrap();
        let decrypted_plaintext = Aes256Gcm::decrypt(&ciphertext, &key1()).unwrap();
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn given_emptydata_then_sizecalculationsarecorrect() {
        let plaintext = vec![];
        let ciphertext = Aes256Gcm::encrypt(&plaintext, &key1()).unwrap();
        assert_eq!(plaintext.len(), Aes256Gcm::plaintext_size(ciphertext.len()));
        assert_eq!(
            ciphertext.len(),
            Aes256Gcm::ciphertext_size(plaintext.len())
        );
    }

    #[test]
    fn given_somedata_when_encrypted_then_canbedecrypted() {
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let ciphertext = Aes256Gcm::encrypt(&plaintext, &key1()).unwrap();
        let decrypted_plaintext = Aes256Gcm::decrypt(&ciphertext, &key1()).unwrap();
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn given_somedata_then_sizecalculationsarecorrect() {
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let ciphertext = Aes256Gcm::encrypt(&plaintext, &key1()).unwrap();
        assert_eq!(plaintext.len(), Aes256Gcm::plaintext_size(ciphertext.len()));
        assert_eq!(
            ciphertext.len(),
            Aes256Gcm::ciphertext_size(plaintext.len())
        );
    }

    // TODO Test encryption fails with wrong key, or wrong ciphertext
}
