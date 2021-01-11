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

// TODO AES-GCM-SIV might be better than AES-GCM


pub struct AESGCM<C: NewAead + Aead> {
    cipher: C,
}

impl<C: NewAead + Aead> Cipher for AESGCM<C> {
    type EncryptionKey = EncryptionKey<C::KeySize>;

    fn new(encryption_key: Self::EncryptionKey) -> Self {
        let cipher = C::new(encryption_key.as_bytes());
        Self {cipher}
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key1() -> <Aes256Gcm as Cipher>::EncryptionKey {
        EncryptionKey::from_bytes(
            &hex::decode("9726ca3703940a918802953d8db5996c5fb25008a20c92cb95aa4b8fe92702d9")
                .unwrap(),
        )
    }

    fn key2() -> <Aes256Gcm as Cipher>::EncryptionKey {
        EncryptionKey::from_bytes(
            &hex::decode("a3703940a918802953d8db5996c5fb25008a20c92cb95aa4b8fe92702d99726c")
                .unwrap(),
        )
    }

    #[test]
    fn given_emptydata_when_encrypted_then_canbedecrypted() {
        let cipher = Aes256Gcm::new(key1());
        let plaintext = vec![];
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        let decrypted_plaintext = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn given_emptydata_then_sizecalculationsarecorrect() {
        let cipher = Aes256Gcm::new(key1());
        let plaintext = vec![];
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(plaintext.len(), Aes256Gcm::plaintext_size(ciphertext.len()));
        assert_eq!(
            ciphertext.len(),
            Aes256Gcm::ciphertext_size(plaintext.len())
        );
    }

    #[test]
    fn given_somedata_when_encrypted_then_canbedecrypted() {
        let cipher = Aes256Gcm::new(key1());
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        let decrypted_plaintext = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn given_somedata_then_sizecalculationsarecorrect() {
        let cipher = Aes256Gcm::new(key1());
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(plaintext.len(), Aes256Gcm::plaintext_size(ciphertext.len()));
        assert_eq!(
            ciphertext.len(),
            Aes256Gcm::ciphertext_size(plaintext.len())
        );
    }

    #[test]
    fn given_invalidciphertext_then_doesntdecrypt() {
        let cipher = Aes256Gcm::new(key1());
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let mut ciphertext = cipher.encrypt(&plaintext).unwrap();
        ciphertext[20] += 1;
        let decrypted_plaintext = cipher.decrypt(&ciphertext);
        assert!(decrypted_plaintext.is_err());
    }

    #[test]
    fn given_differentkey_then_doesntdecrypt() {
        let cipher = Aes256Gcm::new(key1());
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let mut ciphertext = cipher.encrypt(&plaintext).unwrap();
        let decrypted_plaintext = Aes256Gcm::new(key2()).decrypt(&ciphertext);
        assert!(decrypted_plaintext.is_err());
    }
}
