#![cfg(test)]

use generic_array::ArrayLength;

use super::{aes_gcm::Aes256Gcm as aesgcm_Aes256Gcm, libsodium::Aes256Gcm as libsodium_Aes256Gcm};
use super::super::{Cipher, EncryptionKey};

fn key1<L: ArrayLength<u8>>() -> EncryptionKey<L> {
    EncryptionKey::from_hex("9726ca3703940a918802953d8db5996c5fb25008a20c92cb95aa4b8fe92702d9").unwrap()
}

fn key2<L: ArrayLength<u8>>() -> EncryptionKey<L> {
    EncryptionKey::from_hex("a3703940a918802953d8db5996c5fb25008a20c92cb95aa4b8fe92702d99726c").unwrap()
}

#[generic_tests::define]
mod enc_dec {
    use super::*;

    #[test]
    fn given_emptydata_when_encrypted_then_canbedecrypted<Enc: Cipher, Dec: Cipher>() {
        let enc_cipher = Enc::new(key1());
        let dec_cipher = Dec::new(key1());
        let plaintext = vec![];
        let ciphertext = enc_cipher.encrypt(&plaintext).unwrap();
        let decrypted_plaintext = dec_cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn given_somedata_when_encrypted_then_canbedecrypted<Enc: Cipher, Dec: Cipher>() {
        let enc_cipher = Enc::new(key1());
        let dec_cipher = Dec::new(key1());
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let ciphertext = enc_cipher.encrypt(&plaintext).unwrap();
        let decrypted_plaintext = dec_cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn given_invalidciphertext_then_doesntdecrypt<Enc: Cipher, Dec: Cipher>() {
        let enc_cipher = Enc::new(key1());
        let dec_cipher = Dec::new(key1());
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let mut ciphertext = enc_cipher.encrypt(&plaintext).unwrap();
        ciphertext[20] += 1;
        let decrypted_plaintext = dec_cipher.decrypt(&ciphertext);
        assert!(decrypted_plaintext.is_err());
    }
    
    #[test]
    fn given_differentkey_then_doesntdecrypt<Enc: Cipher, Dec: Cipher>() {
        let enc_cipher = Enc::new(key1());
        let dec_cipher = Dec::new(key2());
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let ciphertext = enc_cipher.encrypt(&plaintext).unwrap();
        let decrypted_plaintext = dec_cipher.decrypt(&ciphertext);
        assert!(decrypted_plaintext.is_err());
    }

    // Test aes_gcm implementation
    #[instantiate_tests(<aesgcm_Aes256Gcm, aesgcm_Aes256Gcm>)]
    mod aesgcm {}

    // Test libsodium implementation
    #[instantiate_tests(<libsodium_Aes256Gcm, libsodium_Aes256Gcm>)]
    mod libsodium {}

    // Test interoperability (i.e. encrypting with one and decrypting with the other works)
    #[instantiate_tests(<libsodium_Aes256Gcm, aesgcm_Aes256Gcm>)]
    mod libsodium_aesgcm {}
    #[instantiate_tests(<aesgcm_Aes256Gcm, libsodium_Aes256Gcm>)]
    mod aesgcm_libsodium {}
}

#[generic_tests::define]
mod basics {
    use super::*;

    #[test]
    fn given_emptydata_then_sizecalculationsarecorrect<C: Cipher>() {
        let cipher = C::new(key1());
        let plaintext = vec![];
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(plaintext.len(), C::plaintext_size(ciphertext.len()));
        assert_eq!(
            ciphertext.len(),
            C::ciphertext_size(plaintext.len())
        );
    }
    
    #[test]
    fn given_somedata_then_sizecalculationsarecorrect<C: Cipher>() {
        let cipher = C::new(key1());
        let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(plaintext.len(), C::plaintext_size(ciphertext.len()));
        assert_eq!(
            ciphertext.len(),
            C::ciphertext_size(plaintext.len())
        );
    }
    
    #[test]
    fn test_backward_compatibility<C: Cipher>() {
        // Test a preencrypted message to make sure we can still encrypt it
        let cipher = C::new(key1());
        let ciphertext = hex::decode("4e19cd2f561923fe7f1042a38a827ac36bc34fa64d99d1ce01b7d883dafe12739b06562b9ce59f").unwrap();
        assert_eq!(b"Hello World", &cipher.decrypt(&ciphertext).unwrap().as_ref());
    }

    // Test aes_gcm implementation
    #[instantiate_tests(<aesgcm_Aes256Gcm>)]
    mod aesgcm {}

    // Test libsodium implementation
    #[instantiate_tests(<libsodium_Aes256Gcm>)]
    mod libsodium {}
}
