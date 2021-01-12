#![cfg(test)]

#[macro_export]
macro_rules! test_cipher {
    ($name: ident, $cipher: ty) => {
        mod $name {
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
                let cipher = Aes256Gcm::new(key1()).unwrap();
                let plaintext = vec![];
                let ciphertext = cipher.encrypt(&plaintext).unwrap();
                let decrypted_plaintext = cipher.decrypt(&ciphertext).unwrap();
                assert_eq!(plaintext, decrypted_plaintext);
            }
            
            #[test]
            fn given_emptydata_then_sizecalculationsarecorrect() {
                let cipher = Aes256Gcm::new(key1()).unwrap();
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
                let cipher = Aes256Gcm::new(key1()).unwrap();
                let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
                let ciphertext = cipher.encrypt(&plaintext).unwrap();
                let decrypted_plaintext = cipher.decrypt(&ciphertext).unwrap();
                assert_eq!(plaintext, decrypted_plaintext);
            }
            
            #[test]
            fn given_somedata_then_sizecalculationsarecorrect() {
                let cipher = Aes256Gcm::new(key1()).unwrap();
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
                let cipher = Aes256Gcm::new(key1()).unwrap();
                let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
                let mut ciphertext = cipher.encrypt(&plaintext).unwrap();
                ciphertext[20] += 1;
                let decrypted_plaintext = cipher.decrypt(&ciphertext);
                assert!(decrypted_plaintext.is_err());
            }
            
            #[test]
            fn given_differentkey_then_doesntdecrypt() {
                let cipher = Aes256Gcm::new(key1()).unwrap();
                let plaintext = hex::decode("0ffc9a43e15ccfbef1b0880167df335677c9005948eeadb31f89b06b90a364ad03c6b0859652dca960f8fa60c75747c4f0a67f50f5b85b800468559ea1a816173c0abaf5df8f02978a54b250bc57c7c6a55d4d245014722c0b1764718a6d5ca654976370").unwrap();
                let ciphertext = cipher.encrypt(&plaintext).unwrap();
                let decrypted_plaintext = Aes256Gcm::new(key2()).unwrap().decrypt(&ciphertext);
                assert!(decrypted_plaintext.is_err());
            }
            
            #[test]
            fn test_backward_compatibility() {
                // Test a preencrypted message to make sure we can still encrypt it
                let cipher = Aes256Gcm::new(key1()).unwrap();
                let ciphertext = hex::decode("4e19cd2f561923fe7f1042a38a827ac36bc34fa64d99d1ce01b7d883dafe12739b06562b9ce59f").unwrap();
                assert_eq!(b"Hello World", &cipher.decrypt(&ciphertext).unwrap().as_ref());
            }
        }
    };
}
