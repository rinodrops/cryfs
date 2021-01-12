use generic_array::{GenericArray, ArrayLength};

pub struct EncryptionKey<KeySize: ArrayLength<u8>> {
    // TODO protect key_data with mlock/munlock and make sure we zero it on destruction
    // (libsodium should have functionalities for this, it can be difficult to ensure zeroizing without the compiler optimizing it away)
    // also the 'secrets' crates looks interesting.
    key_data: GenericArray<u8, KeySize>,
}

impl <KeySize: ArrayLength<u8>> EncryptionKey<KeySize> {
    const KeySize: usize = KeySize::USIZE;

    // TODO This still leaves an unprotected time before key_data enters this function.
    //      Can we extend the protection to the whole key generation?
    pub fn from_bytes(key_data: &[u8]) -> Self {
        assert_eq!(Self::KeySize, key_data.len(), "Invalid key size");
        Self {
            key_data: GenericArray::clone_from_slice(key_data),
        }
    }

    pub fn as_bytes(&self) -> &GenericArray<u8, KeySize> {
        &self.key_data
    }
}

impl <KeySize: ArrayLength<u8>> std::fmt::Debug for EncryptionKey<KeySize> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Hide secrets from debug output.
        write!(f, "EncryptionKey(******)")
    }
}
