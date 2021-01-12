use generic_array::{GenericArray, ArrayLength};
use log::warn;

// TODO The 'secrets' crate looks interesting as a replacement to 'region',
// but the dependency didn't compile for me.

/// An encryption key for a cipher. The key is stored in protected memory, i.e.
/// it shouldn't be swapped to disk and will be automatically zeroed on destruction.
/// Note that this is only a best-effort and not guaranteed. There's still scenarios
/// (say when the PC is suspended to disk) where the key will end up on the disk.
pub struct EncryptionKey<KeySize: ArrayLength<u8>> {
    key_data: Box<GenericArray<u8, KeySize>>,
    lock_guard: Option<region::LockGuard>,
}

impl <KeySize: ArrayLength<u8>> EncryptionKey<KeySize> {
    const KeySize: usize = KeySize::USIZE;

    // TODO This still leaves an unprotected time before key_data enters this function.
    //      Can we extend the protection to the whole key generation process?
    pub fn from_bytes(key_data: &[u8]) -> Self {
        assert_eq!(Self::KeySize, key_data.len(), "Invalid key size");
        // Don't use GenericArray::clone_from_slice to avoid copying to the key to the unprotected stack first
        let mut key_data_protected = Box::new(GenericArray::default());
        let lock_guard = region::lock(key_data_protected.as_slice().as_ptr(), key_data_protected.as_slice().len());
        let lock_guard = match lock_guard {
            Ok(lock_guard) => Some(lock_guard),
            Err(err) => {
                warn!("Couldn't protect the RAM page storing the encryption key, which means it could get swapped to the disk if your operating system chooses to. This does not hinder any functionality though. Error: {}", err);
                None
            }
        };
        key_data_protected.as_mut_slice().copy_from_slice(key_data);
        Self {
            key_data: key_data_protected,
            lock_guard,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }
}

impl <KeySize: ArrayLength<u8>> std::fmt::Debug for EncryptionKey<KeySize> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptionKey<{}>(****)", KeySize::USIZE)
    }
}

impl <KeySize: ArrayLength<u8>> Drop for EncryptionKey<KeySize> {
    fn drop(&mut self) {
        sodiumoxide::utils::memzero(&mut self.key_data);
    }
}
