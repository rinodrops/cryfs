// use sodiumoxide::

// TODO libsodium doesn't implement non-hw-accelerated AES.
// We probably should have a fallback (maybe to the aes_gcm crate?) or use a library like the 'ring' crate
// that does auto detection and provides both hw-accelerated and non-hw-accelerated versions.
// But 'ring' in particular has the disadvantage that it doesn't mlock keys (afaik). Needs further evaluation.
