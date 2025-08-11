use aes_gcm::aead::consts::U16;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::{Aes256Gcm, AesGcm, Error, Key, Nonce};

pub type Aes256GcmIv16 = AesGcm<Aes256, U16>;

pub trait IvLength: KeyInit + Aead {
    fn iv_length() -> usize;
}

impl IvLength for Aes256Gcm {
    fn iv_length() -> usize {
        12
    }
}

impl IvLength for Aes256GcmIv16 {
    fn iv_length() -> usize {
        16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cipher<I: IvLength> {
    cipher: I,
}

impl<I: IvLength> Cipher<I> {
    pub(crate) fn new(key: &[u8]) -> Self {
        let key = Key::<I>::from_slice(key);

        Cipher {
            cipher: I::new(key),
        }
    }

    pub(crate) fn init_iv(&self) -> Vec<u8> {
        let mut iv = vec![0u8; I::iv_length()];
        OsRng.fill_bytes(&mut iv);
        iv
    }

    pub(crate) fn encrypt(&self, payload: Payload, iv: Vec<u8>) -> Result<Vec<u8>, Error> {
        let nonce = Nonce::from_slice(&iv);
        self.cipher.encrypt(nonce, payload)
    }

    pub(crate) fn decrypt(&self, remainder: Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, Error> {
        let iv_length = I::iv_length();

        // Extract IV, Ciphertag, and Ciphertext
        let iv = &remainder[..iv_length];
        let ciphertag = &remainder[iv_length..iv_length + 16]; // 16-byte Ciphertag
        let ciphertext = &remainder[iv_length + 16..]; // Remaining is ciphertext

        // Combine ciphertext and ciphertag for decryption
        let mut combined_ciphertext = Vec::new();
        combined_ciphertext.extend_from_slice(ciphertext);
        combined_ciphertext.extend_from_slice(ciphertag); // Append the tag for decryption

        let payload = Payload {
            msg: &combined_ciphertext,
            aad,
        };

        self.cipher.decrypt(Nonce::from_slice(iv), payload)
    }
}
