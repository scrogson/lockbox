//! Lockbox
//!
//! This library provides encryption and decryption using the AES-GCM (Galois/Counter Mode) algorithm.
//! It ensures data integrity and confidentiality while providing flexibility for various use cases.
//!
//! # Features
//!
//! - Simple and intuitive API for encrypting and decrypting data.
//! - Support for customizable tags, Additional Authenticated Data (AAD), and Initialization Vectors (IV).
//! - Secure default settings to avoid common cryptographic pitfalls.
//! - Error handling with detailed, meaningful messages.

mod cipher;
mod config;
mod tag;

use crate::cipher::{Aes256GcmIv16, Cipher, IvLength};
use crate::config::VaultConfig;
use crate::tag::{TagDecoder, TagEncoder};
use aes_gcm::aead::{KeyInit, OsRng, Payload};
use aes_gcm::Aes256Gcm;
use thiserror::Error;

pub type Vault = VaultWithConfig<DefaultIvLength>;
pub type DefaultIvLength = IvLength12;

pub type IvLength12 = Aes256Gcm;
pub type IvLength16 = Aes256GcmIv16;

#[derive(Debug, Error)]
pub enum Error {
    #[error("AES-GCM encrypt error")]
    Encrypt,

    #[error("AES-GCM decrypt error")]
    Decrypt,

    #[error("Unsupported version")]
    UnsupportedVersion,

    #[error("Unsupported tag")]
    UnsupportedTag,

    #[error("UTF-8 error")]
    Utf8(#[from] std::string::FromUtf8Error),
}

/// Generates a random 256-bit (32-byte) key for AES-256 encryption.
///
/// # Returns
///
/// A `Vec<u8>` containing the generated key.
///
/// # Example
///
/// ```
/// let key = lockbox::generate_key();
/// println!("Generated key: {:?}", key);
/// ```
pub fn generate_key() -> Vec<u8> {
    Aes256Gcm::generate_key(OsRng).to_vec()
}

/// Vault provides methods for encrypting and decrypting data using the AES-GCM algorithm.
///
/// This struct supports customizable tags, Initialization Vectors (IV), and Additional Authenticated Data (AAD).
pub struct VaultWithConfig<I: IvLength = DefaultIvLength> {
    cipher: Cipher<I>,
    pub config: VaultConfig,
}

impl<I: IvLength> VaultWithConfig<I> {
    /// Creates a new `Vault` instance with default config.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice representing the encryption key (32 bytes for AES-256).
    ///
    /// # Returns
    ///
    /// A new `Vault` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use lockbox::Vault;
    ///
    /// let key = [0u8; 32]; // 256-bit key for AES-256
    /// let vault = Vault::new(&key);
    /// ```
    pub fn new(key: &[u8]) -> Self {
        Self {
            cipher: Cipher::new(key),
            config: VaultConfig::default(),
        }
    }

    /// Sets a custom tag for the vault.
    ///
    /// # Arguments
    ///
    /// * `tag` - A string that represents a version or identifier for the cipher.
    ///
    /// # Returns
    ///
    /// `Vault` instance with the updated tag.
    ///
    /// # Example
    ///
    /// ```
    /// use lockbox::Vault;
    ///
    /// let key = [0u8; 32];
    /// let vault = Vault::new(&key).with_tag("Custom.Tag.V1");
    /// ```
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.config.tag = tag.to_string();
        self
    }

    /// Sets custom Additional Authenticated Data (AAD) for the vault.
    ///
    /// # Arguments
    ///
    /// * `aad` - A string representing Additional Authenticated Data.
    ///
    /// # Returns
    ///
    /// `Vault` instance with the updated AAD.
    ///
    /// # Example
    ///
    /// ```
    /// use lockbox::Vault;
    ///
    /// let key = [0u8; 32];
    /// let vault = Vault::new(&key).with_aad("Custom.AAD");
    /// ```
    pub fn with_aad(mut self, aad: &str) -> Self {
        self.config.aad = aad.to_string();
        self
    }

    /// Encrypts the provided plaintext.
    ///
    /// Generates a random Initialization Vector (IV) for each encryption.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - A byte slice of the data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted data as a `Vec<u8>` or an `Error`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::Encrypt` if encryption fails.
    ///
    /// # Example
    ///
    /// ```
    /// use lockbox::{Vault, generate_key};
    ///
    /// let key = generate_key();
    /// let vault = Vault::new(&key);
    ///
    /// let encrypted = vault.encrypt(b"Hello, world!").unwrap();
    /// ```
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let iv = self.cipher.init_iv();
        let aad = self.config.aad.as_bytes();

        // Encrypt the plaintext with AAD
        let ciphertext_with_tag = self
            .cipher
            .encrypt(
                Payload {
                    msg: plaintext,
                    aad,
                },
                iv.to_vec(),
            )
            .map_err(|_| Error::Encrypt)?;

        // Split ciphertext and authentication tag
        let (ciphertext, ciphertag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

        // Encode the tag using TagEncoder
        let encoded_tag = TagEncoder::encode(self.config.tag.as_bytes());

        // Concatenate Encoded Tag, IV, Ciphertag, and Ciphertext
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&encoded_tag); // Encoded Tag
        encoded.extend_from_slice(&iv);
        encoded.extend_from_slice(ciphertag); // 16-byte Ciphertag
        encoded.extend_from_slice(ciphertext); // Ciphertext

        Ok(encoded)
    }

    /// Decrypts the provided ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - A byte slice of the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted data as a `String` or an `Error`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::Decrypt` if decryption fails.
    ///
    /// # Example
    ///
    /// ```
    /// use lockbox::{Vault, generate_key};
    ///
    /// let key = generate_key();
    /// let vault = Vault::new(&key);
    ///
    /// let encrypted = vault.encrypt(b"Hello, world!").unwrap();
    /// let decrypted = vault.decrypt(&encrypted).unwrap();
    /// assert_eq!(decrypted.as_bytes(), b"Hello, world!");
    /// ```
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<String, Error> {
        // Decode the tag using TagDecoder
        let (tag, remainder) =
            TagDecoder::decode(ciphertext).map_err(|_| Error::UnsupportedVersion)?;
        if tag != self.config.tag.as_bytes() {
            return Err(Error::UnsupportedTag);
        }

        let aad = self.config.aad.as_bytes();

        let plaintext = self
            .cipher
            .decrypt(remainder, aad)
            .map_err(|_| Error::Decrypt)?;

        // Return the decrypted data as a UTF-8 string
        Ok(String::from_utf8(plaintext)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &[u8] = b"Hello, world";

    #[test]
    fn works_with_default_config() {
        let key = generate_key();
        let vault = Vault::new(&key);

        let encrypted = vault.encrypt(PLAINTEXT).expect("encryption failed");
        let decrypted = vault.decrypt(&encrypted).expect("decryption failed");

        assert_eq!(decrypted.as_bytes(), PLAINTEXT);
    }

    #[test]
    fn works_with_16_byte_iv_length() {
        let key = generate_key();
        let vault: VaultWithConfig<IvLength16> = VaultWithConfig::new(&key);

        let encrypted = vault.encrypt(PLAINTEXT).expect("encryption failed");
        let decrypted = vault.decrypt(&encrypted).expect("decryption failed");

        assert_eq!(decrypted.as_bytes(), PLAINTEXT);
    }

    #[test]
    fn works_with_custom_tag() {
        let key = generate_key();
        let vault = Vault::new(&key).with_tag("Custom.Tag.V1");

        let encrypted = vault.encrypt(PLAINTEXT).expect("encryption failed");
        let decrypted = vault.decrypt(&encrypted).expect("decryption failed");

        assert_eq!(decrypted.as_bytes(), PLAINTEXT);
    }

    #[test]
    fn works_with_custom_aad() {
        let key = generate_key();
        let vault: VaultWithConfig<DefaultIvLength> =
            VaultWithConfig::new(&key).with_aad("Custom AAD");

        let encrypted = vault.encrypt(PLAINTEXT).expect("encryption failed");
        let decrypted = vault.decrypt(&encrypted).expect("decryption failed");

        assert_eq!(decrypted.as_bytes(), PLAINTEXT);
    }

    #[test]
    fn decryption_fails_with_wrong_tag() {
        let key = generate_key();
        let vault_1 = Vault::new(&key).with_tag("Tag.V1");
        let vault_2 = Vault::new(&key).with_tag("Tag.V2");

        let encrypted = vault_1.encrypt(PLAINTEXT).expect("encryption failed");
        assert!(vault_2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn decryption_fails_with_wrong_aad() {
        let key = generate_key();
        let vault_1 = Vault::new(&key).with_aad("AAD.V1");
        let vault_2 = Vault::new(&key).with_aad("AAD.V2");

        let encrypted = vault_1.encrypt(PLAINTEXT).expect("encryption failed");
        assert!(vault_2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn decryption_fails_with_invalid_ciphertext() {
        let key = generate_key();
        let vault = Vault::new(&key);

        let invalid_ciphertext = b"Invalid data";
        assert!(vault.decrypt(invalid_ciphertext).is_err());
    }
}
