//! Cloak
//!
//! This library provides encryption and decryption using the AES-GCM (Galois/Counter Mode) algorithm.
//! It ensures data integrity and confidentiality while providing flexibility for various use cases.
//!
//! # Features
//!
//! - Simple and intuitive API for encrypting and decrypting data.
//! - Support for customizable tags, Additional Authenticated Data (AAD), and Initialization Vectors (IV).
//! - Secure default settings to avoid common cryptographic pitfalls.
//! - Compatible with other implementations, such as Elixir's Cloak library.
//! - Error handling with detailed, meaningful messages.

mod tag;

use crate::tag::{TagDecoder, TagEncoder};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use thiserror::Error;

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
/// let key = cloak::generate_key();
/// println!("Generated key: {:?}", key);
/// ```
pub fn generate_key() -> Vec<u8> {
    Aes256Gcm::generate_key(OsRng).to_vec()
}

/// Vault provides methods for encrypting and decrypting data using the AES-GCM algorithm.
///
/// This struct supports customizable tags, Initialization Vectors (IV), and Additional Authenticated Data (AAD).
pub struct Vault {
    cipher: Aes256Gcm,
    tag: String,
}

impl Vault {
    /// Creates a new `Vault` instance.
    ///
    /// # Arguments
    ///
    /// * `key` - A byte slice representing the encryption key (32 bytes for AES-256).
    /// * `tag` - A string that represents a version or identifier for the cipher.
    ///
    /// # Returns
    ///
    /// A new `Vault` instance.
    ///
    /// # Example
    ///
    /// ```
    /// use cloak::Vault;
    ///
    /// let key = [0u8; 32]; // 256-bit key for AES-256
    /// let vault = Vault::new(&key, "AES.GCM.V1");
    /// ```
    pub fn new(key: &[u8], tag: &str) -> Self {
        Self {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)),
            tag: tag.to_string(),
        }
    }

    /// Encrypts the provided plaintext.
    ///
    /// Generates a random 96-bit (12-byte) Initialization Vector (IV) for each encryption.
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
    /// use cloak::{Vault, generate_key};
    ///
    /// let key = generate_key();
    /// let vault = Vault::new(&key, "AES.GCM.V1");
    ///
    /// let encrypted = vault.encrypt(b"Hello, world!").unwrap();
    /// ```
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // Generate a random 96-bit IV (12 bytes) to match the Elixir Cloak configuration
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);

        // Use the full 12-byte IV as the nonce
        let nonce = Nonce::from_slice(&iv); // Use the full 12-byte IV
        let aad = b"AES256GCM"; // Additional Authenticated Data

        // Encrypt the plaintext with AAD
        let ciphertext_with_tag = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Encrypt)?;

        // Split ciphertext and authentication tag
        let (ciphertext, ciphertag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

        // Encode the tag using TagEncoder
        let encoded_tag = TagEncoder::encode(self.tag.as_bytes());

        // Concatenate Encoded Tag, IV, Ciphertag, and Ciphertext
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&encoded_tag); // Encoded Tag
        encoded.extend_from_slice(&iv); // 12-byte IV
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
    /// use cloak::{Vault, generate_key};
    ///
    /// let key = generate_key();
    /// let vault = Vault::new(&key, "AES.GCM.V1");
    ///
    /// let encrypted = vault.encrypt(b"Hello, world!").unwrap();
    /// let decrypted = vault.decrypt(&encrypted).unwrap();
    /// assert_eq!(decrypted.as_bytes(), b"Hello, world!");
    /// ```
    pub fn decrypt(&self, encrypted_payload: &[u8]) -> Result<String, Error> {
        // Decode the tag using TagDecoder
        let (tag, remainder) =
            TagDecoder::decode(encrypted_payload).map_err(|_| Error::UnsupportedVersion)?;
        if tag != self.tag.as_bytes() {
            return Err(Error::UnsupportedTag);
        }

        // Extract IV, Ciphertag, and Ciphertext
        let iv = &remainder[..12]; // Full 12-byte IV
        let ciphertag = &remainder[12..28]; // 16-byte Ciphertag
        let ciphertext = &remainder[28..]; // Remaining is ciphertext

        // Combine ciphertext and ciphertag for decryption
        let mut combined_ciphertext = Vec::new();
        combined_ciphertext.extend_from_slice(ciphertext);
        combined_ciphertext.extend_from_slice(ciphertag); // Append the tag for decryption

        // Use the full 12-byte IV as the nonce
        let nonce = Nonce::from_slice(&iv); // Use the full 12-byte IV
        let aad = b"AES256GCM"; // Additional Authenticated Data

        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &combined_ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Decrypt)?;

        // Return the decrypted data as a UTF-8 string
        Ok(String::from_utf8(plaintext)?)
    }
}
