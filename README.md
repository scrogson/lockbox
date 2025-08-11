# Lockbox

`Lockbox` is a Rust library that provides easy-to-use, secure, and efficient
encryption and decryption using the AES-GCM (Galois/Counter Mode) algorithm.

It ensures data integrity and confidentiality while offering flexibility for
various use cases.

## Features

- Simple and intuitive API for encrypting and decrypting data.
- Support for customizable tags, Additional Authenticated Data (AAD), and Initialization Vectors (IV).
- Secure default settings to avoid common cryptographic pitfalls.
- Error handling with detailed, meaningful messages.

## Installation

To use `Lockbox` in your Rust project, add the following to your `Cargo.toml`:

```toml
[dependencies]
lockbox = "0.1"
```

## Getting Started

Here’s a quick example to get you started with `Lockbox`:

```rust
use lockbox::Vault;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random key
    // This is for demo purposes. In a real situation you'll want to
    // use a stable key.
    let key = lockbox::generate_key();

    // Initialize a vault with the key
    let vault = Vault::new(&key);

    // Or with config options:
    let vault = Vault::new(&key)
        .with_tag("Custom.Tag.V1")
        .with_aad("Custom.AAD");

    // Encrypt some plaintext
    let plaintext = b"Hello, secure world!";
    let encrypted = vault.encrypt(plaintext)?;
    println!("Encrypted: {:?}", encrypted);

    // Decrypt the ciphertext
    let decrypted = vault.decrypt(&encrypted)?;
    println!("Decrypted: {}", String::from_utf8(decrypted)?);

    Ok(())
}
```
