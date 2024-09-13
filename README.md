# Cloak

`Cloak` is a Rust library that provides easy-to-use, secure, and efficient
encryption and decryption using the AES-GCM (Galois/Counter Mode) algorithm.

It ensures data integrity and confidentiality while offering flexibility for
various use cases.

## Features

- Simple and intuitive API for encrypting and decrypting data.
- Support for customizable tags, Additional Authenticated Data (AAD), and Initialization Vectors (IV).
- Secure default settings to avoid common cryptographic pitfalls.
- Compatible with other implementations, such as Elixir's Cloak library.
- Error handling with detailed, meaningful messages.

## Installation

To use `Cloak` in your Rust project, add the following to your `Cargo.toml`:

```toml
[dependencies]
cloak = "0.1"
```

## Getting Started

Here’s a quick example to get you started with `Cloak`:

```rust
use cloak::Vault;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random key
    // This is for demo purposes. In a real situation you'll want to
    // use a stable key.
    let key = cloak::generate_key();

    // Initialize a vault with the key and a tag
    let vault = Vault::new(&key, "AES.GCM.V1");

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
