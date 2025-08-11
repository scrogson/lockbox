use lockbox::{IvLength16, VaultWithConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = lockbox::generate_key();
    let vault: VaultWithConfig<IvLength16> = VaultWithConfig::new(&key)
        .with_tag("Custom.Tag.V1")
        .with_aad("Custom.AAD");

    let plaintext = b"plaintext";
    println!("Plaintext: {}", std::str::from_utf8(plaintext)?);

    // Encrypt the plaintext
    let encrypted = vault.encrypt(plaintext)?;
    println!("Encrypted: {}", hex::encode_upper(&encrypted));

    // Decrypt the ciphertext
    let decrypted = vault.decrypt(&encrypted)?;
    println!("Decrypted: {decrypted}");

    assert_eq!(&decrypted.as_bytes(), plaintext);

    Ok(())
}
