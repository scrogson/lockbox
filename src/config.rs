pub(crate) const DEFAULT_TAG: &str = "AES.GCM.V1";
pub(crate) const DEFAULT_AAD: &str = "AES256GCM";

/// Configuration for the Vault.
///
/// Allows overriding default values for tag and AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultConfig {
    /// A string that represents a version or identifier for the cipher.
    /// Default is "AES.GCM.V1".
    pub tag: String,
    /// Additional Authenticated Data (AAD).
    /// Default is "AES256GCM".
    pub aad: String,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            tag: DEFAULT_TAG.into(),
            aad: DEFAULT_AAD.into(),
        }
    }
}
