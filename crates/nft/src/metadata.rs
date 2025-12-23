//! NFT Metadata types
//!
//! Supports both general NFT metadata and specialized document certification metadata.
//! All metadata is validated against strict byte limits to prevent state bloat attacks.

use serde::{Deserialize, Serialize};
use sumchain_primitives::{Address, Hash, Timestamp};

/// Maximum length for metadata name field (in bytes)
pub const MAX_NAME_BYTES: usize = 256;

/// Maximum length for metadata description field (in bytes)
pub const MAX_DESCRIPTION_BYTES: usize = 2048;

/// Maximum length for URI fields (image, animation_url, external_url) (in bytes)
pub const MAX_URI_BYTES: usize = 512;

/// Maximum number of attributes per token
pub const MAX_ATTRIBUTES: usize = 32;

/// Maximum length for attribute trait_type (in bytes)
pub const MAX_ATTRIBUTE_NAME_BYTES: usize = 64;

/// Maximum length for attribute string value (in bytes)
pub const MAX_ATTRIBUTE_VALUE_BYTES: usize = 256;

/// Metadata validation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataValidationError {
    /// Name exceeds maximum length
    NameTooLong { max: usize, actual: usize },
    /// Description exceeds maximum length
    DescriptionTooLong { max: usize, actual: usize },
    /// Image URI exceeds maximum length
    ImageUriTooLong { max: usize, actual: usize },
    /// Animation URL exceeds maximum length
    AnimationUrlTooLong { max: usize, actual: usize },
    /// External URL exceeds maximum length
    ExternalUrlTooLong { max: usize, actual: usize },
    /// Too many attributes
    TooManyAttributes { max: usize, actual: usize },
    /// Attribute trait name too long
    AttributeNameTooLong { index: usize, max: usize, actual: usize },
    /// Attribute value too long
    AttributeValueTooLong { index: usize, max: usize, actual: usize },
}

impl std::fmt::Display for MetadataValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameTooLong { max, actual } => {
                write!(f, "Name too long: {} bytes (max: {})", actual, max)
            }
            Self::DescriptionTooLong { max, actual } => {
                write!(f, "Description too long: {} bytes (max: {})", actual, max)
            }
            Self::ImageUriTooLong { max, actual } => {
                write!(f, "Image URI too long: {} bytes (max: {})", actual, max)
            }
            Self::AnimationUrlTooLong { max, actual } => {
                write!(f, "Animation URL too long: {} bytes (max: {})", actual, max)
            }
            Self::ExternalUrlTooLong { max, actual } => {
                write!(f, "External URL too long: {} bytes (max: {})", actual, max)
            }
            Self::TooManyAttributes { max, actual } => {
                write!(f, "Too many attributes: {} (max: {})", actual, max)
            }
            Self::AttributeNameTooLong { index, max, actual } => {
                write!(f, "Attribute[{}] name too long: {} bytes (max: {})", index, actual, max)
            }
            Self::AttributeValueTooLong { index, max, actual } => {
                write!(f, "Attribute[{}] value too long: {} bytes (max: {})", index, actual, max)
            }
        }
    }
}

impl std::error::Error for MetadataValidationError {}

/// Type of metadata storage
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetadataType {
    /// Metadata stored directly on-chain
    OnChain,
    /// Metadata stored on IPFS (content-addressed)
    Ipfs,
    /// Metadata at an external URL
    External,
}

/// General NFT metadata (ERC-721 compatible)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Asset name
    pub name: String,

    /// Asset description
    pub description: String,

    /// Image URI (IPFS or URL)
    pub image: Option<String>,

    /// Animation/video URI
    pub animation_url: Option<String>,

    /// External link
    pub external_url: Option<String>,

    /// Arbitrary attributes
    pub attributes: Vec<Attribute>,

    /// Content hash for verification
    pub content_hash: Option<Hash>,

    /// Where metadata is stored
    pub storage_type: MetadataType,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            image: None,
            animation_url: None,
            external_url: None,
            attributes: Vec::new(),
            content_hash: None,
            storage_type: MetadataType::OnChain,
        }
    }
}

impl Metadata {
    /// Create metadata with just name and description
    pub fn simple(name: String, description: String) -> Self {
        Self {
            name,
            description,
            ..Default::default()
        }
    }

    /// Create metadata with IPFS content hash
    pub fn with_ipfs(name: String, description: String, ipfs_cid: String) -> Self {
        Self {
            name,
            description,
            image: Some(format!("ipfs://{}", ipfs_cid)),
            storage_type: MetadataType::Ipfs,
            ..Default::default()
        }
    }

    /// Add an attribute
    pub fn add_attribute(mut self, trait_type: &str, value: &str) -> Self {
        self.attributes.push(Attribute {
            trait_type: trait_type.to_string(),
            value: AttributeValue::String(value.to_string()),
            display_type: None,
        });
        self
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Metadata serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Metadata JSON serialization should not fail")
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Compute content hash
    pub fn compute_hash(&self) -> Hash {
        Hash::hash(&self.to_bytes())
    }

    /// Validate metadata against size limits to prevent state bloat attacks.
    /// Returns Ok(()) if valid, or Err with the first validation error found.
    pub fn validate(&self) -> Result<(), MetadataValidationError> {
        // Validate name
        if self.name.len() > MAX_NAME_BYTES {
            return Err(MetadataValidationError::NameTooLong {
                max: MAX_NAME_BYTES,
                actual: self.name.len(),
            });
        }

        // Validate description
        if self.description.len() > MAX_DESCRIPTION_BYTES {
            return Err(MetadataValidationError::DescriptionTooLong {
                max: MAX_DESCRIPTION_BYTES,
                actual: self.description.len(),
            });
        }

        // Validate image URI
        if let Some(ref image) = self.image {
            if image.len() > MAX_URI_BYTES {
                return Err(MetadataValidationError::ImageUriTooLong {
                    max: MAX_URI_BYTES,
                    actual: image.len(),
                });
            }
        }

        // Validate animation URL
        if let Some(ref url) = self.animation_url {
            if url.len() > MAX_URI_BYTES {
                return Err(MetadataValidationError::AnimationUrlTooLong {
                    max: MAX_URI_BYTES,
                    actual: url.len(),
                });
            }
        }

        // Validate external URL
        if let Some(ref url) = self.external_url {
            if url.len() > MAX_URI_BYTES {
                return Err(MetadataValidationError::ExternalUrlTooLong {
                    max: MAX_URI_BYTES,
                    actual: url.len(),
                });
            }
        }

        // Validate attribute count
        if self.attributes.len() > MAX_ATTRIBUTES {
            return Err(MetadataValidationError::TooManyAttributes {
                max: MAX_ATTRIBUTES,
                actual: self.attributes.len(),
            });
        }

        // Validate individual attributes
        for (i, attr) in self.attributes.iter().enumerate() {
            if attr.trait_type.len() > MAX_ATTRIBUTE_NAME_BYTES {
                return Err(MetadataValidationError::AttributeNameTooLong {
                    index: i,
                    max: MAX_ATTRIBUTE_NAME_BYTES,
                    actual: attr.trait_type.len(),
                });
            }

            // Check string value length
            if let AttributeValue::String(ref s) = attr.value {
                if s.len() > MAX_ATTRIBUTE_VALUE_BYTES {
                    return Err(MetadataValidationError::AttributeValueTooLong {
                        index: i,
                        max: MAX_ATTRIBUTE_VALUE_BYTES,
                        actual: s.len(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate and return self, for builder-pattern chaining
    pub fn validated(self) -> Result<Self, MetadataValidationError> {
        self.validate()?;
        Ok(self)
    }
}

/// NFT attribute (ERC-721 metadata standard)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    /// Trait name
    pub trait_type: String,

    /// Trait value
    pub value: AttributeValue,

    /// Display hint
    pub display_type: Option<String>,
}

/// Attribute value types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    String(String),
    Number(i64),
    Float(f64),
    Bool(bool),
}

/// Specialized metadata for certified documents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    /// Base metadata
    pub base: Metadata,

    /// Document type (e.g., "degree", "certificate", "license")
    pub document_type: String,

    /// Issuing organization
    pub issuer: IssuerInfo,

    /// Subject of the document (who it was issued to)
    pub subject: SubjectInfo,

    /// Issue date
    pub issued_at: Timestamp,

    /// Expiration date (if applicable)
    pub expires_at: Option<Timestamp>,

    /// Document serial/reference number
    pub serial_number: Option<String>,

    /// Cryptographic signature from issuer (hex-encoded)
    pub issuer_signature: Option<String>,

    /// Hash of the original document (for verification)
    pub document_hash: Hash,

    /// Additional fields specific to document type
    pub custom_fields: Vec<DocumentField>,
}

impl DocumentMetadata {
    /// Create new document metadata
    pub fn new(
        name: String,
        description: String,
        document_type: String,
        issuer: IssuerInfo,
        subject: SubjectInfo,
        document_hash: Hash,
        issued_at: Timestamp,
    ) -> Self {
        Self {
            base: Metadata::simple(name, description),
            document_type,
            issuer,
            subject,
            issued_at,
            expires_at: None,
            serial_number: None,
            issuer_signature: None,
            document_hash,
            custom_fields: Vec::new(),
        }
    }

    /// Add a custom field
    pub fn add_field(mut self, key: &str, value: &str) -> Self {
        self.custom_fields.push(DocumentField {
            key: key.to_string(),
            value: value.to_string(),
        });
        self
    }

    /// Check if document is expired
    pub fn is_expired(&self, current_time: Timestamp) -> bool {
        if let Some(expires) = self.expires_at {
            current_time > expires
        } else {
            false
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("DocumentMetadata serialization should not fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Issuer information for certified documents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerInfo {
    /// Issuer's on-chain address
    pub address: Address,

    /// Organization name
    pub name: String,

    /// Organization identifier (e.g., registration number)
    pub identifier: Option<String>,

    /// Contact information
    pub contact: Option<String>,

    /// Website
    pub website: Option<String>,
}

impl IssuerInfo {
    /// Create issuer info with minimal fields
    pub fn new(address: Address, name: String) -> Self {
        Self {
            address,
            name,
            identifier: None,
            contact: None,
            website: None,
        }
    }
}

/// Subject information (recipient of the document)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectInfo {
    /// Subject's on-chain address
    pub address: Address,

    /// Subject's name (as appears on document)
    pub name: String,

    /// Subject identifier (e.g., student ID, license number)
    pub identifier: Option<String>,
}

impl SubjectInfo {
    /// Create subject info with minimal fields
    pub fn new(address: Address, name: String) -> Self {
        Self {
            address,
            name,
            identifier: None,
        }
    }
}

/// Custom document field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentField {
    pub key: String,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_creation() {
        let metadata = Metadata::simple("Test NFT".to_string(), "A test NFT".to_string())
            .add_attribute("rarity", "common")
            .add_attribute("level", "1");

        assert_eq!(metadata.name, "Test NFT");
        assert_eq!(metadata.attributes.len(), 2);
    }

    #[test]
    fn test_metadata_serialization() {
        let metadata = Metadata::simple("Test".to_string(), "Description".to_string());
        let bytes = metadata.to_bytes();
        let restored = Metadata::from_bytes(&bytes).unwrap();
        assert_eq!(metadata.name, restored.name);
    }

    #[test]
    fn test_document_metadata() {
        let issuer = IssuerInfo::new(
            Address::from_hex("0x0000000000000000000000000000000000000001").unwrap(),
            "Test University".to_string(),
        );
        let subject = SubjectInfo::new(
            Address::from_hex("0x0000000000000000000000000000000000000002").unwrap(),
            "John Doe".to_string(),
        );

        let doc = DocumentMetadata::new(
            "Bachelor's Degree".to_string(),
            "Bachelor of Science in Computer Science".to_string(),
            "degree".to_string(),
            issuer,
            subject,
            Hash::ZERO,
            1700000000000,
        )
        .add_field("major", "Computer Science")
        .add_field("graduation_year", "2024");

        assert_eq!(doc.document_type, "degree");
        assert_eq!(doc.custom_fields.len(), 2);
    }

    #[test]
    fn test_document_expiration() {
        let issuer = IssuerInfo::new(Address::ZERO, "Issuer".to_string());
        let subject = SubjectInfo::new(Address::ZERO, "Subject".to_string());

        let mut doc = DocumentMetadata::new(
            "License".to_string(),
            "Professional License".to_string(),
            "license".to_string(),
            issuer,
            subject,
            Hash::ZERO,
            1700000000000,
        );

        // No expiration
        assert!(!doc.is_expired(1800000000000));

        // With expiration
        doc.expires_at = Some(1750000000000);
        assert!(!doc.is_expired(1740000000000));
        assert!(doc.is_expired(1760000000000));
    }

    #[test]
    fn test_metadata_validation_valid() {
        let metadata = Metadata::simple("Test NFT".to_string(), "A test NFT".to_string())
            .add_attribute("rarity", "common")
            .add_attribute("level", "1");

        assert!(metadata.validate().is_ok());
    }

    #[test]
    fn test_metadata_validation_name_too_long() {
        let long_name = "x".repeat(MAX_NAME_BYTES + 1);
        let metadata = Metadata::simple(long_name, "Description".to_string());

        let result = metadata.validate();
        assert!(matches!(result, Err(MetadataValidationError::NameTooLong { .. })));
    }

    #[test]
    fn test_metadata_validation_description_too_long() {
        let long_desc = "x".repeat(MAX_DESCRIPTION_BYTES + 1);
        let metadata = Metadata::simple("Name".to_string(), long_desc);

        let result = metadata.validate();
        assert!(matches!(result, Err(MetadataValidationError::DescriptionTooLong { .. })));
    }

    #[test]
    fn test_metadata_validation_too_many_attributes() {
        let mut metadata = Metadata::simple("Name".to_string(), "Desc".to_string());
        for i in 0..MAX_ATTRIBUTES + 1 {
            metadata = metadata.add_attribute(&format!("attr{}", i), "value");
        }

        let result = metadata.validate();
        assert!(matches!(result, Err(MetadataValidationError::TooManyAttributes { .. })));
    }

    #[test]
    fn test_metadata_validation_attribute_name_too_long() {
        let long_attr_name = "x".repeat(MAX_ATTRIBUTE_NAME_BYTES + 1);
        let metadata = Metadata::simple("Name".to_string(), "Desc".to_string())
            .add_attribute(&long_attr_name, "value");

        let result = metadata.validate();
        assert!(matches!(result, Err(MetadataValidationError::AttributeNameTooLong { .. })));
    }

    #[test]
    fn test_metadata_validation_attribute_value_too_long() {
        let long_value = "x".repeat(MAX_ATTRIBUTE_VALUE_BYTES + 1);
        let metadata = Metadata::simple("Name".to_string(), "Desc".to_string())
            .add_attribute("attr", &long_value);

        let result = metadata.validate();
        assert!(matches!(result, Err(MetadataValidationError::AttributeValueTooLong { .. })));
    }

    #[test]
    fn test_metadata_validated_builder() {
        // Valid metadata
        let valid = Metadata::simple("Name".to_string(), "Desc".to_string())
            .validated();
        assert!(valid.is_ok());

        // Invalid metadata
        let long_name = "x".repeat(MAX_NAME_BYTES + 1);
        let invalid = Metadata::simple(long_name, "Desc".to_string())
            .validated();
        assert!(invalid.is_err());
    }
}
