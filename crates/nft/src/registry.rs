//! # Issuer Registry
//!
//! On-chain registry for authorized document issuers.
//! Only registered issuers can mint certified document NFTs.
//!
//! ## Security Model
//!
//! - Prevents unauthorized entities from minting fake certifications
//! - Each issuer has a verified domain and metadata
//! - Issuers can be suspended or revoked
//! - All issuer changes are recorded on-chain

use serde::{Deserialize, Serialize};
use sumchain_primitives::Address;

/// Issuer status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IssuerStatus {
    /// Issuer is active and can mint documents
    Active = 0,
    /// Issuer is suspended (temporary)
    Suspended = 1,
    /// Issuer is revoked (permanent)
    Revoked = 2,
}

impl IssuerStatus {
    /// Check if issuer can mint documents
    pub fn can_mint(&self) -> bool {
        matches!(self, IssuerStatus::Active)
    }

    /// Convert from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(IssuerStatus::Active),
            1 => Some(IssuerStatus::Suspended),
            2 => Some(IssuerStatus::Revoked),
            _ => None,
        }
    }
}

/// Registered issuer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredIssuer {
    /// Issuer's address (signing key)
    pub address: Address,
    /// Official name of the issuing organization
    pub name: String,
    /// Verified domain (e.g., "university.edu")
    pub domain: String,
    /// Organization type/category
    pub org_type: IssuerOrgType,
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: String,
    /// Current status
    pub status: IssuerStatus,
    /// Document types this issuer can mint
    pub allowed_doc_types: Vec<String>,
    /// When the issuer was registered (timestamp ms)
    pub registered_at: u64,
    /// When the issuer was last updated (timestamp ms)
    pub updated_at: u64,
    /// Registration expiry (0 = no expiry)
    pub expires_at: u64,
    /// Additional metadata (JSON)
    pub metadata: Option<String>,
}

impl RegisteredIssuer {
    /// Create a new registered issuer
    pub fn new(
        address: Address,
        name: String,
        domain: String,
        org_type: IssuerOrgType,
        country_code: String,
        allowed_doc_types: Vec<String>,
        timestamp: u64,
    ) -> Self {
        Self {
            address,
            name,
            domain,
            org_type,
            country_code,
            status: IssuerStatus::Active,
            allowed_doc_types,
            registered_at: timestamp,
            updated_at: timestamp,
            expires_at: 0,
            metadata: None,
        }
    }

    /// Check if this issuer can mint a specific document type
    pub fn can_mint_doc_type(&self, doc_type: &str) -> bool {
        if !self.status.can_mint() {
            return false;
        }

        // Empty list means all types allowed
        if self.allowed_doc_types.is_empty() {
            return true;
        }

        self.allowed_doc_types.iter().any(|t| t == doc_type || t == "*")
    }

    /// Check if issuer registration has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expires_at > 0 && current_time > self.expires_at
    }

    /// Check if issuer can mint documents at the given time
    pub fn can_mint_at(&self, current_time: u64) -> bool {
        self.status.can_mint() && !self.is_expired(current_time)
    }

    /// Suspend the issuer
    pub fn suspend(&mut self, timestamp: u64) {
        self.status = IssuerStatus::Suspended;
        self.updated_at = timestamp;
    }

    /// Reactivate the issuer
    pub fn reactivate(&mut self, timestamp: u64) {
        if self.status == IssuerStatus::Suspended {
            self.status = IssuerStatus::Active;
            self.updated_at = timestamp;
        }
    }

    /// Revoke the issuer permanently
    pub fn revoke(&mut self, timestamp: u64) {
        self.status = IssuerStatus::Revoked;
        self.updated_at = timestamp;
    }
}

/// Organization type for issuers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IssuerOrgType {
    /// Educational institution
    Educational = 0,
    /// Government agency
    Government = 1,
    /// Healthcare organization
    Healthcare = 2,
    /// Corporate/business entity
    Corporate = 3,
    /// Non-profit organization
    NonProfit = 4,
    /// Professional certification body
    Certification = 5,
    /// Other organization type
    Other = 255,
}

impl IssuerOrgType {
    /// Convert from byte
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => IssuerOrgType::Educational,
            1 => IssuerOrgType::Government,
            2 => IssuerOrgType::Healthcare,
            3 => IssuerOrgType::Corporate,
            4 => IssuerOrgType::NonProfit,
            5 => IssuerOrgType::Certification,
            _ => IssuerOrgType::Other,
        }
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            IssuerOrgType::Educational => "Educational Institution",
            IssuerOrgType::Government => "Government Agency",
            IssuerOrgType::Healthcare => "Healthcare Organization",
            IssuerOrgType::Corporate => "Corporation",
            IssuerOrgType::NonProfit => "Non-Profit Organization",
            IssuerOrgType::Certification => "Certification Body",
            IssuerOrgType::Other => "Other",
        }
    }
}

/// Registry operation for registering/updating issuers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryOperation {
    /// Register a new issuer (requires governance approval)
    Register {
        issuer: RegisteredIssuer,
    },
    /// Update issuer metadata
    Update {
        address: Address,
        name: Option<String>,
        domain: Option<String>,
        allowed_doc_types: Option<Vec<String>>,
        metadata: Option<String>,
    },
    /// Suspend an issuer
    Suspend {
        address: Address,
        reason: String,
    },
    /// Reactivate a suspended issuer
    Reactivate {
        address: Address,
    },
    /// Permanently revoke an issuer
    Revoke {
        address: Address,
        reason: String,
    },
    /// Extend issuer registration
    Extend {
        address: Address,
        new_expiry: u64,
    },
}

/// Result of validating an issuer for document minting
#[derive(Debug, Clone)]
pub struct IssuerValidation {
    /// Whether the issuer is valid
    pub valid: bool,
    /// Error message if invalid
    pub error: Option<String>,
    /// The issuer if found and valid
    pub issuer: Option<RegisteredIssuer>,
}

impl IssuerValidation {
    /// Create a valid result
    pub fn valid(issuer: RegisteredIssuer) -> Self {
        Self {
            valid: true,
            error: None,
            issuer: Some(issuer),
        }
    }

    /// Create an invalid result with error
    pub fn invalid(error: impl Into<String>) -> Self {
        Self {
            valid: false,
            error: Some(error.into()),
            issuer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_issuer() -> RegisteredIssuer {
        RegisteredIssuer::new(
            Address::from_hex("0x0000000000000000000000000000000000000001").unwrap(),
            "Test University".to_string(),
            "test.edu".to_string(),
            IssuerOrgType::Educational,
            "US".to_string(),
            vec!["degree".to_string(), "certificate".to_string()],
            1000,
        )
    }

    #[test]
    fn test_issuer_creation() {
        let issuer = create_test_issuer();
        assert_eq!(issuer.name, "Test University");
        assert_eq!(issuer.status, IssuerStatus::Active);
        assert!(issuer.can_mint_doc_type("degree"));
        assert!(issuer.can_mint_doc_type("certificate"));
        assert!(!issuer.can_mint_doc_type("license"));
    }

    #[test]
    fn test_issuer_wildcard() {
        let mut issuer = create_test_issuer();
        issuer.allowed_doc_types = vec!["*".to_string()];
        assert!(issuer.can_mint_doc_type("anything"));
    }

    #[test]
    fn test_issuer_empty_allows_all() {
        let mut issuer = create_test_issuer();
        issuer.allowed_doc_types = vec![];
        assert!(issuer.can_mint_doc_type("anything"));
    }

    #[test]
    fn test_issuer_suspend_reactivate() {
        let mut issuer = create_test_issuer();
        assert!(issuer.can_mint_doc_type("degree"));

        issuer.suspend(2000);
        assert!(!issuer.can_mint_doc_type("degree"));
        assert_eq!(issuer.status, IssuerStatus::Suspended);

        issuer.reactivate(3000);
        assert!(issuer.can_mint_doc_type("degree"));
        assert_eq!(issuer.status, IssuerStatus::Active);
    }

    #[test]
    fn test_issuer_revoke() {
        let mut issuer = create_test_issuer();
        issuer.revoke(2000);
        assert!(!issuer.can_mint_doc_type("degree"));
        assert_eq!(issuer.status, IssuerStatus::Revoked);

        // Reactivate should not work on revoked issuers
        issuer.reactivate(3000);
        assert_eq!(issuer.status, IssuerStatus::Revoked);
    }

    #[test]
    fn test_issuer_expiry() {
        let mut issuer = create_test_issuer();
        issuer.expires_at = 5000;

        assert!(issuer.can_mint_at(4000));
        assert!(!issuer.can_mint_at(6000));
        assert!(issuer.is_expired(6000));
    }

    #[test]
    fn test_org_type() {
        assert_eq!(IssuerOrgType::Educational.name(), "Educational Institution");
        assert_eq!(IssuerOrgType::from_byte(0), IssuerOrgType::Educational);
        assert_eq!(IssuerOrgType::from_byte(100), IssuerOrgType::Other);
    }
}
