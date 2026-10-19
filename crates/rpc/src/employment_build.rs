//! Conversion from the `employment_buildTransaction` request shape to
//! [`EmploymentBuildOp`], shared by the node's builder and the `sumchain
//! employment` client commands.
//!
//! Both sides run the same conversion and then the same
//! [`build_employment_tx`](sumchain_primitives::employment_build::build_employment_tx),
//! so for the same explicit request they produce the same bytes. The node's
//! builder resolves omitted fields from its own state first; a client that
//! compares the builder's signing hash with its own passes every field
//! explicitly (see [`make_explicit`]).
//!
//! Error messages name the field and the rule, never the value supplied.

use sumchain_primitives::employment::{EmploymentIssuerClass, EmploymentType};
use sumchain_primitives::employment_build::{
    derive_revocation_ref, EmploymentBuildOp, EmploymentCredentialInput,
};
use sumchain_primitives::Address;

use crate::docclass_build::{parse_address, parse_hex32};
use crate::types::EmploymentBuildOpRequest;

/// Values used when the request omits them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmploymentRequestDefaults {
    /// Milliseconds; used for an omitted `registered_at`, `created_at` or
    /// `revoked_at`.
    pub now_ms: u64,
    /// Used for an omitted `registered_at_height`.
    pub latest_height: u64,
    /// The sender's registered display name and issuer class, if it has a
    /// record.
    pub issuer: Option<(String, EmploymentIssuerClass)>,
    /// For a revocation, the stored credential's employee, if it exists.
    pub employee_address: Option<Address>,
}

/// Parse an issuer class by the names `employment_getIssuer` reports.
pub fn parse_issuer_class(field: &str, s: &str) -> Result<EmploymentIssuerClass, String> {
    Ok(match s {
        "GovernmentLabor" => EmploymentIssuerClass::GovernmentLabor,
        "PayrollProcessor" => EmploymentIssuerClass::PayrollProcessor,
        "RegulatedHrPlatform" => EmploymentIssuerClass::RegulatedHrPlatform,
        "Peo" => EmploymentIssuerClass::Peo,
        "Employer" => EmploymentIssuerClass::Employer,
        "HrPlatform" => EmploymentIssuerClass::HrPlatform,
        "StaffingAgency" => EmploymentIssuerClass::StaffingAgency,
        "GigPlatform" => EmploymentIssuerClass::GigPlatform,
        _ => return Err(format!("{field}: unknown issuer class")),
    })
}

/// The name [`parse_issuer_class`] accepts for `class`.
pub fn issuer_class_name(class: EmploymentIssuerClass) -> &'static str {
    match class {
        EmploymentIssuerClass::GovernmentLabor => "GovernmentLabor",
        EmploymentIssuerClass::PayrollProcessor => "PayrollProcessor",
        EmploymentIssuerClass::RegulatedHrPlatform => "RegulatedHrPlatform",
        EmploymentIssuerClass::Peo => "Peo",
        EmploymentIssuerClass::Employer => "Employer",
        EmploymentIssuerClass::HrPlatform => "HrPlatform",
        EmploymentIssuerClass::StaffingAgency => "StaffingAgency",
        EmploymentIssuerClass::GigPlatform => "GigPlatform",
    }
}

fn employment_type(s: &str) -> Result<EmploymentType, String> {
    Ok(match s {
        "FullTime" => EmploymentType::FullTime,
        "PartTime" => EmploymentType::PartTime,
        "Contract" => EmploymentType::Contract,
        "Temporary" => EmploymentType::Temporary,
        "Internship" => EmploymentType::Internship,
        "Freelance" => EmploymentType::Freelance,
        "Gig" => EmploymentType::Gig,
        _ => return Err("employment_type: unknown employment type".to_string()),
    })
}

/// Convert a request operation into the builder's explicit operation.
pub fn op_from_request(
    op: &EmploymentBuildOpRequest,
    defaults: &EmploymentRequestDefaults,
) -> Result<EmploymentBuildOp, String> {
    Ok(match op {
        EmploymentBuildOpRequest::RegisterIssuer {
            issuer_class,
            display_name,
            issuer_commitment,
            jurisdiction_code,
            policy_id,
            registered_at_height,
            registered_at,
        } => EmploymentBuildOp::RegisterIssuer {
            issuer_class: parse_issuer_class("issuer_class", issuer_class)?,
            display_name: display_name.clone(),
            issuer_commitment: parse_hex32("issuer_commitment", issuer_commitment)?,
            jurisdiction_code: jurisdiction_code.clone(),
            policy_id: parse_hex32("policy_id", policy_id)?,
            registered_at_height: registered_at_height.unwrap_or(defaults.latest_height),
            registered_at: registered_at.unwrap_or(defaults.now_ms),
        },
        EmploymentBuildOpRequest::CreateEmployment {
            employee_address,
            employee_ref,
            employer_ref,
            tenure_commitment,
            role_commitment,
            employment_type: kind,
            valid_from,
            expiry,
            policy_id,
            issuer_name,
            issuer_class,
            created_at,
        } => {
            let issuer_name = match issuer_name {
                Some(name) => name.clone(),
                None => defaults
                    .issuer
                    .as_ref()
                    .map(|(name, _)| name.clone())
                    .ok_or_else(|| {
                        "issuer_name: required when the sender has no issuer record".to_string()
                    })?,
            };
            let issuer_class = match issuer_class {
                Some(class) => parse_issuer_class("issuer_class", class)?,
                None => defaults.issuer.as_ref().map(|(_, c)| *c).ok_or_else(|| {
                    "issuer_class: required when the sender has no issuer record".to_string()
                })?,
            };
            EmploymentBuildOp::CreateEmployment(EmploymentCredentialInput {
                employee_address: parse_address("employee_address", employee_address)?,
                employee_ref: parse_hex32("employee_ref", employee_ref)?,
                employer_ref: parse_hex32("employer_ref", employer_ref)?,
                tenure_commitment: parse_hex32("tenure_commitment", tenure_commitment)?,
                role_commitment: match role_commitment {
                    Some(r) => Some(parse_hex32("role_commitment", r)?),
                    None => None,
                },
                employment_type: employment_type(kind)?,
                valid_from: *valid_from,
                expiry: *expiry,
                policy_id: parse_hex32("policy_id", policy_id)?,
                issuer_name,
                issuer_class,
                created_at: created_at.unwrap_or(defaults.now_ms),
            })
        }
        EmploymentBuildOpRequest::RevokeEmployment {
            employment_id,
            employee_address,
            revocation_ref,
            revoked_at,
            reason,
        } => {
            let employment_id = parse_hex32("employment_id", employment_id)?;
            let employee_address = match employee_address {
                Some(a) => parse_address("employee_address", a)?,
                None => defaults.employee_address.ok_or_else(|| {
                    "employee_address: required when the credential is not on this node".to_string()
                })?,
            };
            let revocation_ref = match revocation_ref {
                Some(r) => parse_hex32("revocation_ref", r)?,
                None => derive_revocation_ref(
                    &employment_id,
                    revoked_at.unwrap_or(defaults.now_ms),
                    reason.as_deref(),
                ),
            };
            EmploymentBuildOp::RevokeEmployment {
                employment_id,
                employee_address,
                revocation_ref,
            }
        }
    })
}

/// The same operation with every field the node would default made explicit,
/// so a builder given it has nothing left to choose.
///
/// A revocation's reference is derived here, locally, and `revoked_at` and
/// `reason` are then dropped: the reason text is hashed on the client and never
/// sent to the node.
pub fn make_explicit(
    op: &EmploymentBuildOpRequest,
    defaults: &EmploymentRequestDefaults,
) -> Result<EmploymentBuildOpRequest, String> {
    let mut op = op.clone();
    match &mut op {
        EmploymentBuildOpRequest::RegisterIssuer {
            registered_at_height,
            registered_at,
            ..
        } => {
            registered_at_height.get_or_insert(defaults.latest_height);
            registered_at.get_or_insert(defaults.now_ms);
        }
        EmploymentBuildOpRequest::CreateEmployment {
            issuer_name,
            issuer_class,
            created_at,
            ..
        } => {
            if issuer_name.is_none() || issuer_class.is_none() {
                let (name, class) = defaults.issuer.clone().ok_or_else(|| {
                    "issuer_name: required when the sender has no issuer record".to_string()
                })?;
                issuer_name.get_or_insert(name);
                issuer_class.get_or_insert_with(|| issuer_class_name(class).to_string());
            }
            created_at.get_or_insert(defaults.now_ms);
        }
        EmploymentBuildOpRequest::RevokeEmployment {
            employment_id,
            employee_address,
            revocation_ref,
            revoked_at,
            reason,
        } => {
            if employee_address.is_none() {
                *employee_address = Some(
                    defaults
                        .employee_address
                        .ok_or_else(|| {
                            "employee_address: required when the credential is not on this node"
                                .to_string()
                        })?
                        .to_base58(),
                );
            }
            if revocation_ref.is_none() {
                let id = parse_hex32("employment_id", employment_id)?;
                let r = derive_revocation_ref(
                    &id,
                    revoked_at.unwrap_or(defaults.now_ms),
                    reason.as_deref(),
                );
                *revocation_ref = Some(hex::encode(r));
            }
            *revoked_at = None;
            *reason = None;
        }
    }
    Ok(op)
}

/// Whether converting `op` needs the sender's issuer record.
pub fn needs_issuer_record(op: &EmploymentBuildOpRequest) -> bool {
    matches!(
        op,
        EmploymentBuildOpRequest::CreateEmployment {
            issuer_name: None,
            ..
        } | EmploymentBuildOpRequest::CreateEmployment {
            issuer_class: None,
            ..
        }
    )
}

/// The employment id whose stored credential converting `op` needs, if any.
pub fn needs_credential(op: &EmploymentBuildOpRequest) -> Option<&str> {
    match op {
        EmploymentBuildOpRequest::RevokeEmployment {
            employment_id,
            employee_address: None,
            ..
        } => Some(employment_id.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revoke(reason: Option<&str>) -> EmploymentBuildOpRequest {
        EmploymentBuildOpRequest::RevokeEmployment {
            employment_id: "07".repeat(32),
            employee_address: None,
            revocation_ref: None,
            revoked_at: None,
            reason: reason.map(str::to_string),
        }
    }

    #[test]
    fn errors_name_the_field_not_the_value() {
        let e = parse_issuer_class("issuer_class", "SecretLookingClass").unwrap_err();
        assert_eq!(e, "issuer_class: unknown issuer class");
        let e = employment_type("SecretLookingType").unwrap_err();
        assert_eq!(e, "employment_type: unknown employment type");
        let e = op_from_request(
            &EmploymentBuildOpRequest::RevokeEmployment {
                employment_id: "0xzz99secretlooking".into(),
                employee_address: Some("x".into()),
                revocation_ref: None,
                revoked_at: None,
                reason: None,
            },
            &EmploymentRequestDefaults::default(),
        )
        .unwrap_err();
        assert_eq!(e, "employment_id: expected 32 bytes of hex");
    }

    #[test]
    fn every_issuer_class_name_round_trips() {
        for class in [
            EmploymentIssuerClass::GovernmentLabor,
            EmploymentIssuerClass::PayrollProcessor,
            EmploymentIssuerClass::RegulatedHrPlatform,
            EmploymentIssuerClass::Peo,
            EmploymentIssuerClass::Employer,
            EmploymentIssuerClass::HrPlatform,
            EmploymentIssuerClass::StaffingAgency,
            EmploymentIssuerClass::GigPlatform,
        ] {
            let name = issuer_class_name(class);
            assert_eq!(parse_issuer_class("c", name).unwrap(), class);
            assert_eq!(
                name,
                format!("{class:?}"),
                "the name employment_getIssuer reports"
            );
        }
    }

    #[test]
    fn a_revocation_is_made_explicit_and_its_reason_is_not_kept() {
        let d = EmploymentRequestDefaults {
            now_ms: 5,
            employee_address: Some(Address::new([0x22; 20])),
            ..Default::default()
        };
        let explicit = make_explicit(&revoke(Some("ended")), &d).unwrap();
        let EmploymentBuildOpRequest::RevokeEmployment {
            employee_address,
            revocation_ref,
            revoked_at,
            reason,
            ..
        } = &explicit
        else {
            unreachable!()
        };
        assert_eq!(revoked_at, &None);
        assert_eq!(reason, &None, "the reason text is not sent on");
        assert_eq!(
            employee_address.as_deref(),
            Some(Address::new([0x22; 20]).to_base58().as_str())
        );
        assert_eq!(
            revocation_ref.as_deref(),
            Some(hex::encode(derive_revocation_ref(&[7; 32], 5, Some("ended"))).as_str())
        );
        // The explicit request converts to the same operation as the original.
        assert_eq!(
            op_from_request(&explicit, &EmploymentRequestDefaults::default()).unwrap(),
            op_from_request(&revoke(Some("ended")), &d).unwrap()
        );
    }

    #[test]
    fn a_create_without_an_issuer_record_needs_its_name_and_class() {
        let op = EmploymentBuildOpRequest::CreateEmployment {
            employee_address: Address::new([0x22; 20]).to_base58(),
            employee_ref: "31".repeat(32),
            employer_ref: "32".repeat(32),
            tenure_commitment: "33".repeat(32),
            role_commitment: None,
            employment_type: "FullTime".into(),
            valid_from: 1,
            expiry: 0,
            policy_id: "35".repeat(32),
            issuer_name: None,
            issuer_class: None,
            created_at: None,
        };
        assert!(needs_issuer_record(&op));
        let e = make_explicit(&op, &EmploymentRequestDefaults::default()).unwrap_err();
        assert!(e.starts_with("issuer_name:"), "{e}");
        let d = EmploymentRequestDefaults {
            now_ms: 9,
            issuer: Some((
                "Example Employer Inc".into(),
                EmploymentIssuerClass::HrPlatform,
            )),
            ..Default::default()
        };
        let explicit = make_explicit(&op, &d).unwrap();
        assert!(!needs_issuer_record(&explicit));
        assert_eq!(
            op_from_request(&explicit, &EmploymentRequestDefaults::default()).unwrap(),
            op_from_request(&op, &d).unwrap()
        );
    }

    #[test]
    fn explicit_fills_only_what_is_missing() {
        let d = EmploymentRequestDefaults {
            now_ms: 5,
            latest_height: 40,
            ..Default::default()
        };
        let op = |h: Option<u64>, t: Option<u64>| EmploymentBuildOpRequest::RegisterIssuer {
            issuer_class: "Employer".into(),
            display_name: "Example Employer Inc".into(),
            issuer_commitment: "41".repeat(32),
            jurisdiction_code: "US".into(),
            policy_id: "42".repeat(32),
            registered_at_height: h,
            registered_at: t,
        };
        assert_eq!(
            make_explicit(&op(Some(3), Some(9)), &d).unwrap(),
            op(Some(3), Some(9))
        );
        assert_eq!(
            make_explicit(&op(None, None), &d).unwrap(),
            op(Some(40), Some(5))
        );
    }
}
