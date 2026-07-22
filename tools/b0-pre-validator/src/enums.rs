//! Frozen enums (plan §2).
//!
//! Every discriminant maps to an explicit literal in both directions. Nothing
//! relies on Rust declaration order or `as` casting: `to_repr` matches each
//! variant to its frozen value, and `from_repr` matches each value back, with
//! reserved values rejected distinctly from unknown ones.

use crate::codec::DecodeError;

macro_rules! frozen_enum {
    (
        $(#[$meta:meta])*
        $name:ident : $repr:ty {
            $( $variant:ident = $val:literal ),+ $(,)?
        }
        $( reserved { $( $rvariant:ident = $rval:literal ),+ $(,)? } )?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
        pub enum $name {
            $( $variant ),+
        }

        impl $name {
            /// The frozen wire discriminant for this variant.
            pub const fn to_repr(self) -> $repr {
                match self {
                    $( $name::$variant => $val ),+
                }
            }

            /// Decode a wire discriminant, rejecting reserved and unknown values.
            pub fn from_repr(v: $repr) -> Result<Self, DecodeError> {
                match v {
                    $( $val => Ok($name::$variant), )+
                    $( $( $rval => Err(DecodeError::ReservedEnum {
                        name: stringify!($name), value: v as u64,
                    }), )+ )?
                    _ => Err(DecodeError::BadEnum { name: stringify!($name), value: v as u64 }),
                }
            }

            /// Every defined (non-reserved) variant, for exhaustive testing.
            pub const ALL: &'static [$name] = &[ $( $name::$variant ),+ ];

            /// Bit width of the wire discriminant (8 or 16).
            pub const REPR_BITS: u32 = <$repr>::BITS;

            /// `(variant_name, wire_value)` for every defined variant, in
            /// declaration order — the frozen source for the protocol artifact's
            /// enum catalog, so the artifact cannot drift from these definitions.
            pub const CATALOG: &'static [(&'static str, u64)] =
                &[ $( (stringify!($variant), $val as u64) ),+ ];

            /// `(variant_name, wire_value)` for reserved-and-rejected values
            /// (empty when the enum declares none).
            pub const RESERVED: &'static [(&'static str, u64)] =
                &[ $( $( (stringify!($rvariant), $rval as u64) ),+ )? ];
        }
    };
}

frozen_enum!(
    /// Object kinds. 2 (Tokenizer) and 8 (Slot) are reserved and rejected.
    ObjectKind: u16 {
        Empty = 0, Model = 1, TokenPrefix = 3, InputManifest = 4, OutputManifest = 5,
        ResidualState = 6, KvState = 7, DerivedInput = 9, TokenSeq = 10,
        PriorResidual = 11, PriorKv = 12,
    }
    reserved { Tokenizer = 2, Slot = 8 }
);

frozen_enum!(SlotKind: u8 { ResidualStream = 0, KvCache = 1 });
frozen_enum!(InputSlotKind: u8 { PriorResidual = 0, PriorKv = 1, TokenPrefix = 2 });
frozen_enum!(Candidate: u16 { Sp1 = 1, Risc0 = 2 });
frozen_enum!(UnitKind: u16 { TransformerLayerGroup = 0, SelectToken = 1 });
frozen_enum!(ProofRefKind: u8 { ContentDigest = 1 });
frozen_enum!(
    MetricKind: u8 {
        GuestCyclesModelAuth = 0, GuestCyclesTransformer = 1, GuestCyclesStateHash = 2,
        GuestCyclesTotal = 3, HostProveWrapNs = 4, HostVerifyNs = 5, HostSetupNs = 6,
        ProofBytes = 7,
    }
);
frozen_enum!(Unit: u8 { Cycles = 0, Nanoseconds = 1, Bytes = 2 });
frozen_enum!(RssScope: u8 { ProvingRun = 0, VerifyBatch = 1 });
frozen_enum!(SampleKind: u8 { Warmup = 0, Measured = 1 });
frozen_enum!(Status: u8 { Ok = 0, Failed = 1, Timeout = 2 });
frozen_enum!(Arch: u8 { X86_64 = 1, Aarch64 = 2 });
frozen_enum!(ProvenanceRole: u8 { Proving = 0, Verification = 1 });
frozen_enum!(
    VerifierMaterialRole: u8 { Groth16Vk = 0, ControlRoot = 1, ControlId = 2, VerifierParams = 3 }
);
frozen_enum!(StatementIndex: u8 { Tlg = 0, SelectToken = 1 });

impl SlotKind {
    /// The object kind an output-manifest slot of this kind must embed.
    pub const fn object_kind(self) -> ObjectKind {
        match self {
            SlotKind::ResidualStream => ObjectKind::ResidualState,
            SlotKind::KvCache => ObjectKind::KvState,
        }
    }
}

impl InputSlotKind {
    /// The object kind an input-manifest slot of this kind must embed.
    pub const fn object_kind(self) -> ObjectKind {
        match self {
            InputSlotKind::PriorResidual => ObjectKind::PriorResidual,
            InputSlotKind::PriorKv => ObjectKind::PriorKv,
            InputSlotKind::TokenPrefix => ObjectKind::TokenPrefix,
        }
    }
}

impl VerifierMaterialRole {
    /// The single canonical verifier-material label for this role: the lowercase
    /// role name (`groth16_vk`, `control_root`, `control_id`, `verifier_params`).
    /// Delegates to the shared canonical primitive so labels are minted in exactly
    /// one place; extractors and the manifest constructor assign the same string.
    pub fn canonical_label(self) -> &'static str {
        b0_pre_vmat::canonical_label(self.to_repr())
            .expect("every VerifierMaterialRole has a shared canonical label")
    }

    /// Parse a canonical lowercase role label back to its role, rejecting any
    /// non-canonical (e.g. uppercase / aliased) spelling. Delegates to the shared
    /// primitive's `role_from_canonical_label`.
    pub fn from_canonical_label(label: &str) -> Result<Self, DecodeError> {
        b0_pre_vmat::role_from_canonical_label(label)
            .and_then(|r| Self::from_repr(r).ok())
            .ok_or(DecodeError::BadValue {
                ctx: "VerifierMaterialRole.canonical_label",
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_kind_valid_roundtrips_reserved_and_unknown_rejected() {
        for &k in ObjectKind::ALL {
            assert_eq!(ObjectKind::from_repr(k.to_repr()).unwrap(), k);
        }
        // reserved
        assert!(matches!(
            ObjectKind::from_repr(2),
            Err(DecodeError::ReservedEnum { .. })
        ));
        assert!(matches!(
            ObjectKind::from_repr(8),
            Err(DecodeError::ReservedEnum { .. })
        ));
        // adjacent / unknown
        assert!(matches!(
            ObjectKind::from_repr(13),
            Err(DecodeError::BadEnum { .. })
        ));
        assert!(matches!(
            ObjectKind::from_repr(65535),
            Err(DecodeError::BadEnum { .. })
        ));
    }

    #[test]
    fn small_enums_roundtrip_and_reject_neighbours() {
        macro_rules! check {
            ($ty:ty, $bad:expr) => {{
                for &v in <$ty>::ALL {
                    assert_eq!(<$ty>::from_repr(v.to_repr()).unwrap(), v);
                }
                assert!(<$ty>::from_repr($bad).is_err());
            }};
        }
        check!(SlotKind, 2);
        check!(InputSlotKind, 3);
        check!(Candidate, 0); // 0 is not a candidate
        check!(UnitKind, 2);
        check!(ProofRefKind, 0);
        check!(MetricKind, 8);
        check!(Unit, 3);
        check!(RssScope, 2);
        check!(SampleKind, 2);
        check!(Status, 3);
        check!(Arch, 0);
        check!(ProvenanceRole, 2);
        check!(VerifierMaterialRole, 4);
        check!(StatementIndex, 2);
    }

    #[test]
    fn slot_kind_object_kind_mapping() {
        assert_eq!(
            SlotKind::ResidualStream.object_kind(),
            ObjectKind::ResidualState
        );
        assert_eq!(SlotKind::KvCache.object_kind(), ObjectKind::KvState);
        assert_eq!(
            InputSlotKind::PriorResidual.object_kind(),
            ObjectKind::PriorResidual
        );
        assert_eq!(InputSlotKind::PriorKv.object_kind(), ObjectKind::PriorKv);
        assert_eq!(
            InputSlotKind::TokenPrefix.object_kind(),
            ObjectKind::TokenPrefix
        );
    }

    #[test]
    fn candidate_and_proofref_have_no_zero_variant() {
        assert!(Candidate::from_repr(0).is_err());
        assert!(ProofRefKind::from_repr(0).is_err());
        assert_eq!(Candidate::Sp1.to_repr(), 1);
        assert_eq!(Candidate::Risc0.to_repr(), 2);
    }

    #[test]
    fn verifier_material_role_canonical_labels_roundtrip_and_reject_noncanonical() {
        for &r in VerifierMaterialRole::ALL {
            assert_eq!(
                VerifierMaterialRole::from_canonical_label(r.canonical_label()).unwrap(),
                r
            );
        }
        assert_eq!(
            VerifierMaterialRole::Groth16Vk.canonical_label(),
            "groth16_vk"
        );
        assert_eq!(
            VerifierMaterialRole::VerifierParams.canonical_label(),
            "verifier_params"
        );
        // the historical uppercase spelling is NOT a canonical label
        assert!(VerifierMaterialRole::from_canonical_label("GROTH16_VK_BYTES").is_err());
        assert!(VerifierMaterialRole::from_canonical_label("groth16").is_err());
    }
}
