//! Refusing unknown genesis fields (#268) changes which inputs are accepted,
//! never what an accepted genesis means.
//!
//! Every value below was computed from the tracked genesis files on `main` at
//! 1f017f55, before unknown fields were refused, and must be reproduced
//! exactly: the canonical JSON the loader writes back (`Genesis::to_json`), the
//! genesis block hash, the activation and protocol digests, and the
//! consensus-configuration encoding and commitment (#268) a node records.
//!
//! The consensus-configuration pins are the frozen schema-2 encoding, built
//! under the policy of the release that wrote schema 2, and the schema-3
//! encoding this binary records, which must be exactly the schema-2 one with
//! schema 3's one field absent.
//!
//! The two network templates hold placeholder validator keys and are refused
//! by validation, before and after, with the same error; what serde reads from
//! them (including the template's top-level `_comment`) is pinned too. The
//! devnet topology template (#118) was added after 1f017f55; it is pinned the
//! same way, from when it was added.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sumchain_consensus::consensus_config as ccfg;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::Hash;

struct Pin {
    file: &'static str,
    /// BLAKE3 of the genesis as JSON, allocations in key order.
    json: &'static str,
    block: &'static str,
    activation: &'static str,
    protocol: &'static str,
    /// BLAKE3 of the schema-2 consensus-configuration encoding.
    ccfg_encoding: &'static str,
    ccfg_commitment: &'static str,
    /// BLAKE3 of the schema-3 consensus-configuration encoding, which this
    /// binary records.
    ccfg3_encoding: &'static str,
    ccfg3_commitment: &'static str,
}

/// The release that wrote schema 2: reads schemas 1 and 2, writes 2.
static SCHEMA_2_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2],
    writes: &ccfg::SCHEMA_2,
    knows: &ccfg::SCHEMA_3,
};

struct Template {
    file: &'static str,
    /// BLAKE3 of the raw serde parse as JSON, allocations in key order.
    json: &'static str,
    error: &'static str,
}

// Re-pinned when the node-registry `UpdateStatus` gate was declared: the
// activation digest folds every gate's name (set or not), the protocol digest
// folds the activation digest, and canonical JSON writes the unset gate as
// `null`, as it does every sibling gate. Block hash and consensus-configuration
// encoding and commitment are unchanged.
//
// When this binary began writing schema 3, the schema-3 pins were added beside
// the frozen schema-2 ones, which did not move: `identity` checks that each
// schema-3 configuration is its schema-2 one plus 0x1043 absent.
const PINS: &[Pin] = &[
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-1v.json",
        json: "0x38544a81a1436d868d1d8f9178b5f6d6ae1f10f78f4fb811c3a0cbcfc7546e5e",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        activation: "0xf86f11d18e57eab928d2cece0c029d883ef5ea9eb40435c467f9cfb1e376aeae",
        protocol: "0x9dc8e8541b2e6408fdedeb979bdc8ea4594a5c5f87a9d1424c5ef61ec96ebfe0",
        ccfg_encoding: "0xc9bb4182295ac07b0bf71136259679caa1639cb6ab96a627ca409616e3d76c32",
        ccfg_commitment: "0x66ef2cb66e07cb457a998c4361226ee114877f92666addd599caa89d07d53b79",
        ccfg3_encoding: "0xb288184ea98d1c7203d55133138c8cfcfb21c0a6083530ad9ec1dffa65d30f4a",
        ccfg3_commitment: "0xea325096bd25e2f7a4c5935f265e52b512fc46525002fc502048486428949842",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-2v.json",
        json: "0x90b160e6505b7e56274bf51e0226b5c528bcd7299b6fb04f66b435eedf43ac87",
        block: "0xf92241d3986ae1c5a30ef34e61dbec5e851ee289404e3276792dd0a27cf3083c",
        activation: "0x04c08b4ba547e3ce30316f58c14fc655a6003bd4f55f350232efbfd8600f6af7",
        protocol: "0x904b68a5df74f7137f950f9863a25bd30ccd9b47f8ecfe40c145630493be9e52",
        ccfg_encoding: "0xa518ff0db6253e80545b24b5d20aadee593cb7a8692671aabc5f7710ebf22d7c",
        ccfg_commitment: "0x075b28ec3521f49c6ca7fb12ae5297c79f74bada8649899771bd1cdb1fdce564",
        ccfg3_encoding: "0xf91dbc6a2fd1661cfbc2fb074e5edad6d80725ab3776d67c0635cc3c64a73ee9",
        ccfg3_commitment: "0x70cb4bd4242d57f83d63fa7879b167b07a084c3eea13f792069ca4090ea09fa7",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-A.json",
        json: "0xf868995b13701831f40887777d245f3fd2f42785f29c13f91088a0e45652d780",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        activation: "0x1479fea55e30c9f5e5c964950fe32ca8f36f1c5cac4c6f19557b8941177b52f0",
        protocol: "0xbc97e0241d82d8481ae23eef4d3a849038bec2c8b5cf93f77ebfd170d8b70bb3",
        ccfg_encoding: "0x62cc58e670135f46769fae95eb7a41ee7aff3a6de2fe5e783b726ed9281b0aa4",
        ccfg_commitment: "0xfb73f20bec922b4c256098ea2a4f78f230271a42fe961ac913a97a511c217eb0",
        ccfg3_encoding: "0x9d8dc2b7f8bbfd4e3adb635568e8316c6f4d5a220d88c20b98df62570270f52b",
        ccfg3_commitment: "0x29c78ebd241a2c25325c7f54e915363684af3775be676c7a2419e85b122f492c",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-B.json",
        json: "0x93f00e4747255012ffcbb0482d2da58778ddce08a7b89c7ae8bc2b797d7f54ee",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        activation: "0xfa0d55848ad38399358f32c99675ded98984527b0f61582a59e5ec6d7d8d6425",
        protocol: "0x12086768c768c8b35b0086bdaf055b33dc61435a5aa5056a29a55eaa5de1a688",
        ccfg_encoding: "0x67b53cfd13cb2ac5eca5150f1e0dd163fb41134afe74d7fce86534c77d471efc",
        ccfg_commitment: "0x2f3026bc8d54499c35c0cf657e431c8cf7b5731e3acc1ca3735e8bf7d3a309d9",
        ccfg3_encoding: "0x6140a1bb966583aacde73103f6783fbdd5c10597e3cb8d9a5b1cb981d9df8005",
        ccfg3_commitment: "0x452c12e896e5187255653d358ba10aa67deb35de367c0d9c780362812c187880",
    },
    Pin {
        file: "genesis.json",
        json: "0x4b41558f189c6aeb0a67a7765bd6465cb0b9976ecc35a91dee2815ce2a301c93",
        block: "0x1156d350e7d0ac45cb96bfca25d57c71675ceea5949ea44d81432d08baed68e6",
        activation: "0xa454afffab50ba7d1c3f52d2c212acdccfe1793e812aa6d08f0895a364651b3d",
        protocol: "0xb9a324d5473e632220e5143619e2362029f37c2875331e15d3cb6ef6379592bd",
        ccfg_encoding: "0xd3d4f1ccf5cde71083d000b87d9425d08b9e6817d30614ed312747968f0af3e3",
        ccfg_commitment: "0x2afc2d46fbad85cdeac914d3c6ccb5e4457f596f36d3265997710a42268f979b",
        ccfg3_encoding: "0x1b3979f0684772f2c49c1f1d16103126645873f666981869545520a759f98001",
        ccfg3_commitment: "0x23e7f5a5d78889d8f363d73963eda02be837e43e2115c6c54b7d2bd3f581cb28",
    },
    Pin {
        file: "genesis/local_genesis.json",
        json: "0xecbbf8053928c6bf9059d551ef7d772a9a8b73eb705d6fce79c5734eea2c802f",
        block: "0xe5e3fccc545ef9b0f29fb4204d4e79da04d47661e89eaebe23352abba269e1b4",
        activation: "0xdf6786c49f2c444581f6f071977b889b3d5ea13018b5ce0070427f5dbafd0376",
        protocol: "0xeb2859c0f358cb51f01a3471aa9e29a29ff56ba8ec803357219469f0bc25211b",
        ccfg_encoding: "0x708b1cc7fe7aa9ac8e823d6ecb9ec2eccf495e7a79b6f9da41bc3703416b574a",
        ccfg_commitment: "0x1d61e756ad20cd078dbde4d89ad38fa28ef6b04b98f6eb3b7a18a7653fcdf591",
        ccfg3_encoding: "0x97c1a0e8c53813ae5bc3539291bb412b5484531f4464a2fe39a6d62ec7d17bc8",
        ccfg3_commitment: "0x50222daa238087b6f29b83b4024cd0158cfe33f9638fe0137168889b0a29ec0b",
    },
];

const TEMPLATES: &[Template] = &[
    Template {
        file: "genesis/mainnet_genesis.json",
        json: "0x03b62eeb1ffd4d571647deee6b473dc49c2e6fc5b047609fa701b67ab5ebe892",
        error: "Invalid validator public key: validator[0]: VALIDATOR1_PUBKEY_PLACEHOLDER",
    },
    // Added by #118 (not on 1f017f55): the synthetic topology template,
    // refused until `sumchain_scripts::substitute_template` fills it. Re-pinned
    // with the node-registry gate like its siblings: only the gate's `null`
    // line is new in what serde reads.
    Template {
        file: "genesis/snip-mirror-genesis.template.json",
        json: "0xcfded7d0c523d61de6e525512886a08155082870492bc73df1783b8dde99c5c6",
        error: "Invalid validator public key: validator[0]: DEVNET_VALIDATOR1_PUBKEY",
    },
    Template {
        file: "genesis/testnet_genesis.json",
        json: "0xec654a2615fe2324d8b812c5ba8981df142f221a1db5fa52e08e988553297221",
        error: "Invalid validator public key: validator[0]: TESTNET_VALIDATOR1_PUBKEY",
    },
];

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn blake3(bytes: &[u8]) -> String {
    Hash::hash(bytes).to_string()
}

/// `g` written back as `Genesis::to_json` writes it, except that the
/// allocations are in key order, so the map's iteration order cannot move the
/// bytes.
fn canonical_json(g: &Genesis) -> String {
    #[derive(serde::Serialize)]
    struct Canonical<'a> {
        chain_id: u64,
        genesis_time: u64,
        validators: &'a [String],
        alloc: BTreeMap<&'a String, &'a u128>,
        params: &'a ChainParams,
    }
    serde_json::to_string_pretty(&Canonical {
        chain_id: g.chain_id,
        genesis_time: g.genesis_time,
        validators: &g.validators,
        alloc: g.alloc.iter().collect(),
        params: &g.params,
    })
    .unwrap()
}

fn identity(file: &str) -> [String; 8] {
    let g = Genesis::from_file(repo().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    let two = ccfg::build_with(&g, &SCHEMA_2_RELEASE).unwrap_or_else(|e| panic!("{file}: {e}"));
    let three = ccfg::build(&g).unwrap_or_else(|e| panic!("{file}: {e}"));
    assert_eq!(
        three.schema().number,
        3,
        "{file}: this binary records schema 3"
    );
    assert_eq!(
        two.extend_to(&ccfg::SCHEMA_3).unwrap(),
        three,
        "{file}: schema 3 is schema 2 plus its one field, absent"
    );
    [
        blake3(canonical_json(&g).as_bytes()),
        g.create_genesis_block().unwrap().hash().to_string(),
        g.activation_digest().unwrap().to_string(),
        sumchain_state::protocol_digest::protocol_digest(&g)
            .unwrap()
            .to_string(),
        blake3(&two.encode()),
        two.commitment().to_string(),
        blake3(&three.encode()),
        three.commitment().to_string(),
    ]
}

fn template(file: &str) -> [String; 2] {
    let path = repo().join(file);
    let text = std::fs::read_to_string(&path).unwrap();
    let raw: Genesis = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
    [
        blake3(canonical_json(&raw).as_bytes()),
        Genesis::from_file(&path).unwrap_err().to_string(),
    ]
}

/// Every tracked `*genesis*.json` under the repository, skipping build output
/// and the ignored devnet runtime directory (`/devnet/`, #118), where a
/// provisioned, untracked `genesis.json` may legitimately sit.
fn tracked_genesis_files() -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                let ignored_devnet = p == root.join("devnet");
                if !ignored_devnet && !matches!(name.as_str(), "target" | ".git" | "node_modules") {
                    walk(&p, root, out);
                }
            } else if name.contains("genesis") && name.ends_with(".json") {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().to_string();
                out.push(rel);
            }
        }
    }
    let root = repo().canonicalize().unwrap();
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out.sort();
    out
}

#[test]
fn every_tracked_genesis_file_is_pinned() {
    let mut pinned: Vec<String> = PINS
        .iter()
        .map(|p| p.file)
        .chain(TEMPLATES.iter().map(|t| t.file))
        .map(String::from)
        .collect();
    pinned.sort();
    assert_eq!(
        tracked_genesis_files(),
        pinned,
        "a genesis file was added or removed: pin its identity here, computed before \
         and after any change to how genesis is read"
    );
}

#[test]
fn loadable_genesis_files_keep_their_identity() {
    for pin in PINS {
        let [json, block, activation, protocol, ccfg_encoding, ccfg_commitment, ccfg3_encoding, ccfg3_commitment] =
            identity(pin.file);
        assert_eq!(json, pin.json, "{}: canonical JSON", pin.file);
        assert_eq!(block, pin.block, "{}: genesis block hash", pin.file);
        assert_eq!(
            activation, pin.activation,
            "{}: activation digest",
            pin.file
        );
        assert_eq!(protocol, pin.protocol, "{}: protocol digest", pin.file);
        assert_eq!(
            ccfg_encoding, pin.ccfg_encoding,
            "{}: consensus-configuration encoding",
            pin.file
        );
        assert_eq!(
            ccfg_commitment, pin.ccfg_commitment,
            "{}: consensus-configuration commitment",
            pin.file
        );
        assert_eq!(
            ccfg3_encoding, pin.ccfg3_encoding,
            "{}: schema-3 consensus-configuration encoding",
            pin.file
        );
        assert_eq!(
            ccfg3_commitment, pin.ccfg3_commitment,
            "{}: schema-3 consensus-configuration commitment",
            pin.file
        );
    }
}

#[test]
fn templates_parse_as_before_and_are_refused_as_before() {
    for t in TEMPLATES {
        let [json, error] = template(t.file);
        assert_eq!(json, t.json, "{}: what serde reads", t.file);
        assert_eq!(error, t.error, "{}: the refusal", t.file);
    }
}
