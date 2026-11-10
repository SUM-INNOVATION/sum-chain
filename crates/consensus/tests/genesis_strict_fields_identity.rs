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
//! under the policy of the release that wrote schema 2, the frozen schema-3
//! encoding, built under the policy of the releases that wrote schema 3 and
//! exactly the schema-2 one with schema 3's one field absent, and the schema-4
//! encoding this binary records, which must be exactly the schema-3 one with
//! schema 4's four fields absent.
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
    /// BLAKE3 of the schema-3 consensus-configuration encoding.
    ccfg3_encoding: &'static str,
    ccfg3_commitment: &'static str,
    /// BLAKE3 of the schema-4 consensus-configuration encoding, which this
    /// binary records.
    ccfg4_encoding: &'static str,
    ccfg4_commitment: &'static str,
}

/// The release that wrote schema 2: reads schemas 1 and 2, writes 2.
static SCHEMA_2_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2],
    writes: &ccfg::SCHEMA_2,
    knows: &ccfg::SCHEMA_5,
};

/// The releases that wrote schema 3: read schemas 1, 2 and 3, write 3, and
/// know schema 4 only as a draft. (Every stand-in here knows the draft schema
/// 5 too: this test binary's genesis declares its gates, unset.)
static SCHEMA_3_RELEASE: ccfg::SchemaPolicy = ccfg::SchemaPolicy {
    reads: &[&ccfg::SCHEMA_1, &ccfg::SCHEMA_2, &ccfg::SCHEMA_3],
    writes: &ccfg::SCHEMA_3,
    knows: &ccfg::SCHEMA_5,
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
// Re-pinned when the gate under which BeginUnstake counts only the sender's own
// open challenges (#369), and then the attested-target storage-challenge gate,
// were declared in the draft schema 4, for the same reason: canonical JSON, and the activation and
// protocol digests, moved; block hash and every consensus-configuration
// encoding and commitment did not (the gate is a draft field this binary never
// writes).
//
// Re-pinned again when the strict transaction-signature gate was declared in
// the draft schema 4 (0x1046), and then the legacy-evidence refusal
// gate (0x1047), for the same reason and with the same result:
// canonical JSON and the two digests moved, nothing else did.
//
// Re-pinned again when the sponsored-envelope verification gate was declared
// as the first field of the draft schema 5 (0x1048, proposed), and then the
// messaging fee-and-nonce accounting gate (0x1049, proposed), for the same
// reason and with the same result: canonical JSON and the two digests moved,
// nothing else did. The schema-5 envelope-tag field (0x252b) is absent while
// the envelope gate is unset, so the schema-2 and schema-3 encodings and
// commitments are unchanged.
//
// When this binary began writing schema 3, the schema-3 pins were added beside
// the frozen schema-2 ones, which did not move: `identity` checks that each
// schema-3 configuration is its schema-2 one plus 0x1043 absent.
//
// When this binary began writing schema 4, the schema-4 pins were added beside
// the frozen schema-2 and schema-3 ones, which did not move, and neither did
// canonical JSON, the block hash or the two digests: `identity` checks that
// each schema-4 configuration is its schema-3 one plus 0x1044 to 0x1047
// absent.
const PINS: &[Pin] = &[
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-1v.json",
        json: "0x4412b989577884a7150c7a288d58441ce8b0f2f8284ccb580b5b1c8cbce6b0be",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        activation: "0xf18ea587ec7c257ce0919f8488dc6e4dda1f27e545203e41075186ca662e4544",
        protocol: "0x8e58ee3045a533470d62c080ae0c5e5f646100ee41cad1f9baf54ffd04d299c2",
        ccfg_encoding: "0xc9bb4182295ac07b0bf71136259679caa1639cb6ab96a627ca409616e3d76c32",
        ccfg_commitment: "0x66ef2cb66e07cb457a998c4361226ee114877f92666addd599caa89d07d53b79",
        ccfg3_encoding: "0xb288184ea98d1c7203d55133138c8cfcfb21c0a6083530ad9ec1dffa65d30f4a",
        ccfg3_commitment: "0xea325096bd25e2f7a4c5935f265e52b512fc46525002fc502048486428949842",
        ccfg4_encoding: "0xc10cd4afd71c0eff58a7135a6928175f704a0d17a59726e04242a652b1829ce8",
        ccfg4_commitment: "0x024d960dfefb282a04c75b3ffcc9c2b15a1888ee35e84e8f1b106229f4f5be5d",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-2v.json",
        json: "0xa4e84beed8759f197abb41da19d294ab23597a95f973570a200ed01509fed1e5",
        block: "0xf92241d3986ae1c5a30ef34e61dbec5e851ee289404e3276792dd0a27cf3083c",
        activation: "0x734d6d7dd689565017e51eefde7b2b0827f7ac5195300e9d61836211327b0119",
        protocol: "0x5fbe61c8d4a98d985349b0e977681fcf15a81bfa5fdcf23707473585bd1eb651",
        ccfg_encoding: "0xa518ff0db6253e80545b24b5d20aadee593cb7a8692671aabc5f7710ebf22d7c",
        ccfg_commitment: "0x075b28ec3521f49c6ca7fb12ae5297c79f74bada8649899771bd1cdb1fdce564",
        ccfg3_encoding: "0xf91dbc6a2fd1661cfbc2fb074e5edad6d80725ab3776d67c0635cc3c64a73ee9",
        ccfg3_commitment: "0x70cb4bd4242d57f83d63fa7879b167b07a084c3eea13f792069ca4090ea09fa7",
        ccfg4_encoding: "0x20d971d8c96d4780ef286bf4577294607322724e4cf325f8e7c6288b67fdfc56",
        ccfg4_commitment: "0x631cc72dd5146bc8a00edf2c3af6e27c12091c60678e63b4f1be0f1325ad5f01",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-A.json",
        json: "0xfda3982bc2b20e370b4b957bc5a7c009eec161b83d40f673225565c49e3da13e",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        activation: "0x197d5121f6ff449ee5aaf6346075af7c9956446b88da4ea27ab0eb1beca267f0",
        protocol: "0xeff47678df27f8e1ca4c2ad5255c7601e1c2b4ae7ccdf8261fe362375d3e49a7",
        ccfg_encoding: "0x62cc58e670135f46769fae95eb7a41ee7aff3a6de2fe5e783b726ed9281b0aa4",
        ccfg_commitment: "0xfb73f20bec922b4c256098ea2a4f78f230271a42fe961ac913a97a511c217eb0",
        ccfg3_encoding: "0x9d8dc2b7f8bbfd4e3adb635568e8316c6f4d5a220d88c20b98df62570270f52b",
        ccfg3_commitment: "0x29c78ebd241a2c25325c7f54e915363684af3775be676c7a2419e85b122f492c",
        ccfg4_encoding: "0x4ba8c5fa2e12b0ea8015db93436147575c9b0f80f0a06ceaa467a495955d3b22",
        ccfg4_commitment: "0xe5f46cb0000906ed7f9f7621111ba2502a04354a29d57c1a814f0b539a4b9edd",
    },
    Pin {
        file: "docs/operations/evidence/stage1-local-2026-09-24/genesis-B.json",
        json: "0x6552167b015d7ec59bd84201da5a45db158cd1b49c013af71c0adb7109c2716d",
        block: "0x9c22b13ee6c753f288538165afac3dd48ea79a5581341fa2d08e23035726e28e",
        activation: "0x8ff3a7f603affa50ff6b973c16e62f5a05867bac3e6c7afe233c4a6ef6076608",
        protocol: "0x76a11483afd2f1bb2e704c1f0391860fca4c13a3721a79e8f9107dd21c0b0330",
        ccfg_encoding: "0x67b53cfd13cb2ac5eca5150f1e0dd163fb41134afe74d7fce86534c77d471efc",
        ccfg_commitment: "0x2f3026bc8d54499c35c0cf657e431c8cf7b5731e3acc1ca3735e8bf7d3a309d9",
        ccfg3_encoding: "0x6140a1bb966583aacde73103f6783fbdd5c10597e3cb8d9a5b1cb981d9df8005",
        ccfg3_commitment: "0x452c12e896e5187255653d358ba10aa67deb35de367c0d9c780362812c187880",
        ccfg4_encoding: "0x8a33ef0551b054dac35b8c91601bf1c31bb303db3ea94debf8cc1015390c57e1",
        ccfg4_commitment: "0xa412b1594a443b66a9ec5b27e7beecdaa2299e71adcd6eee7c468f8e759de694",
    },
    Pin {
        file: "genesis.json",
        json: "0x2df071062c77bac8c953f454f39cd4762af4969be64855f8d418bdffa010cd29",
        block: "0x1156d350e7d0ac45cb96bfca25d57c71675ceea5949ea44d81432d08baed68e6",
        activation: "0xa580b4b3035dc29e7b105d6c9c9c198949386b57374ff20c45b05086493206ee",
        protocol: "0xd5b304de88c5f615b7f27ed5a9eeacd35485378bb80270d5605e67093336f161",
        ccfg_encoding: "0xd3d4f1ccf5cde71083d000b87d9425d08b9e6817d30614ed312747968f0af3e3",
        ccfg_commitment: "0x2afc2d46fbad85cdeac914d3c6ccb5e4457f596f36d3265997710a42268f979b",
        ccfg3_encoding: "0x1b3979f0684772f2c49c1f1d16103126645873f666981869545520a759f98001",
        ccfg3_commitment: "0x23e7f5a5d78889d8f363d73963eda02be837e43e2115c6c54b7d2bd3f581cb28",
        ccfg4_encoding: "0xa74c4cd08c2b265f80d2dcc3123a596a7f62f392da6900f6bd7b7ffd9d76ff4a",
        ccfg4_commitment: "0x8646e7dd068f1f422bca024f86504354dc8cddcb1e74621db439b6c67e679dc6",
    },
    Pin {
        file: "genesis/local_genesis.json",
        json: "0xfb61f623ddd6f80608b78b569cad8817874d9be104f0dc2750228f1c8fa1866a",
        block: "0xe5e3fccc545ef9b0f29fb4204d4e79da04d47661e89eaebe23352abba269e1b4",
        activation: "0x2c870f3c3e12a5efc5020404597a3f5028339481393454f55acfea9be57363ee",
        protocol: "0x86e97ed97da5c1101dd79fb03f1ba4863719b82a406b815d70d49db18077de87",
        ccfg_encoding: "0x708b1cc7fe7aa9ac8e823d6ecb9ec2eccf495e7a79b6f9da41bc3703416b574a",
        ccfg_commitment: "0x1d61e756ad20cd078dbde4d89ad38fa28ef6b04b98f6eb3b7a18a7653fcdf591",
        ccfg3_encoding: "0x97c1a0e8c53813ae5bc3539291bb412b5484531f4464a2fe39a6d62ec7d17bc8",
        ccfg3_commitment: "0x50222daa238087b6f29b83b4024cd0158cfe33f9638fe0137168889b0a29ec0b",
        ccfg4_encoding: "0x874abad24bfaa862a60a4b9d3bafff5065b31962b9820dcb09ed109475ac71bf",
        ccfg4_commitment: "0x2a90db93196d63fd7003dcf10239849753893186ec892626a8927b03409849bc",
    },
];

const TEMPLATES: &[Template] = &[
    Template {
        file: "genesis/mainnet_genesis.json",
        json: "0xd330ef5c24eedb764ed946c80231bd850aed37fa1e19535b8a2825c01cac8e99",
        error: "Invalid validator public key: validator[0]: VALIDATOR1_PUBKEY_PLACEHOLDER",
    },
    // Added by #118 (not on 1f017f55): the synthetic topology template,
    // refused until `sumchain_scripts::substitute_template` fills it. Re-pinned
    // with the node-registry gate like its siblings: only the gate's `null`
    // line is new in what serde reads.
    Template {
        file: "genesis/snip-mirror-genesis.template.json",
        json: "0xb452f8bc68bb4f2b9b8c47c73719b53486e3d7c910a9cba0a32dda72c3257b83",
        error: "Invalid validator public key: validator[0]: DEVNET_VALIDATOR1_PUBKEY",
    },
    Template {
        file: "genesis/testnet_genesis.json",
        json: "0x809c1078fe2af23aaa6df503500b1968754a129125e53b92f03a53492c1a92ca",
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

fn identity(file: &str) -> [String; 10] {
    let g = Genesis::from_file(repo().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    let two = ccfg::build_with(&g, &SCHEMA_2_RELEASE).unwrap_or_else(|e| panic!("{file}: {e}"));
    let three = ccfg::build_with(&g, &SCHEMA_3_RELEASE).unwrap_or_else(|e| panic!("{file}: {e}"));
    let four = ccfg::build(&g).unwrap_or_else(|e| panic!("{file}: {e}"));
    assert_eq!(
        four.schema().number,
        4,
        "{file}: this binary records schema 4"
    );
    assert_eq!(
        two.extend_to(&ccfg::SCHEMA_3).unwrap(),
        three,
        "{file}: schema 3 is schema 2 plus its one field, absent"
    );
    assert_eq!(
        three.extend_to(&ccfg::SCHEMA_4).unwrap(),
        four,
        "{file}: schema 4 is schema 3 plus its four fields, absent"
    );
    // The schema-4 pin's preimage, byte for byte: the frozen schema-3 encoding
    // with schema number 4, field count + 4, and the four gates' absent entries
    // (`id ‖ tag 0 ‖ len 0`, 7 bytes each) right after 0x1043's entry.
    let b3 = three.encode();
    let mut derived = b3.clone();
    derived[7..9].copy_from_slice(&4u16.to_le_bytes());
    let n = u16::from_le_bytes([b3[9], b3[10]]) + 4;
    derived[9..11].copy_from_slice(&n.to_le_bytes());
    let at = b3
        .windows(7)
        .position(|w| w == [0x43, 0x10, 0, 0, 0, 0, 0])
        .unwrap_or_else(|| panic!("{file}: 0x1043 absent in the schema-3 encoding"))
        + 7;
    derived.splice(
        at..at,
        [
            0x44u8, 0x10, 0, 0, 0, 0, 0, 0x45, 0x10, 0, 0, 0, 0, 0, 0x46, 0x10, 0, 0, 0, 0, 0,
            0x47, 0x10, 0, 0, 0, 0, 0,
        ],
    );
    assert_eq!(
        four.encode(),
        derived,
        "{file}: the schema-4 encoding derives from the schema-3 one"
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
        blake3(&four.encode()),
        four.commitment().to_string(),
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
        let [json, block, activation, protocol, ccfg_encoding, ccfg_commitment, ccfg3_encoding, ccfg3_commitment, ccfg4_encoding, ccfg4_commitment] =
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
        assert_eq!(
            ccfg4_encoding, pin.ccfg4_encoding,
            "{}: schema-4 consensus-configuration encoding",
            pin.file
        );
        assert_eq!(
            ccfg4_commitment, pin.ccfg4_commitment,
            "{}: schema-4 consensus-configuration commitment",
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

/// Prints every value the pins above hold, for re-pinning after a change that
/// legitimately moves them (declaring a gate moves the canonical JSON and both
/// digests of every genesis). Never a substitute for explaining the move.
#[test]
#[ignore = "reporting aid: prints every pinned value of the tracked genesis files"]
fn print_pins() {
    for pin in PINS {
        let v = identity(pin.file);
        println!("PIN {} {}", pin.file, v.join(" "));
    }
    for t in TEMPLATES {
        let v = template(t.file);
        println!("TEMPLATE {} {}", t.file, v[0]);
    }
}
